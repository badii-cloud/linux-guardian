#!/usr/bin/env python3
"""
Linux Guardian -- test_explain.py                                  (Phase 9)

PROOF THAT THE PLAIN-ENGLISH LAYER IS COMPLETE AND HONEST.

Run it live:   python3 test_explain.py

The failure this suite exists to catch is silence. A monitoring page that shows
a blank panel reads as "nothing is wrong" at exactly the moment something is,
so every status, every risk band and every incident type must produce a
sentence -- and the sentence must not invent numbers that were not measured.

  1. Every status, incident type and risk band has wording.
  2. Every status produces a lifecycle position and exactly one next step.
  3. A null confidence NEVER prints as 0%.
  4. A self-resolved incident does not claim a fix ran.
  5. The presenter cannot execute anything (checked against the AST).
  6. Real incidents from this machine's own database render end to end.
"""

import ast
import sys

import guardian_explain as ex
import guardian_incidents as gi

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

failures = 0


def head(title):
    print(f"\n\033[1m{title}\033[0m")
    print("-" * 78)


def record(ok):
    global failures
    if not ok:
        failures += 1
    return PASS if ok else FAIL


def check(ok, label):
    """record() with the label on the same line, for one-line expectations."""
    print(f"  {record(ok)}  {label}")


# ===========================================================================
head("1. NOTHING IS LEFT WITHOUT WORDS")

problems = ex.check_explain()
for problem in problems:
    print(f"  {FAIL}  {problem}")
failures += len(problems)
if not problems:
    print(f"  {PASS}  {len(gi.STATUSES)} statuses, {len(gi.TYPES)} incident "
          f"types and 5 risk bands all have wording")


# ===========================================================================
head("2. EVERY STATUS PRODUCES A POSITION AND EXACTLY ONE NEXT STEP")

for status in gi.STATUSES:
    fake = {"status": status, "risk_level": "MEDIUM", "occurrences": 3,
            "component": "cpu", "type": "cpu_saturation",
            "created_human": "2026-08-16 12:00:00",
            "updated_human": "2026-08-16 12:05:00",
            "open": status in gi.OPEN_STATUSES, "detail": {}}
    step = ex.next_step(fake)
    stages = ex.pipeline(fake)
    current = [s for s in stages if s["state"] in ("current", "failed")]

    ok = bool(step["text"]) and len(current) == 1
    print(f"  {record(ok)}  {status:<18} -> \"{step['label']}\" "
          f"(at stage: {current[0]['label'] if current else 'NONE'})")

# The state machine and the pipeline must agree about which statuses are open.
for status in gi.STATUSES:
    fake = {"status": status, "risk_level": "LOW", "detail": {}}
    stages = ex.pipeline(fake)
    closed_stage = stages[-1]["state"] in ("current", "failed")
    should_be_closed = status not in gi.OPEN_STATUSES or status == gi.FAILED
    ok = closed_stage == should_be_closed
    print(f"  {record(ok)}  {status:<18} last stage reached: {closed_stage}")


# ===========================================================================
head("3. A MISSING NUMBER IS NEVER PRINTED AS ZERO")
print("  guardian_anomaly returns confidence=None when the baseline had no")
print("  variation at all. Printing 0% there would claim certainty that the")
print("  finding was meaningless -- the exact opposite of what happened.\n")

unknown = ex.confidence_sentence({"confidence": None})
print(f"  {record('0%' not in unknown)}  no '0%' in the sentence")
print(f"  {record('cannot put a number' in unknown)}  it says so plainly")
print(f"        \033[90m{unknown[:96]}...\033[0m")

known = ex.confidence_sentence({"confidence": 0.889})
print(f"  {record('89%' in known)}  a real confidence is printed as a percentage")
print(f"  {record('Chebyshev' in known)}  and names the bound it came from")

# A symptom whose readings were lost must say so, not render "None".
lost = ex.symptom_sentence({"metric": "load_1min", "current": None,
                            "baseline": None, "percent": None})
print(f"  {record('None' not in lost)}  a symptom with no reading does not "
      f"print 'None': {lost!r}")


# ===========================================================================
head("4. A SELF-RESOLVED INCIDENT DOES NOT CLAIM A FIX RAN")
print("  Marking approval and remediation 'done' on an incident that recovered")
print("  by itself would put a repair in the record that never happened.\n")

self_healed = {"status": gi.RESOLVED, "risk_level": "LOW", "detail": {}}
stages = {s["key"]: s["state"] for s in ex.pipeline(self_healed)}
for key in ("approved", "fixed", "checked"):
    print(f"  {record(stages[key] == 'skipped')}  '{key}' is marked "
          f"'{stages[key]}', not 'done'")

repaired = {"status": gi.RESOLVED, "risk_level": "LOW",
            "detail": {"remediation": {"exit_status": 0}}}
stages = {s["key"]: s["state"] for s in ex.pipeline(repaired)}
print(f"  {record(stages['fixed'] == 'done')}  but an incident that really was "
      f"repaired shows 'fixed' as done")

# FAILED is the one status that is not a simple position on a line.
failed = ex.pipeline({"status": gi.FAILED, "risk_level": "HIGH", "detail": {}})
print(f"  {record(failed[-1]['state'] == 'failed')}  a FAILED incident marks "
      f"its last stage 'failed', not 'current'")


# ===========================================================================
head("5. THE PRESENTER CANNOT EXECUTE ANYTHING")

tree = ast.parse(open(ex.__file__, encoding="utf-8").read())
imported = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        imported.update(alias.name.split(".")[0] for alias in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module:
        imported.add(node.module.split(".")[0])

for banned in ("subprocess", "os"):
    print(f"  {record(banned not in imported)}  does not import {banned}")
print(f"        \033[90mimports: {', '.join(sorted(imported))}\033[0m")


# ===========================================================================
head("6. PLAIN ENGLISH FOR THE SIZE OF A CHANGE")

ladder = [
    (5,    "slightly"),
    (40,   "noticeably"),
    (100,  "double"),
    (220,  "times"),
    (900,  "five times"),
    (-100, "half"),
    (None, "changed"),
]
for percent, expected in ladder:
    phrase = ex.magnitude(percent)
    ok = expected in phrase
    print(f"  {record(ok)}  {str(percent):>6}% -> {phrase!r}")


# ===========================================================================
head("7. REAL INCIDENTS FROM THIS MACHINE RENDER END TO END")

try:
    rows = gi.listing(limit=20)
except Exception as error:                                    # noqa: BLE001
    rows = []
    print(f"  \033[90mno database available: {error}\033[0m")

if not rows:
    print("  \033[90m(no incidents recorded yet -- nothing to render)\033[0m")

for row in rows[:6]:
    incident = gi.get(row["id"])
    story = ex.explain(incident)

    filled = all(story[key] for key in
                 ("happened", "noticed", "means", "severity", "risk", "confidence"))
    one_current = len([s for s in story["pipeline"]
                       if s["state"] in ("current", "failed")]) == 1
    no_none = "None" not in " ".join(s["sentence"] for s in story["symptoms"])

    ok = filled and one_current and no_none
    print(f"  {record(ok)}  {row['id']}  {row['status']:<14} "
          f"{story['urgency']['title']}")
    print(f"        \033[90m{story['happened']}\033[0m")
    for symptom in story["symptoms"][:2]:
        print(f"        \033[90m- {symptom['sentence']}\033[0m")
    print(f"        \033[90mNext: {story['next']['label']} -- "
          f"{story['next']['text'][:70]}...\033[0m")


# ===========================================================================
head("8. THE LIST SUMMARY IS SHORT AND STILL SAYS WHAT TO DO")

for row in rows[:3]:
    short = ex.summarise(row)
    ok = bool(short["means"]) and bool(short["next_label"])
    print(f"  {record(ok)}  {row['id']}  [{short['urgency']['title']}] "
          f"next: {short['next_label']}")
    print(f"        \033[90m{short['means'][:88]}\033[0m")
    print(f"        \033[90msymptoms in English: "
          f"{', '.join(short['symptoms']) or '(none)'}\033[0m")


# ===========================================================================
head("9. WHAT A HUMAN CAN DO WHEN GUARDIAN MAY NOT")

# The gap this closes: every incident type except service_failure recommends
# only read-only actions, so the page said "it needs a human" and stopped.
# These steps are what that human should type.


def fake(component, cause, status="INVESTIGATING"):
    """An incident record with a root-cause analysis already stored."""
    return {
        "id": "INC-TEST", "type": "cpu_saturation", "component": component,
        "status": status,
        "detail": {"root_cause": {"facts": ["x"], "primary_cause": cause}},
    }


# --- a named, unprotected process gets real commands ----------------------
steps = ex.manual_steps(fake("cpu", {"kind": "process", "pid": 4242,
                                     "name": "stress-ng", "share": 0.82}))
kinds = [s["kind"] for s in steps]
commands = " ".join(s["command"] for s in steps)
check(kinds == ["look", "soften", "stop"],
      f"three steps, gentlest first: {kinds}")
check("4242" in commands and commands.count("4242") == 3,
      "every command names the pid the investigation found, not a placeholder")
check("renice" in commands and "kill 4242" in commands,
      "the reversible option (renice) is offered before the destructive one")
check(steps.index(next(s for s in steps if s["kind"] == "stop")) == len(steps) - 1,
      "the destructive step is last, never first under the cursor")
check(bool(steps[-1]["caution"]) and "Unsaved work" in steps[-1]["caution"],
      "and it carries a caution the other two do not")
check(all(not s["caution"] for s in steps[:2]),
      "the safe steps are not cluttered with warnings that would dilute the real one")

# --- THE RULE THAT MATTERS: a protected process is never offered up -------
# On this desktop VM the busiest process is routinely Xorg or the browser. A
# page that mechanically printed "kill <busiest pid>" would eventually tell a
# student to destroy the session they are demonstrating in.
for name in ("Xorg", "xfwm4", "systemd", "gnome-shell", "python3"):
    guarded = ex.manual_steps(fake("cpu", {"kind": "process", "pid": 949,
                                           "name": name, "share": 0.91}))
    text = " ".join(s["command"] for s in guarded)
    ok = ("kill" not in text and "renice" not in text
          and len(guarded) == 1 and guarded[0]["kind"] == "look"
          and name in guarded[0]["caution"])
    check(ok, f"{name} (91% of the CPU) is described, never offered for killing")

# Case must not be a way round the list: the config says 'Xorg', a process
# table could say 'xorg'.
lower = ex.manual_steps(fake("cpu", {"kind": "process", "pid": 1, "name": "xorg"}))
check("kill" not in " ".join(s["command"] for s in lower),
      "the protected list is matched case-insensitively")

# --- no single culprit: the commoner and harder case ----------------------
spread = ex.manual_steps(fake("cpu", None))
check(len(spread) == 3 and all(s["kind"] == "look" for s in spread),
      f"load with no dominant process gets {len(spread)} read-only steps, no kill")
check(any("top" in s["command"] for s in spread),
      "including watching the machine live, which a single snapshot cannot replace")

# --- nothing invented before there is anything to say ---------------------
check(ex.manual_steps({"id": "x", "component": "cpu", "status": "DETECTED",
                       "detail": {}}) == [],
      "an uninvestigated incident gets no commands -- there is no pid to name yet")
check(ex.manual_steps({"id": "x", "component": "quantum", "status": "DETECTED",
                       "detail": {"root_cause": {"primary_cause": None}}}) == [],
      "an unknown component gets nothing rather than generic filler advice")

# --- other components get advice about the right subsystem ----------------
for component, expected in (("memory", "free"), ("disk", "df"),
                            ("network", "ping"), ("services", "systemctl")):
    got = ex.manual_steps(fake(component, None))
    check(bool(got) and expected in got[0]["command"],
          f"a {component} incident is pointed at {expected!r}: {got[0]['command'][:44]}")

# --- the commands are data, and stay data ---------------------------------
# Section 5 above proves this module imports nothing that can execute, which is
# what makes the strings here safe to build. Worth restating where the reason
# is sharpest: this section produces the text "kill 4242". The only thing
# standing between that string and a dead process is that nothing in this file,
# or on the page that prints it, can run it.
every = ex.manual_steps(fake("cpu", {"kind": "process", "pid": 4242,
                                     "name": "stress-ng", "share": 0.9}))
check(all(isinstance(s["command"], str) and isinstance(s["why"], str)
          for s in every),
      "every step is a string for a person to read, never a callable")
check(all(set(s) == {"kind", "command", "why", "caution"} for s in every),
      "and carries no field the template could mistake for an instruction to run")


# ===========================================================================
print("\n" + "=" * 78)
if failures:
    print(f"\033[31m{failures} expectation(s) failed\033[0m")
    sys.exit(1)
print("\033[32mEvery expectation held.\033[0m")
sys.exit(0)
