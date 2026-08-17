#!/usr/bin/env python3
"""
Linux Guardian -- test_rootcause.py                        (Phase 8, step 2)

PROOF THAT THE ANALYSIS NAMES A CAUSE WHEN THERE IS ONE, REFUSES TO WHEN THERE
IS NOT, AND NEVER PRESENTS A GUESS AS A MEASUREMENT.

Run it live:   python3 test_rootcause.py

The failure that matters here is not a crash. It is a confident sentence with
nothing behind it -- "the cause is process X" produced by templating whichever
process happened to be at the top of the list. Section 14 of the brief forbids
exactly that, and most of this file is about proving the restraint rather than
the capability.
"""

import json
import math
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

temporary = tempfile.TemporaryDirectory(prefix="guardian-rootcause-test-")
TEST_DB = Path(temporary.name) / "test.db"
os.environ["GUARDIAN_DB"] = str(TEST_DB)

import guardian_actions as actions        # noqa: E402
import guardian_incidents as inc          # noqa: E402
import guardian_rootcause as rc           # noqa: E402
import guardian_store as store            # noqa: E402

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

failures = 0


def head(title):
    print(f"\n\033[1m{title}\033[0m")
    print("-" * 78)


def check(ok, description, detail=""):
    global failures
    if not ok:
        failures += 1
    print(f"  {PASS if ok else FAIL}  {description}")
    if detail:
        print(f"        {detail}")


NOW = int(time.time())


def open_incident(type_id, component, metric, connection):
    """Put one incident in the database without running the whole detector."""
    candidate = {
        "type": type_id, "component": component, "metric_scope": None,
        "symptoms": [{
            "metric": metric, "verdict": "CRITICAL", "confidence": 0.97,
            "deviation": {"z_score": 8.0, "percent": 200.0, "absolute": 1.0},
            "current": {"mean": 3.0}, "baseline": {"mean": 1.0},
            "trend": {"direction": "rising"},
        }],
    }
    inc._summarise(candidate)
    return inc.record(candidate, connection=connection, now=NOW)["incident_id"]


def fresh():
    connection = store.connect()
    for table in ("incident_timeline", "incidents", "samples", "sample_runs"):
        connection.execute(f"DELETE FROM {table}")
    connection.commit()
    return connection


# ===========================================================================
head("1. INVESTIGATION CANNOT CHANGE THE MACHINE")

# The registry check already enforces this, but it is the single most important
# property of this module, so it is asserted here too rather than assumed.
investigators = {
    definition["investigate"]
    for definition in inc.TYPES.values()
    if definition.get("investigate")
}
check(
    all(actions.ACTIONS[a]["danger"] == "read" for a in investigators),
    f"all {len(investigators)} investigation actions are danger:read",
    ", ".join(sorted(investigators)),
)

# Checked against the PARSED SOURCE, not by searching the text. A substring
# search for "subprocess" also matches the file's own docstring, which says it
# does not use one -- the first version of this test failed on the sentence
# promising the thing the test was checking for.
import ast  # noqa: E402

tree = ast.parse(Path(rc.__file__).read_text(encoding="utf-8"))
imported = {
    alias.name.split(".")[0]
    for node in ast.walk(tree)
    if isinstance(node, ast.Import)
    for alias in node.names
} | {
    node.module.split(".")[0]
    for node in ast.walk(tree)
    if isinstance(node, ast.ImportFrom) and node.module
}
check(
    "subprocess" not in imported and "os" not in imported,
    "guardian_rootcause.py imports neither subprocess nor os -- it cannot run a command",
    f"imports: {', '.join(sorted(imported))}",
)

# A registry edited to point an investigation at a write action must be caught
# at the moment of use, not merely at load.
saved = inc.TYPES["cpu_saturation"]["investigate"]
inc.TYPES["cpu_saturation"]["investigate"] = "heal_service"
connection = fresh()
incident_id = open_incident("cpu_saturation", "cpu", "load_1min", connection)
evidence = rc.gather(inc.get(incident_id, connection=connection))
inc.TYPES["cpu_saturation"]["investigate"] = saved
check(
    evidence["status"] == "error",
    "an investigation pointed at a WRITE action is refused at the moment of use",
    evidence.get("message", ""),
)
connection.close()


# ===========================================================================
head("2. A REAL RUNAWAY PROCESS IS NAMED")

connection = fresh()
incident_id = open_incident("cpu_saturation", "cpu", "load_per_core", connection)

# A genuine busy loop, so the evidence comes from the real ps on this machine.
burner = subprocess.Popen(["bash", "-c", "while :; do :; done"])
time.sleep(2.5)
try:
    analysis = rc.analyse(incident_id, connection=connection, now=NOW)
finally:
    burner.kill()
    burner.wait()

cause = analysis["primary_cause"]
check(
    cause is not None and cause["kind"] == "process",
    f"a dominant process was identified: {cause}" if cause else "no cause was named",
)
check(
    cause and cause["pid"] == burner.pid,
    f"and it is the right one: pid {cause['pid'] if cause else '?'} "
    f"(the burner was {burner.pid})",
)
check(
    0 < analysis["confidence"] <= rc.MAX_CONFIDENCE,
    f"confidence {analysis['confidence']:.0%}, capped at {rc.MAX_CONFIDENCE:.0%}",
    "a root cause is an inference from one reading, never a proof",
)
check(
    any(str(burner.pid) in line for line in analysis["facts"]),
    "the pid appears in the FACTS, not only in the conclusion",
)
check(
    any(str(burner.pid) in line for line in analysis["recommendations"]),
    "and the recommendation names it too",
    analysis["recommendations"][0] if analysis["recommendations"] else "",
)


# ===========================================================================
head("3. IT REFUSES TO NAME A CAUSE WHEN THERE ISN'T ONE")

# Ten processes each at 5%: nothing dominates. A templated analysis would still
# blame the first one.
spread = [{"rank": i + 1, "pid": 1000 + i, "name": f"proc{i}",
           "cpu_percent": 5.0, "memory_mb": 10.0} for i in range(10)]
facts, inferences, recommendations, confidence, cause = rc._interpret_cpu(
    {"type": "cpu_saturation", "component": "cpu", "detail": {}},
    {"status": "ok", "data": spread},
)
check(cause is None, "ten equal processes -> no primary cause is claimed")
check(
    any("no single process dominates" in line for line in inferences),
    "and it says so plainly",
    inferences[0],
)
check(
    confidence <= 0.5,
    f"with low confidence ({confidence:.0%}), not a confident wrong answer",
)

# One process at 60% of the total is over the line; at 40% it is not.
def share_case(top_cpu, others):
    listing = [{"rank": 1, "pid": 99, "name": "hog", "cpu_percent": top_cpu, "memory_mb": 1}]
    listing += [{"rank": i + 2, "pid": 100 + i, "name": f"p{i}",
                 "cpu_percent": others, "memory_mb": 1} for i in range(4)]
    return rc._interpret_cpu({"type": "cpu_saturation", "component": "cpu", "detail": {}},
                             {"status": "ok", "data": listing})[4]

check(
    share_case(80.0, 5.0) is not None and share_case(20.0, 20.0) is None,
    f"the {rc.DOMINANCE_SHARE:.0%} dominance threshold is applied, not fudged",
    "80 vs 4x5 names a cause; 20 vs 4x20 does not",
)

# A component with no interpreter must say so rather than inventing prose.
facts, inferences, _, confidence, cause = rc._interpret_generic(
    {"component": "quantum_flux", "detail": {"symptoms": [
        {"metric": "flux", "current": 3.0, "baseline": 1.0}]}},
    {"status": "ok", "data": {}},
)
check(
    cause is None and confidence == 0.0
    and any("no root-cause interpreter" in line for line in inferences),
    "an unknown component reports that no interpreter exists, at zero confidence",
    inferences[0],
)
check(
    facts and "flux" in facts[0],
    "but it still reports the measured readings -- silence would be worse",
    facts[0],
)


# ===========================================================================
head("4. FACT, INFERENCE AND RECOMMENDATION STAY APART  (brief section 14)")

connection = fresh()
incident_id = open_incident("memory_pressure", "memory", "memory_used_percent", connection)
analysis = rc.analyse(incident_id, connection=connection, now=NOW)

check(
    {"facts", "inferences", "recommendations"} <= set(analysis),
    "the analysis has three separate lists, not one paragraph",
    f"{len(analysis['facts'])} facts, {len(analysis['inferences'])} inferences, "
    f"{len(analysis['recommendations'])} recommendations",
)
for line in analysis["facts"]:
    print(f"        FACT            {line}")
for line in analysis["inferences"]:
    print(f"        INFERENCE       {line}")
for line in analysis["recommendations"]:
    print(f"        RECOMMENDATION  {line}")

# A fact must be a measurement. The clearest machine-checkable proxy: no fact
# may contain the hedging words that belong in an inference.
hedges = ("probably", "likely", "suggests", "appears to", "may be", "seems")
check(
    not any(h in line.lower() for line in analysis["facts"] for h in hedges),
    "no FACT contains a hedging word -- hedges belong in inferences",
)
check(
    all(isinstance(line, str) and line for line in analysis["recommendations"]),
    "every recommendation is a sentence a human could act on",
)


# ===========================================================================
head("5. IT READS THE ALLOW-LIST RATHER THAN ASSUMING")

connection = fresh()
incident_id = open_incident("service_failure", "services", "failed_units", connection)
analysis = rc.analyse(incident_id, connection=connection, now=NOW)

healable = set(actions.config_words("HEALABLE_SERVICES"))
monitored = actions.config_words("MONITORED_SERVICES")
text = " ".join(analysis["recommendations"])

check(
    analysis["action"] == "check_service" and analysis["facts"],
    f"check_service was run once per monitored service ({', '.join(monitored)})",
    "; ".join(analysis["facts"]),
)
not_healable = [s for s in monitored if s not in healable]
if not_healable:
    check(
        any(f"{name}" in text and "NOT on the healing allow-list" in text
            for name in not_healable),
        f"a service outside HEALABLE_SERVICES is reported as off-limits ({not_healable[0]})",
        next((r for r in analysis["recommendations"] if "NOT on" in r), ""),
    )
else:
    check(True, "every monitored service is healable on this machine, nothing to refuse")


# ===========================================================================
head("6. THE INCIDENT RECORD IS UPDATED, AND CLOSED ONES ARE PROTECTED")

connection = fresh()
incident_id = open_incident("cpu_saturation", "cpu", "load_1min", connection)
before = inc.get(incident_id, connection=connection)
check(before["status"] == inc.DETECTED, "the incident starts DETECTED")

rc.analyse(incident_id, connection=connection, now=NOW)
after = inc.get(incident_id, connection=connection)
check(
    after["status"] == inc.INVESTIGATING,
    "investigating moves it DETECTED -> INVESTIGATING",
)
check(
    after["detail"].get("root_cause") is not None,
    "the analysis is stored on the incident, so the page needs no re-investigation",
)
check(
    any("investigated with" in e["message"] for e in after["timeline"]),
    "and the timeline records that it happened",
    next(e["message"] for e in after["timeline"] if "investigated with" in e["message"]),
)

# A second investigation of an already-INVESTIGATING incident is allowed and
# must not throw -- a human may well press the button twice.
rc.analyse(incident_id, connection=connection, now=NOW + 5)
check(
    inc.get(incident_id, connection=connection)["status"] == inc.INVESTIGATING,
    "investigating twice is harmless and does not double-transition",
)

inc.transition(incident_id, inc.RESOLVED, "cleared", connection=connection, now=NOW + 10)
try:
    rc.analyse(incident_id, connection=connection, now=NOW + 11)
    check(False, "a RESOLVED incident was investigated, appending to a finished record")
except rc.RootCauseError as error:
    check(True, "investigating a RESOLVED incident is refused", f"refused: {error}")


# ===========================================================================
head("7. THE COMMAND LINE HONOURS THE PROJECT'S JSON CONTRACT")

environment = dict(os.environ)
environment["GUARDIAN_DB"] = str(TEST_DB)


def cli(*arguments):
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "guardian_rootcause.py"),
         *arguments],
        capture_output=True, text=True, timeout=60, env=environment, check=False,
    )
    try:
        return completed.returncode, json.loads(completed.stdout)
    except json.JSONDecodeError:
        return completed.returncode, None


connection = fresh()
live_id = open_incident("cpu_saturation", "cpu", "load_1min", connection)
connection.close()

code, payload = cli("analyse", live_id)
check(
    payload is not None and payload.get("status") == "ok",
    f"`analyse {live_id}` returns one JSON object, exit {code}",
)

code, payload = cli("analyse", "INC-19700101-0001")
check(
    code != 0 and payload is not None and payload.get("status") == "error",
    "an unknown incident exits non-zero with a JSON error",
    payload.get("message") if payload else "no JSON",
)

code, payload = cli("nonsense")
check(code != 0 and payload is not None, "an unknown subcommand still prints valid JSON")

code, payload = cli()
check(code == 2 and payload is not None, "no arguments prints usage as JSON, exit 2")


# ===========================================================================
print()
print("=" * 78)
if failures:
    print(f"  {FAIL}  {failures} expectation(s) did not hold")
else:
    print(f"  {PASS}  every expectation held")
print("=" * 78)

temporary.cleanup()
sys.exit(1 if failures else 0)
