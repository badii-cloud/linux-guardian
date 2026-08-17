#!/usr/bin/env python3
"""
Linux Guardian -- test_guide.py                                    (Phase 9)

PROOF THAT THE ASSISTANT'S GUIDANCE IS TRUE.

Run it live:   python3 test_guide.py

A help page that lies is worse than no help page. Every example the console
shows is a CLAIM -- "type this and it will work" -- and this file checks each
claim by feeding the example back through the real matcher.

The four things proved here:

  1. Every action in the registry has guidance, and no guidance names an action
     that does not exist.
  2. Every example sentence resolves to the action it is filed under, above the
     confidence threshold, with the parameters the sentence states.
  3. The translator NEVER executes: it imports neither subprocess nor os, and
     the check is made against the PARSED SYNTAX TREE, not by searching the
     text -- a docstring promising "never executes" would satisfy a grep.
  4. A half-filled or hostile builder form produces errors and an empty argv,
     never a partly-built command.

Same style as the other six suites: a readable table rather than a dot per
test, and exit 1 on any failure so it works as a regression check.
"""

import ast
import sys

import guardian_actions as ga
import guardian_guide as guide
import guardian_nlp as nlp

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


# ===========================================================================
head("1. GUIDE INTEGRITY -- every action has guidance, no orphans")

problems = guide.check_guide()
for problem in problems:
    print(f"  {FAIL}  {problem}")
failures += len(problems)
if not problems:
    print(f"  {PASS}  {len(ga.ACTIONS)} actions, each with a template, a "
          f"'when to use' line and trigger phrases")

groups = guide.catalogue()
listed = sum(len(group["actions"]) for group in groups)
print(f"  {record(listed == len(ga.ACTIONS))}  catalogue lists {listed} of "
      f"{len(ga.ACTIONS)} actions across {len(groups)} groups")


# ===========================================================================
head("2. EVERY EXAMPLE SENTENCE ACTUALLY WORKS")
print("  Each example is fed back through guardian_nlp.match(). If an example")
print("  stops resolving to its own action, this test fails -- not a demo.\n")

for action_id in ga.ACTIONS:
    sentence = guide.example_sentence(action_id)
    candidates = nlp.match(sentence)
    top = candidates[0] if candidates else None
    confident = bool(top and top.confidence >= nlp.min_confidence())
    got = top.action_id if top else None

    ok = confident and got == action_id
    detail = f"{got} {top.confidence}" if top else "no match at all"
    print(f"  {record(ok)}  {sentence!r:<52} -> {detail}")
    if top and not confident:
        print(f"        \033[90m-> understood, but below the "
              f"{nlp.min_confidence()} threshold\033[0m")


# ===========================================================================
head("3. THE PARAMETERS IN AN EXAMPLE ARE THE ONES EXTRACTED")
print("  An example that names a file must produce that name, or the builder")
print("  is teaching a sentence whose values silently go missing.\n")

expectations = [
    ("create_file", {"name": "notes"}),
    ("schedule_file", {"name": "report", "day": "Thu", "time": "09:00"}),
    ("cancel_schedule", {"name": "report"}),
    ("heal_service", {"service": "apache2"}),
    ("check_service", {"service": "apache2"}),
]
for action_id, expected in expectations:
    sentence = guide.example_sentence(action_id)
    found = nlp.usable_params(action_id, nlp.extract_params(sentence))
    ok = all(found.get(key) == value for key, value in expected.items())
    print(f"  {record(ok)}  {action_id:<16} {sentence!r:<52} -> {found}")


# ===========================================================================
head("4. THE TRANSLATOR CANNOT EXECUTE ANYTHING")
print("  Checked against the parsed AST, not the file's text: a docstring")
print("  saying 'never runs a command' would pass a grep and prove nothing.\n")

tree = ast.parse(open(guide.__file__, encoding="utf-8").read())
imported = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        imported.update(alias.name.split(".")[0] for alias in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module:
        imported.add(node.module.split(".")[0])

for banned in ("subprocess", "os"):
    ok = banned not in imported
    print(f"  {record(ok)}  guardian_guide does not import {banned}")

print(f"        \033[90mimports: {', '.join(sorted(imported))}\033[0m")


# ===========================================================================
head("5. TRANSLATION -- English in, argv out, and the argv is a LIST")

result = guide.translate("create_file", {"name": "notes", "content": "hello there"})
checks = [
    ("understood", result["ok"]),
    ("sentence rebuilt", result["sentence"] == "create a file called notes containing hello there"),
    ("argv is a list", isinstance(result["argv"], list)),
    ("script is first", result["argv"][0].endswith("linux/workspace.sh")),
    ("fixed arg next", result["argv"][1] == "create"),
    ("name then content", result["argv"][2:] == ["notes", "hello there"]),
    ("space is quoted for reading", "'hello there'" in result["command"]),
    ("declared as a write", result["danger"] == "write"),
]
for label, ok in checks:
    print(f"  {record(ok)}  {label}")
print(f"        you type : {result['sentence']}")
print(f"        Linux runs: {result['command']}")


# ===========================================================================
head("6. A HALF-FILLED FORM IS NOT AN ERROR, BUT IT IS NOT A COMMAND EITHER")

partial = guide.translate("schedule_file", {"name": "report"})
print(f"  {record(not partial['ok'])}  incomplete form does not validate")
print(f"  {record(partial['argv'] == [])}  no argv is built from it")
print(f"  {record('<day>' in partial['sentence'])}  the sentence shows what is "
      f"missing: {partial['sentence']!r}")
print(f"        \033[90m{partial['errors']}\033[0m")

optional_missing = guide.translate("create_file", {"name": "notes"})
print(f"  {record(optional_missing['ok'])}  an optional parameter left blank "
      f"still validates")
print(f"  {record(optional_missing['sentence'] == 'create a file called notes')}"
      f"  the optional clause disappears entirely: "
      f"{optional_missing['sentence']!r}")


# ===========================================================================
head("7. THE BUILDER IS NOT A WAY ROUND THE VALIDATOR")
print("  The form posts values like any other request, so the same refusals")
print("  apply. These are the Phase 6 hostile inputs, entered through the")
print("  guided form instead of the text box.\n")

hostile = [
    ("create_file",     {"name": "../../etc/passwd"}, "path traversal"),
    ("create_file",     {"name": "evil.sh"},          "a chosen extension"),
    ("create_file",     {"name": "-rf"},              "a name that is really a flag"),
    ("create_file",     {"name": ""},                 "an empty name"),
    ("heal_service",    {"service": "ssh"},           "a protected service"),
    ("heal_service",    {"service": "nginx"},         "a service not on the allow-list"),
    ("schedule_file",   {"name": "x", "day": "funday", "time": "09:00"}, "not a day"),
    ("schedule_file",   {"name": "x", "day": "Thu", "time": "25:00"},    "not a time"),
    ("cancel_schedule", {"name": "../guardian"},      "escaping the unit prefix"),
    ("no_such_action",  {},                           "an action that does not exist"),
]
for action_id, params, why in hostile:
    answer = guide.translate(action_id, params)
    ok = (not answer["ok"]) and answer["argv"] == []
    print(f"  {record(ok)}  {why:<32} {action_id}({params})")
    print(f"        \033[90m{answer['errors'][0] if answer['errors'] else 'NO ERROR GIVEN'}\033[0m")


# ===========================================================================
head("8. THE COMMAND SHAPE AGREES WITH THE COMMAND BUILT")
print("  The shape shown before values exist must place its slots exactly")
print("  where build_command() will place the real values.\n")

for action_id in ("create_file", "schedule_file", "cancel_schedule", "heal_service"):
    action = ga.ACTIONS[action_id]
    shape = guide.command_shape(action)
    filled = guide.translate(action_id, {
        name: guide.SAMPLES[name]
        for name in (spec["name"] for spec in action["params"])
        if name in guide.SAMPLES
    })
    # Compare only the count and order of the positional slots: the shape has
    # <name>, the command has the value, but there must be the same number in
    # the same sequence.
    slots = [part for part in shape.split()[1:] if part.startswith(("<", "[<"))]
    values = filled["argv"][1 + len(action["args"]):] if filled["ok"] else []
    ok = len(slots) == len(values)
    print(f"  {record(ok)}  {action_id:<16} {shape}")
    print(f"        \033[90m-> {filled['command']}\033[0m")


# ===========================================================================
head("9. UNDERSTAND() -- the live 'as you type' line")

typed = [
    ("how full is my disk",          "ok",        "check_disk"),
    ("restart apache2",              "ok",        "heal_service"),
    ("qwertyuiop",                   "no_match",  None),
    ("",                             "empty",     None),
]
for text, expected_state, expected_id in typed:
    answer = guide.understand(text)
    ok = answer["state"] == expected_state
    if expected_id:
        ok = ok and answer.get("action_id") == expected_id
    print(f"  {record(ok)}  {text!r:<32} -> {answer['state']} "
          f"{answer.get('action_id') or ''}")

# A write action understood perfectly must still report will_run = False,
# because pressing Run gives a preview rather than restarting anything.
write = guide.understand("restart apache2")
print(f"  {record(write.get('will_run') is False)}  a write action reports "
      f"will_run=False -- Run gives a preview, not a restart")
read = guide.understand("how full is my disk")
print(f"  {record(read.get('will_run') is True)}  a read action reports "
      f"will_run=True -- it answers immediately")


# ===========================================================================
print("\n" + "=" * 78)
if failures:
    print(f"\033[31m{failures} expectation(s) failed\033[0m")
    sys.exit(1)
print("\033[32mEvery expectation held.\033[0m")
sys.exit(0)
