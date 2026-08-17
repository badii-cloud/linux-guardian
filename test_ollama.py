#!/usr/bin/env python3
"""
Linux Guardian -- test_ollama.py                                   (Phase 6)

PROOF THAT THE OPTIONAL LANGUAGE MODEL CANNOT DO ANY HARM, AND THAT THE
CONSOLE DOES NOT NEED IT.

Run it live:   python3 test_ollama.py

PART A runs with Ollama genuinely absent -- the state this VM is in and the
state the demo runs in. It shows the console answering every action correctly
with no model involved at all.

PART B starts a FAKE Ollama on a spare port and feeds the classifier the
answers a real model might give, including the hostile ones. A stub is used
rather than a real model on purpose: a real model would have to be installed,
would answer differently on different machines, and -- crucially -- cannot be
made to return "rm -rf /" on demand. The security question here is not "what
does llama3.2 usually say", it is "what happens if a model says the worst
possible thing", and only a stub can ask that question reliably.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import guardian_actions as ga
import guardian_nlp as nlp
import guardian_ollama as go

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
head("PART A -- OLLAMA ABSENT (the real state of this machine)")

available, detail = go.probe()
print(f"  probe(): available={available}  detail={detail}")
print(f"  {record(available is False)}  probe reports unavailable without raising")

# THE HEADLINE CLAIM: every action in the registry is reachable by typing,
# with no model running. If this passes, Ollama is genuinely optional.
sentences = {
    "how full is my disk": "check_disk",
    "check the memory": "check_memory",
    "cpu usage": "check_cpu",
    "is the network ok": "check_network",
    "is apache2 running": "check_service",
    "what processes are running": "list_processes",
    "run a full health check": "run_diagnosis",
    "show me the logs": "show_logs",
    "restart apache2": "heal_service",
    "create a file called notes": "create_file",
    "create a file named schedule every thursday at 12 pm": "schedule_file",
    "list my files": "list_files",
    "list my schedules": "list_schedules",
    "cancel the schedule called schedule": "cancel_schedule",
}

covered = set()
for sentence, expected in sentences.items():
    candidates, source = nlp.resolve(sentence)
    got = candidates[0].action_id if candidates else None
    ok = got == expected and source == "keyword"
    covered.add(got)
    print(f"  {record(ok)}  {sentence!r:<52} -> {got} ({source})")

missing = set(ga.action_ids()) - covered
print(f"  {record(not missing)}  every registry action reachable by keyword "
      f"{'' if not missing else '-- MISSING: ' + str(missing)}")

# And a sentence nothing matches must still end cleanly, not hang for 8s
# waiting for a model that is not there.
candidates, source = nlp.resolve("make me a sandwich")
print(f"  {record(candidates == [] and source == 'none')}  "
      f"unmatched sentence -> no candidates, source={source!r}")


# ===========================================================================
head("PART B -- A FAKE OLLAMA, ANSWERING BADLY ON PURPOSE")

# What the stub will return as the model's answer. Each test sets this.
STUB = {"response": "{}", "delay": 0.0}


class Handler(BaseHTTPRequestHandler):
    """A four-line Ollama, enough to exercise the client."""

    def log_message(self, *args):
        pass                                    # keep the test output clean

    def _send(self, payload):
        body = json.dumps(payload).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # EXPECTED in the timeout test: the client gave up and closed the
            # socket while this handler was still sleeping. Writing to a closed
            # socket raises, and without this the stub prints an alarming
            # traceback for a case that is actually working correctly.
            pass

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def do_GET(self):
        # /api/tags -- what probe() calls
        self._send({"models": [{"name": "llama3.2:1b"}]})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if STUB["delay"]:
            import time
            time.sleep(STUB["delay"])
        self._send({"response": STUB["response"]})


server = HTTPServer(("127.0.0.1", 0), Handler)
port = server.server_port
threading.Thread(target=server.serve_forever, daemon=True).start()

# Point the client at the stub by replacing settings(). The config file on
# disk is left untouched, so this test cannot alter how the real console runs.
go.settings = lambda: {
    "url": f"http://127.0.0.1:{port}",
    "model": "llama3.2:1b",
    "timeout": 3.0,
}

available, detail = go.probe()
print(f"  {record(available)}  stub reachable: {detail}")

print("\n  What the 'model' returns                              -> what Guardian does")
print("  " + "-" * 74)

cases = [
    # (label, model answer, expected action_id or None)
    ("a correct answer",
     {"action_id": "check_disk", "params": {}, "confidence": 0.9}, "check_disk"),

    ("A SHELL COMMAND",
     {"action_id": "rm -rf /", "params": {}, "confidence": 0.99}, None),

    ("an action id with a command appended",
     {"action_id": "check_disk; whoami", "confidence": 0.99}, None),

    ("an action that does not exist",
     {"action_id": "delete_everything", "confidence": 1.0}, None),

    ("the right id in the wrong case",
     {"action_id": "CHECK_DISK", "confidence": 1.0}, None),

    ("an honest 'I do not know'",
     {"action_id": None, "confidence": 0.0}, None),

    ("a path instead of an id",
     {"action_id": "../../etc/passwd", "confidence": 1.0}, None),

    ("a list instead of an object",
     ["check_disk"], None),

    ("a number instead of an object",
     42, None),
]

for label, answer, expected in cases:
    STUB["response"] = json.dumps(answer)
    result = go.classify("anything")
    got = result["action_id"] if result else None
    print(f"  {record(got == expected)}  {label:<52} -> {got}")

# --- malformed output that is not even JSON -------------------------------
STUB["response"] = "Sure! Here is the answer: check_disk"
print(f"  {record(go.classify('x') is None)}  "
      f"{'prose instead of JSON':<52} -> None")

STUB["response"] = "{unclosed"
print(f"  {record(go.classify('x') is None)}  "
      f"{'truncated JSON':<52} -> None")


# ===========================================================================
head("PART C -- FIELDS THAT ARE WRONG BUT NOT DANGEROUS")

STUB["response"] = json.dumps(
    {"action_id": "check_disk", "confidence": "very high"})
result = go.classify("x")
print(f"  {record(result and result['confidence'] == 0.0)}  "
      f"confidence 'very high' -> {result['confidence'] if result else None} "
      f"(below every threshold, so it becomes a suggestion)")

STUB["response"] = json.dumps(
    {"action_id": "check_disk", "confidence": 5.0})
result = go.classify("x")
print(f"  {record(result and result['confidence'] == 1.0)}  "
      f"confidence 5.0 -> {result['confidence'] if result else None} (clamped)")

STUB["response"] = json.dumps(
    {"action_id": "check_disk", "params": {"target": "/etc", "name": "x"},
     "confidence": 0.9})
result = go.classify("x")
print(f"  {record(result and result['params'] == {})}  "
      f"invented params -> {result['params'] if result else None} "
      f"(check_disk declares none, so both are dropped)")


# ===========================================================================
head("PART D -- THE MODEL CLASSIFIES, THE REGEXES EXTRACT")

# The model is told the day is FRIDAY. The sentence plainly says thursday.
# The deterministic extractor must win.
STUB["response"] = json.dumps({
    "action_id": "schedule_file",
    "params": {"name": "wrongname", "day": "Fri", "time": "23:59"},
    "confidence": 0.95,
})
candidates, source = nlp.resolve("zzz qqq schedule_file thursday 12 pm called report")
if candidates:
    params = candidates[0].params
    ok = params.get("day") == "Thu" and params.get("time") == "12:00" \
        and params.get("name") == "report"
    print(f"  {record(ok)}  model said day=Fri time=23:59 name=wrongname")
    print(f"        sentence said thursday / 12 pm / report")
    print(f"        Guardian used -> {params}  (source={source})")
else:
    print(f"  {record(False)}  expected a candidate from the stub")

# And whatever the model says, the parameters still face the validator.
STUB["response"] = json.dumps({
    "action_id": "create_file",
    "params": {"name": "../../etc/passwd"},
    "confidence": 0.99,
})
candidates, _ = nlp.resolve("zzz qqq unmatchable")
if candidates:
    validation = ga.validate(candidates[0].action_id, candidates[0].params)
    print(f"  {record(not validation.ok)}  model supplied name='../../etc/passwd' "
          f"-> validator says: {validation.errors[0][:58]}...")
else:
    print(f"  {record(False)}  expected a candidate")


# ===========================================================================
head("PART E -- A SLOW MODEL MUST NOT HANG THE CONSOLE")

STUB["response"] = json.dumps({"action_id": "check_disk", "confidence": 0.9})
STUB["delay"] = 5.0                       # longer than the 3s test timeout

import time
started = time.monotonic()
result = go.classify("x")
elapsed = time.monotonic() - started
print(f"  {record(result is None and elapsed < 4.5)}  "
      f"5s model vs 3s timeout -> gave up after {elapsed:.1f}s, returned {result}")
STUB["delay"] = 0.0

server.shutdown()

# ===========================================================================
print("\n" + "=" * 78)
if failures:
    print(f"\033[31m{failures} expectation(s) failed\033[0m")
    sys.exit(1)
print("\033[32mEvery expectation held.\033[0m")
sys.exit(0)
