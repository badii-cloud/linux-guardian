#!/usr/bin/env python3
"""
Linux Guardian -- test_remediate.py                        (Phase 8, step 2)

PROOF THAT A FIX NEEDS PERMISSION, CANNOT BE FORGED, AND IS NEVER BELIEVED
WITHOUT BEING CHECKED.

Run it live:   python3 test_remediate.py

The three failures this file exists to prevent:

    a crafted POST runs something nobody approved
    an action reports success and the machine is still broken
    a failed fix retries in a loop until the service is destroyed

Nothing here restarts a real service. The execution step is STUBBED, exactly
as test_ollama.py stubs the model API -- which is what lets the most important
test in the file exist at all: an action that CLAIMS to have worked while the
service is still down. That situation cannot be produced on demand with a real
systemctl, and it is precisely the one section 25 of the brief is about.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

temporary = tempfile.TemporaryDirectory(prefix="guardian-remediate-test-")
TEST_DB = Path(temporary.name) / "test.db"
os.environ["GUARDIAN_DB"] = str(TEST_DB)

import guardian_actions as actions      # noqa: E402
import guardian_incidents as inc        # noqa: E402
import guardian_remediate as rem        # noqa: E402
import guardian_store as store          # noqa: E402

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

# The verification pause is real seconds. Shortened here so the suite runs in a
# few seconds rather than a minute; the code path is identical.
rem.VERIFY_DELAY_SECONDS = 0

HEALABLE = actions.config_words("HEALABLE_SERVICES")
TARGET = HEALABLE[0] if HEALABLE else "apache2"


def fresh():
    connection = store.connect()
    for table in ("incident_timeline", "incidents", "samples", "sample_runs"):
        connection.execute(f"DELETE FROM {table}")
    connection.commit()
    return connection


def open_service_incident(connection, units=None):
    """A service_failure incident that has already been investigated."""
    candidate = {
        "type": "service_failure", "component": "services", "metric_scope": None,
        "symptoms": [{
            "metric": "failed_units", "verdict": "CRITICAL", "confidence": 0.96,
            "deviation": {"z_score": 9.0, "percent": 900.0, "absolute": 1.0},
            "current": {"mean": 1.0}, "baseline": {"mean": 0.0},
            "trend": {"direction": "rising"},
        }],
    }
    inc._summarise(candidate)
    incident_id = inc.record(candidate, connection=connection, now=NOW)["incident_id"]

    # Plant the root-cause result the investigation would have produced, so the
    # remediation has a unit to work on without needing that unit to be down.
    with connection:
        row = connection.execute(
            "SELECT detail FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        detail = json.loads(row["detail"] or "{}")
        detail["root_cause"] = {
            "facts": [], "inferences": [], "recommendations": [], "confidence": 0.9,
            "primary_cause": {"kind": "service", "units": units if units is not None else [TARGET]},
        }
        connection.execute("UPDATE incidents SET detail = ? WHERE id = ?",
                           (json.dumps(detail), incident_id))
    inc.transition(incident_id, inc.INVESTIGATING, "investigated",
                   connection=connection, now=NOW)
    return incident_id


class Stub:
    """Replaces guardian_actions.execute for the duration of one test.

    Records what it was asked to run, and answers whatever the test needs --
    including "success" when the machine is in fact still broken.
    """

    def __init__(self, result, passthrough_reads=True):
        self.result = result
        self.passthrough_reads = passthrough_reads
        self.calls = []
        self.real = actions.execute

    def __enter__(self):
        def fake(validation):
            self.calls.append((validation.action["id"], dict(validation.params)))
            if self.passthrough_reads and validation.action["danger"] == "read":
                return self.real(validation)
            return self.result
        actions.execute = fake
        rem.actions.execute = fake
        return self

    def __exit__(self, *exc):
        actions.execute = self.real
        rem.actions.execute = self.real


# ===========================================================================
head("1. A PROPOSAL IS A DESCRIPTION, NOT A PERMISSION  (brief section 24)")

connection = fresh()
incident_id = open_service_incident(connection)

with Stub({"status": "ok", "data": {}}) as stub:
    preview = rem.propose(incident_id, connection=connection, now=NOW)

check(not stub.calls, "propose() ran NOTHING -- zero actions executed",
      f"calls: {stub.calls}")
check(
    preview["action"] == "heal_service" and preview["parameters"]["service"] == TARGET,
    f"the preview names {preview['action']} on {preview['parameters']}",
)
check(
    preview["risk"]["level"] in ("LOW", "MEDIUM", "HIGH"),
    f"the ACTION's own risk is scored: {preview['risk']['level']} ({preview['risk']['score']}/100)",
    "this is the risk of the act, not of the incident that prompted it",
)
check(bool(preview["expected"]),
      f"an expected result is written down BEFORE the act: \"{preview['expected']}\"",
      "an expectation invented afterwards can never fail")
check(
    inc.get(incident_id, connection=connection)["status"] == inc.WAITING_APPROVAL,
    "and the incident is now WAITING_APPROVAL",
)


# ===========================================================================
head("2. A FORGED APPROVAL GAINS NOTHING")

# An action from another incident type's list.
with Stub({"status": "ok", "data": {}}) as stub:
    try:
        rem.approve(incident_id, "create_file", connection=connection, now=NOW)
        check(False, "an action outside this incident's list was accepted")
    except rem.RemediationError as error:
        check(True, "an action this incident type never recommends is refused",
              f"refused: {error}")
    check(not stub.calls, "and nothing ran")

# An action that does not exist at all.
with Stub({"status": "ok", "data": {}}) as stub:
    for forged in ("rm_rf_slash", "", "heal_service; rm -rf /", "HEAL_SERVICE"):
        try:
            rem.approve(incident_id, forged, connection=connection, now=NOW)
            check(False, f"the forged id {forged!r} was accepted")
        except rem.RemediationError:
            check(True, f"the forged id {forged!r} is refused")
    check(not stub.calls, "none of them ran a single command")

# The refusals are recorded, not discarded.
entries = inc.timeline(incident_id, connection=connection)
refusals = [e for e in entries if "refused" in e["message"]]
check(
    len(refusals) >= 5,
    f"all {len(refusals)} refusals are written to the incident's timeline",
    refusals[0]["message"] if refusals else "",
)
check(
    inc.get(incident_id, connection=connection)["status"] == inc.WAITING_APPROVAL,
    "and the incident is untouched, still waiting for a real approval",
)


# ===========================================================================
head("3. PARAMETERS ARE DERIVED, NEVER ACCEPTED")

# There is deliberately no way to pass a service name in: approve() takes an
# incident id and an action id and nothing else. The proof is the signature.
import inspect  # noqa: E402

parameters = list(inspect.signature(rem.approve).parameters)
check(
    "parameters" not in parameters and "params" not in parameters,
    f"approve() has no parameter for parameters: {parameters}",
    "there is no path from an HTTP request to a value on a command line",
)

# An incident whose root cause names a service NOT on the allow-list cannot
# produce a remediation at all.
connection2 = fresh()
protected_id = open_service_incident(connection2, units=["ssh"])
try:
    rem.propose(protected_id, connection=connection2, now=NOW)
    check("ssh" in HEALABLE, "a protected service produced a proposal")
except rem.RemediationError as error:
    check(True, "an incident about a service outside HEALABLE_SERVICES cannot be remediated",
          f"refused: {error}")

# And one that was never investigated has nothing to act on.
connection3 = fresh()
candidate = {
    "type": "service_failure", "component": "services", "metric_scope": None,
    "symptoms": [{"metric": "failed_units", "verdict": "CRITICAL", "confidence": 0.9,
                  "deviation": {"z_score": 9.0, "percent": 900.0, "absolute": 1.0},
                  "current": {"mean": 1.0}, "baseline": {"mean": 0.0},
                  "trend": {"direction": "rising"}}],
}
inc._summarise(candidate)
raw_id = inc.record(candidate, connection=connection3, now=NOW)["incident_id"]
try:
    rem.propose(raw_id, connection=connection3, now=NOW)
    check(False, "an uninvestigated incident produced a remediation")
except rem.RemediationError as error:
    check(True, "an uninvestigated incident has no target, so no fix is offered",
          f"refused: {error}")
connection2.close()
connection3.close()


# ===========================================================================
head("4. THE EXIT CODE IS NOT PROOF  (brief section 25 -- the important one)")

# The action reports complete success. The service is still down. A system that
# trusted the exit status would mark this incident RESOLVED and move on.
connection = fresh()
incident_id = open_service_incident(connection)
rem.propose(incident_id, connection=connection, now=NOW)

DEAD = {
    "status": "ok",
    "data": {"name": TARGET, "installed": True, "active_state": "failed",
             "sub_state": "dead", "running": False, "failed": True, "main_pid": None},
}


def lying_execute(validation):
    """heal_service claims success; check_service reports the truth."""
    if validation.action["id"] == "check_service":
        return DEAD
    return {"status": "ok", "data": {"result": "healed", "systemctl_exit_code": 0}}


real_execute = actions.execute
actions.execute = lying_execute
rem.actions.execute = lying_execute
try:
    outcome = rem.approve(incident_id, "heal_service", connection=connection, now=NOW)
finally:
    actions.execute = real_execute
    rem.actions.execute = real_execute

check(
    outcome["exit_status"] == "ok",
    "the action reported status 'ok' -- a system trusting exit codes stops here",
)
check(
    outcome["verified"] is False,
    "but verification FAILED, because it re-measured instead of believing the report",
)
for line in outcome["checks"]:
    print(f"        [{'ok  ' if line['ok'] else 'FAIL'}] {line['message']}")

incident = inc.get(incident_id, connection=connection)
check(
    incident["status"] == inc.FAILED,
    f"the incident is {incident['status']}, not RESOLVED",
)
check(incident["open"], "and it is still OPEN -- section 26: a failed fix stays open")
check(
    any("no retry will be attempted" in e["message"] for e in incident["timeline"]),
    "the timeline says plainly that no retry will be attempted",
    next((e["message"][:90] for e in incident["timeline"]
          if "no retry" in e["message"]), ""),
)
check(
    inc.INVESTIGATING in inc.TRANSITIONS[inc.FAILED],
    "and there is a route back out of FAILED for a human to take",
)


# ===========================================================================
head("5. A REAL SUCCESS RESOLVES IT, WITH EVIDENCE")

connection = fresh()
incident_id = open_service_incident(connection)
rem.propose(incident_id, connection=connection, now=NOW)

ALIVE = {
    "status": "ok",
    "data": {"name": TARGET, "installed": True, "active_state": "active",
             "sub_state": "running", "running": True, "failed": False, "main_pid": 4242},
}


def honest_execute(validation):
    if validation.action["id"] == "check_service":
        return ALIVE
    return {"status": "ok", "data": {"result": "healed", "systemctl_exit_code": 0}}


actions.execute = honest_execute
rem.actions.execute = honest_execute
try:
    outcome = rem.approve(incident_id, "heal_service", connection=connection,
                          now=NOW, operator="test")
finally:
    actions.execute = real_execute
    rem.actions.execute = real_execute

check(outcome["verified"] is True, "verification passed on an independent re-read")
for line in outcome["checks"]:
    print(f"        [{'ok  ' if line['ok'] else 'FAIL'}] {line['message']}")

incident = inc.get(incident_id, connection=connection)
check(incident["status"] == inc.RESOLVED, f"the incident is {incident['status']}")
check(
    incident["resolved_at"] is not None,
    "with a resolved_at timestamp",
)
check(
    "before" in outcome and "after" in outcome,
    "and a before/after comparison is stored  (brief section 28)",
    f"before: {outcome['before']['severity']} / risk {outcome['before']['risk_score']}",
)

statuses = [e["status"] for e in incident["timeline"] if e["kind"] in ("STATUS", "ACTION", "VERIFY") and e["status"]]
check(
    inc.VERIFYING in statuses and statuses[-1] == inc.RESOLVED,
    "the lifecycle passed through VERIFYING on its way to RESOLVED",
    " -> ".join(statuses),
)
check(
    any(e["kind"] == inc.TIMELINE_ACTION and "test" in e["message"]
        for e in incident["timeline"]),
    "and the timeline records WHO approved it",
    next((e["message"][:80] for e in incident["timeline"]
          if e["kind"] == inc.TIMELINE_ACTION and "test" in e["message"]), ""),
)


# ===========================================================================
head("6. REJECTION, AND APPROVING OUT OF ORDER")

connection = fresh()
incident_id = open_service_incident(connection)
rem.propose(incident_id, connection=connection, now=NOW)
rem.reject(incident_id, "not now", connection=connection, now=NOW)

check(
    inc.get(incident_id, connection=connection)["status"] == inc.INVESTIGATING,
    "rejecting hands the incident back to INVESTIGATING",
)

with Stub({"status": "ok", "data": {}}) as stub:
    try:
        rem.approve(incident_id, "heal_service", connection=connection, now=NOW)
        check(False, "an approval was accepted without a proposal")
    except rem.RemediationError as error:
        check(True, "an approval with no proposal in front of it is refused",
              f"refused: {error}")
    check(not stub.calls, "and nothing ran")

# A resolved incident cannot be remediated again.
connection = fresh()
incident_id = open_service_incident(connection)
inc.transition(incident_id, inc.RESOLVED, "cleared", connection=connection, now=NOW)
try:
    rem.propose(incident_id, connection=connection, now=NOW)
    check(False, "a RESOLVED incident accepted a remediation proposal")
except rem.RemediationError as error:
    check(True, "a RESOLVED incident cannot be remediated", f"refused: {error}")


# ===========================================================================
head("7. THE COMMAND LINE HONOURS THE PROJECT'S JSON CONTRACT")

environment = dict(os.environ)
environment["GUARDIAN_DB"] = str(TEST_DB)


def cli(*arguments):
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "guardian_remediate.py"),
         *arguments],
        capture_output=True, text=True, timeout=60, env=environment, check=False,
    )
    try:
        return completed.returncode, json.loads(completed.stdout)
    except json.JSONDecodeError:
        return completed.returncode, None


code, payload = cli("propose", "INC-19700101-0001")
check(
    code != 0 and payload is not None and payload.get("status") == "error",
    "an unknown incident exits non-zero with a JSON error",
    payload.get("message") if payload else "no JSON",
)

code, payload = cli("approve", "INC-19700101-0001", "heal_service")
check(code != 0 and payload is not None, "so does an approval on an unknown incident")

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
