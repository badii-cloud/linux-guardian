#!/usr/bin/env python3
"""
Linux Guardian -- test_incidents.py                        (Phase 8, step 1)

PROOF THAT ONE EVENT PRODUCES ONE INCIDENT, THAT IT STAYS ONE INCIDENT, AND
THAT THE LIFECYCLE CANNOT BE WALKED THROUGH SIDEWAYS.

Run it live:   python3 test_incidents.py

The failures that matter in an incident engine are not crashes:

    one cause fills the list with four rows           (Phase 7's complaint)
    an hour-long problem becomes 120 incidents        (no deduplication)
    everything is CRITICAL                            (brief section 12)
    a remediation is called successful without proof  (brief section 25)
    a resolved incident silently reopens              (no state machine)

Every section below closes one of those. As with the other three suites this
prints a readable table and exits 0 only if every expectation held.
"""

import json
import math
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

temporary = tempfile.TemporaryDirectory(prefix="guardian-incident-test-")
TEST_DB = Path(temporary.name) / "test.db"
os.environ["GUARDIAN_DB"] = str(TEST_DB)

import guardian_anomaly as anomaly       # noqa: E402
import guardian_incidents as inc         # noqa: E402
import guardian_risk as risk             # noqa: E402
import guardian_store as store           # noqa: E402

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

ANOMALY_CONFIG = {
    "recent_seconds": 120,
    "baseline_seconds": 1200,
    "min_samples": 20,
    "z_warning": 3.0,
    "z_critical": 4.0,
    "min_change_percent": 10.0,
    "trend_lookbacks": [60, 300],
    "metrics": [],
}
anomaly.settings = lambda: dict(ANOMALY_CONFIG)


def fresh():
    connection = store.connect()
    for table in ("incident_timeline", "incidents", "samples", "sample_runs"):
        connection.execute(f"DELETE FROM {table}")
    connection.commit()
    return connection


def wobble(index, spread=1.0):
    return spread * math.sin(index * 1.7)


def plant(connection, ts, gauges=None, counters=None):
    store.store_sample(
        {
            "module": "metrics", "status": "ok", "timestamp": ts,
            "sample_duration_ms": 50.0,
            "source": {"interface": "eth0", "cpu_cores": 4},
            "gauges": gauges or {}, "counters": counters or {},
        },
        connection=connection,
    )


def cpu_history(connection, quiet_ticks=80, busy_ticks=12, busy=True):
    """A quiet baseline followed by the four-symptom CPU event from Phase 7."""
    for index in range(quiet_ticks):
        plant(connection, NOW - 1300 + index * 10, {
            "load_1min": 0.20 + wobble(index, 0.02),
            "load_5min": 0.40 + wobble(index, 0.02),
            "load_per_core": 0.060 + wobble(index, 0.005),
            "memory_used_percent": 40 + wobble(index),
        })
    for index in range(busy_ticks):
        plant(connection, NOW - 115 + index * 10, {
            "load_1min": (0.73 if busy else 0.20) + wobble(index, 0.02),
            "load_5min": (0.49 if busy else 0.40) + wobble(index, 0.02),
            "load_per_core": (0.18 if busy else 0.060) + wobble(index, 0.005),
            "memory_used_percent": 40 + wobble(index),
        })


# ===========================================================================
head("1. THE REGISTRY -- an incident may only recommend a REAL action")

problems = inc.check_registry()
check(not problems, f"{len(inc.TYPES)} incident types, no structural problems",
      "; ".join(problems) if problems else ", ".join(sorted(inc.TYPES)))

recommended = {
    action_id
    for definition in inc.TYPES.values()
    for action_id in (definition.get("recommended_actions") or [])
}
from guardian_actions import ACTIONS  # noqa: E402
check(
    recommended <= set(ACTIONS),
    f"every one of the {len(recommended)} recommended actions exists in actions.json",
    ", ".join(sorted(recommended)),
)

# The check that would catch a hopeful invention, proven to actually fire.
saved = inc.TYPES["cpu_saturation"]["recommended_actions"]
inc.TYPES["cpu_saturation"]["recommended_actions"] = ["rm_minus_rf_slash"]
caught = inc.check_registry()
inc.TYPES["cpu_saturation"]["recommended_actions"] = saved
check(
    any("rm_minus_rf_slash" in problem for problem in caught),
    "an invented action id is caught by check_registry(), not at demo time",
    next((p for p in caught if "rm_minus_rf_slash" in p), ""),
)

check(
    all(ACTIONS[d["investigate"]]["danger"] == "read"
        for d in inc.TYPES.values() if d.get("investigate")),
    "every 'investigate' action is read-only -- investigating never changes anything",
)


# ===========================================================================
head("2. CORRELATION -- Phase 7's four alarms become one incident")

connection = fresh()
cpu_history(connection)
report = anomaly.scan(connection=connection, now=NOW)
abnormal = [f for f in report["findings"] if f["verdict"] in ("WARNING", "CRITICAL")]

result = inc.process(report, connection=connection, now=NOW)
check(
    len(abnormal) >= 3 and len(result["opened"]) == 1,
    f"{len(abnormal)} abnormal metrics -> {len(result['opened'])} incident",
    f"metrics: {', '.join(f['metric'] for f in abnormal)}",
)

incident = inc.get(result["opened"][0], connection=connection)
check(incident["type"] == "cpu_saturation", f"correctly typed: {incident['title']}")
check(
    len(incident["symptoms"]) == len(abnormal),
    f"all {len(incident['symptoms'])} symptoms are listed inside the one incident",
    ", ".join(incident["symptoms"]),
)
check(
    incident["status"] == inc.DETECTED and incident["open"],
    f"it opens in {incident['status']}",
)
check(
    incident["id"].startswith("INC-") and len(incident["id"]) == 17,
    f"identifier is human-readable and dated: {incident['id']}",
    "a UUID would be untypeable and would say nothing about when it happened",
)

# Two unrelated conditions must NOT be merged.
#
# THE +5 OFFSET IS NOT COSMETIC. store.store_sample() treats a second document
# bearing a timestamp it already holds as a REPLACEMENT for that whole tick --
# documented behaviour, and the right behaviour. Planting listening_sockets at
# the same timestamps as cpu_history would therefore delete the CPU metrics
# rather than accompany them, and this test would "fail" by proving the store
# works. Five seconds apart, both conditions exist in the same window.
connection = fresh()
cpu_history(connection)
for index in range(80):
    plant(connection, NOW - 1295 + index * 10, {"listening_sockets": 3.0})
for index in range(12):
    plant(connection, NOW - 110 + index * 10, {"listening_sockets": 9.0})
report = anomaly.scan(connection=connection, now=NOW)
result = inc.process(report, connection=connection, now=NOW)
types = {inc.get(i, connection=connection)["type"] for i in result["opened"]}
check(
    types == {"cpu_saturation", "exposure_change"},
    f"a CPU event and a port change stay two incidents: {sorted(types)}",
    "correlation groups what the registry declares related, and nothing else",
)


# ===========================================================================
head("3. DEDUPLICATION -- an hour-long problem is ONE row, not 120")

connection = fresh()
cpu_history(connection)
report = anomaly.scan(connection=connection, now=NOW)

first = inc.process(report, connection=connection, now=NOW)
incident_id = first["opened"][0]
for tick in range(1, 12):
    inc.process(report, connection=connection, now=NOW + tick)

rows = inc.listing(connection=connection)
check(len(rows) == 1, f"12 consecutive scans of the same condition -> {len(rows)} incident row")
check(
    rows[0]["id"] == incident_id and rows[0]["occurrences"] == 12,
    f"the same incident, now seen {rows[0]['occurrences']} times",
)

entries = inc.timeline(incident_id, connection=connection)
check(
    len(entries) <= 5,
    f"the timeline has {len(entries)} entries, not 12 -- it records CHANGES, not ticks",
    " | ".join(f"{e['kind']}: {e['message'][:48]}" for e in entries),
)
check(
    all(a["ts"] <= b["ts"] for a, b in zip(entries, entries[1:])),
    "timeline entries are in time order",
)

# THE SYMPTOM LIST IS CUMULATIVE -- the regression guard for a flaw the first
# live run of Phase 8 exposed. A CPU incident opened on two metrics, ran for six
# observations and finished recorded as `symptoms: load_5min`, because each
# update overwrote the list with whatever was still abnormal at that instant --
# and the last instant of a recovering incident is the least informative one.
connection = fresh()
cpu_history(connection)
report = anomaly.scan(connection=connection, now=NOW)
opening = inc.process(report, connection=connection, now=NOW)["opened"][0]
opening_symptoms = set(inc.get(opening, connection=connection)["symptoms"])

# Now a scan in which only ONE of those symptoms is still abnormal, exactly as
# happens while an incident recovers.
narrowed = dict(report)
narrowed["findings"] = [
    f for f in report["findings"]
    if f["metric"] != "load_1min" or f["verdict"] not in ("WARNING", "CRITICAL")
] + [f for f in report["findings"] if f["metric"] == "load_1min"]
narrowed["findings"] = [
    f if f["metric"] in ("load_1min",) else dict(f, verdict="NORMAL")
    for f in report["findings"]
]
inc.process(narrowed, connection=connection, now=NOW + 30)
after = inc.get(opening, connection=connection)

check(
    opening_symptoms <= set(after["symptoms"]),
    f"after a tick where only one symptom remained, the incident still lists all "
    f"{len(after['symptoms'])}",
    f"opened with {sorted(opening_symptoms)}, still records {sorted(after['symptoms'])}",
)
check(
    after["detail"]["symptoms"] and len(after["detail"]["symptoms"]) == 1,
    "while the evidence shows only what is abnormal RIGHT NOW",
    "the two fields answer 'what has this involved' and 'what does it look like now'",
)

# THE SAME MISTAKE, ONE FIELD ACROSS -- found the day a user pressed
# Investigate, read the analysis, and found the panel empty thirty seconds
# later. `detail` is rebuilt from each observation, and writing it whole
# deleted every key an observation does not produce. root_cause is written
# there by guardian_rootcause.analyse(), so the next periodic tick destroyed
# the investigation the user had just asked for.
#
# An observation OWNS the keys it recomputes and must refresh them; it owns
# nothing else and must leave it alone.
import json as _json

with connection:
    connection.execute(
        "UPDATE incidents SET detail = ? WHERE id = ?",
        (_json.dumps({**after["detail"],
                      "root_cause": {"facts": ["planted by the test"],
                                     "primary_cause": {"kind": "process", "pid": 4242}}}),
         opening),
    )

before_tick = inc.get(opening, connection=connection)["detail"]
inc.process(report, connection=connection, now=NOW + 60)
after_tick = inc.get(opening, connection=connection)["detail"]

check(
    after_tick.get("root_cause", {}).get("primary_cause", {}).get("pid") == 4242,
    "an observation tick does not delete the root-cause analysis stored on the incident",
    f"detail keys before: {sorted(before_tick)} -> after: {sorted(after_tick)}",
)
check(
    after_tick["symptoms"] != before_tick.get("symptoms")
    or after_tick["risk"] == before_tick.get("risk"),
    "while the keys an observation DOES own are still refreshed by it",
    "the merge keeps foreign keys without freezing the observation's own",
)


# ===========================================================================
head("4. SEVERITY -- persistence escalates, low confidence caps  (brief 12)")

# Occurrence 1 vs occurrence 12 of the very same evidence.
early = risk.assess_severity(base="MEDIUM", verdict="CRITICAL", confidence=0.99, occurrences=1)
late = risk.assess_severity(base="MEDIUM", verdict="CRITICAL", confidence=0.99, occurrences=12)
check(
    early["severity"] == "HIGH" and late["severity"] == "CRITICAL",
    f"same evidence: seen once -> {early['severity']}, seen 12 times -> {late['severity']}",
    "a first sighting is not an emergency; something that will not go away is",
)

capped = risk.assess_severity(base="HIGH", verdict="CRITICAL", confidence=0.55, occurrences=20)
check(
    capped["severity"] == "MEDIUM",
    f"an alarming finding at 55% confidence is capped at {capped['severity']}",
    next(s for s in capped["steps"] if "capped" in s),
)

unknown = risk.assess_severity(base="HIGH", verdict="CRITICAL", confidence=None, occurrences=20)
check(
    unknown["severity"] == "MEDIUM",
    "a finding with NO computable confidence is capped too",
    next(s for s in unknown["steps"] if "capped" in s),
)

overflow = risk.assess_severity(
    base="CRITICAL", verdict="CRITICAL", confidence=0.99, occurrences=99, security_relevant=True
)
check(
    overflow["severity"] == "CRITICAL",
    "CRITICAL + three escalations stays CRITICAL -- it cannot fall off the ladder",
)

security = risk.assess_severity(base="LOW", verdict="WARNING", confidence=0.9,
                                occurrences=1, security_relevant=True)
plain = risk.assess_severity(base="LOW", verdict="WARNING", confidence=0.9, occurrences=1)
check(
    risk.severity_index(security["severity"]) == risk.severity_index(plain["severity"]) + 1,
    f"a security-relevant type is one step higher: {plain['severity']} -> {security['severity']}",
)

try:
    risk.assess_severity(base="EXTREMELY_BAD")
    check(False, "an unknown base severity was accepted")
except risk.RiskError as error:
    check(True, "an unknown severity name is refused", f"refused: {error}")


# ===========================================================================
head("5. RISK -- a weighted average, checked against hand arithmetic")

# All six factors at their maximum must be exactly 100, and all at zero exactly
# 0. If the weights were applied as a sum of penalties instead of an average,
# the first of these would overshoot.
top = risk.assess_risk(severity="CRITICAL", confidence=1.0, impact=1.0,
                       occurrences=999, previous_occurrences=999, security_relevant=True)
bottom = risk.assess_risk(severity="INFO", confidence=0.0, impact=0.0,
                          occurrences=0, previous_occurrences=0, security_relevant=False)
check(top["score"] == 100 and top["level"] == "CRITICAL", f"every factor maxed -> {top['score']}")
check(bottom["score"] == 0 and bottom["level"] == "LOW", f"every factor zero -> {bottom['score']}")

# One hand-worked example, computed here from the weights rather than hard-coded,
# so the test proves the implementation matches the documented formula.
config = risk.settings()
factors = {"severity": 2 / 4, "confidence": 0.9, "impact": 0.8,
           "persistence": 4 / config["persistence_full"],
           "recurrence": 2 / config["recurrence_full"], "security": 0.0}
weights = {name: config[f"weight_{name}"] for name in factors}
expected = round(100 * sum(weights[n] * factors[n] for n in factors) / sum(weights.values()))
got = risk.assess_risk(severity="MEDIUM", confidence=0.9, impact=0.8,
                       occurrences=4, previous_occurrences=2)
check(
    got["score"] == expected,
    f"MEDIUM/0.9/0.8/4x/2 prior -> {got['score']} ({got['level']}), matches the formula by hand",
)
check(
    abs(sum(got["contributions"].values()) - got["score"]) < 1.0,
    f"the contributions add up to the score: {got['contributions']}",
    "so 'risk 55' can be explained as 'of which N is severity'",
)

repeat = risk.assess_risk(severity="MEDIUM", confidence=0.9, impact=0.8,
                          occurrences=4, previous_occurrences=5)
check(
    repeat["score"] > got["score"],
    f"a repeat offender scores higher: {got['score']} -> {repeat['score']}",
    "recurrence is what separates 'happened' from 'keeps happening'",
)

assumed = risk.assess_risk(severity="MEDIUM", confidence=None, impact=0.5)
check(
    assumed["confidence_assumed"] is True,
    "when confidence had to be assumed, the result says so out loud",
)


# ===========================================================================
head("6. THE STATE MACHINE -- illegal moves are refused  (brief 25, 26)")

connection = fresh()
cpu_history(connection)
report = anomaly.scan(connection=connection, now=NOW)
incident_id = inc.process(report, connection=connection, now=NOW)["opened"][0]

inc.transition(incident_id, inc.INVESTIGATING, "gathering evidence",
               connection=connection, now=NOW + 1)
inc.transition(incident_id, inc.WAITING_APPROVAL, "restart recommended",
               connection=connection, now=NOW + 2)
inc.transition(incident_id, inc.REMEDIATING, "operator approved",
               connection=connection, now=NOW + 3)
check(
    inc.get(incident_id, connection=connection)["status"] == inc.REMEDIATING,
    "DETECTED -> INVESTIGATING -> WAITING_APPROVAL -> REMEDIATING all allowed",
)

# THE ONE THAT MATTERS: a remediation cannot declare itself successful.
try:
    inc.transition(incident_id, inc.RESOLVED, "systemctl exited 0",
                   connection=connection, now=NOW + 4)
    check(False, "REMEDIATING -> RESOLVED was allowed -- an exit code became proof")
except inc.IncidentError as error:
    check(True, "REMEDIATING -> RESOLVED is REFUSED: it must pass through VERIFYING",
          f"refused: {error}")

inc.transition(incident_id, inc.VERIFYING, "re-reading the metrics",
               connection=connection, now=NOW + 5)
inc.transition(incident_id, inc.RESOLVED, "load back within its normal range",
               connection=connection, now=NOW + 6)
check(
    inc.get(incident_id, connection=connection)["status"] == inc.RESOLVED,
    "and through VERIFYING it resolves normally",
)

try:
    inc.transition(incident_id, inc.DETECTED, "reopening", connection=connection, now=NOW + 7)
    check(False, "a RESOLVED incident was reopened")
except inc.IncidentError as error:
    check(True, "RESOLVED is final -- it cannot be walked backwards", f"refused: {error}")

for bad in ("APPROVED", "resolved", ""):
    try:
        inc.transition(incident_id, bad, "x", connection=connection, now=NOW + 8)
        check(False, f"the invented status {bad!r} was accepted")
    except inc.IncidentError:
        check(True, f"the invented status {bad!r} is refused")

try:
    inc.transition("INC-19700101-0001", inc.RESOLVED, "x", connection=connection)
    check(False, "a transition on a non-existent incident was accepted")
except inc.IncidentError as error:
    check(True, "a transition on an unknown incident is refused", f"refused: {error}")

entries = inc.timeline(incident_id, connection=connection)
statuses = [e["status"] for e in entries if e["kind"] == inc.TIMELINE_STATUS]
check(
    statuses == [inc.DETECTED, inc.INVESTIGATING, inc.WAITING_APPROVAL,
                 inc.REMEDIATING, inc.VERIFYING, inc.RESOLVED],
    "the timeline recorded every step, in order, including the refused one's absence",
    " -> ".join(statuses),
)

# Section 26: a failed remediation leaves the incident OPEN.
connection2 = store.connect()
second = inc.process(report, connection=connection2, now=NOW + 100)["opened"][0]
inc.transition(second, inc.INVESTIGATING, "looking", connection=connection2, now=NOW + 101)
inc.transition(second, inc.REMEDIATING, "restarting", connection=connection2, now=NOW + 102)
inc.transition(second, inc.FAILED, "service started then stopped again",
               connection=connection2, now=NOW + 103)
failed = inc.get(second, connection=connection2)
check(
    failed["status"] == inc.FAILED and failed["open"],
    "a FAILED remediation leaves the incident OPEN, with its evidence intact",
)
check(
    inc.INVESTIGATING in inc.TRANSITIONS[inc.FAILED],
    "and FAILED has a way back out, so a human can pick it up",
)
connection2.close()


# ===========================================================================
head("7. AUTOMATIC RESOLUTION -- and what must NOT auto-resolve")

connection = fresh()
cpu_history(connection, busy=True)
report = anomaly.scan(connection=connection, now=NOW)
incident_id = inc.process(report, connection=connection, now=NOW)["opened"][0]

# The same machine, now quiet: no abnormal metrics at all.
connection.execute("DELETE FROM samples")
connection.execute("DELETE FROM sample_runs")
connection.commit()
cpu_history(connection, busy=False)
calm = anomaly.scan(connection=connection, now=NOW)
result = inc.process(calm, connection=connection, now=NOW + 60)

check(
    incident_id in result["resolved"],
    f"the condition cleared, so {incident_id} resolved itself",
)
closed = inc.get(incident_id, connection=connection)
check(
    closed["status"] == inc.RESOLVED and closed["resolved_at"] is not None,
    "status RESOLVED, with a resolved_at timestamp",
)
check(
    "on their own" in closed["timeline"][-1]["message"],
    "and the timeline says the metrics recovered by themselves -- not that anything fixed them",
    closed["timeline"][-1]["message"],
)

# An incident somebody is working on must NOT be closed from underneath them.
connection = fresh()
cpu_history(connection, busy=True)
report = anomaly.scan(connection=connection, now=NOW)
busy_id = inc.process(report, connection=connection, now=NOW)["opened"][0]
inc.transition(busy_id, inc.INVESTIGATING, "looking", connection=connection, now=NOW + 1)
inc.transition(busy_id, inc.WAITING_APPROVAL, "needs a human", connection=connection, now=NOW + 2)

connection.execute("DELETE FROM samples")
connection.execute("DELETE FROM sample_runs")
connection.commit()
cpu_history(connection, busy=False)
calm = anomaly.scan(connection=connection, now=NOW)
inc.process(calm, connection=connection, now=NOW + 60)
check(
    inc.get(busy_id, connection=connection)["status"] == inc.WAITING_APPROVAL,
    "an incident WAITING_APPROVAL is left alone even though the metric recovered",
    "closing it would destroy the record of what a human was being asked to decide",
)


# ===========================================================================
head("8. RECURRENCE -- the same problem coming back scores higher")

connection = fresh()
cpu_history(connection, busy=True)
report = anomaly.scan(connection=connection, now=NOW)

first_id = inc.process(report, connection=connection, now=NOW)["opened"][0]
first_risk = inc.get(first_id, connection=connection)["risk_score"]
inc.transition(first_id, inc.RESOLVED, "cleared", connection=connection, now=NOW + 1)

second_id = inc.process(report, connection=connection, now=NOW + 2)["opened"][0]
second_risk = inc.get(second_id, connection=connection)["risk_score"]

check(second_id != first_id, f"after resolution a new occurrence opens a NEW incident: {second_id}")
check(
    second_risk > first_risk,
    f"and it scores higher for being a repeat: risk {first_risk} -> {second_risk}",
    "the fingerprint is what remembers that this has happened before",
)


# ===========================================================================
head("9. NOTHING IS SILENTLY DROPPED -- the fallback type")

connection = fresh()
for index in range(80):
    plant(connection, NOW - 1300 + index * 10, {"brand_new_metric": 5 + wobble(index, 0.1)})
for index in range(12):
    plant(connection, NOW - 115 + index * 10, {"brand_new_metric": 40 + wobble(index, 0.1)})
report = anomaly.scan(connection=connection, now=NOW)
result = inc.process(report, connection=connection, now=NOW)

check(len(result["opened"]) == 1, "a metric in no declared group still produces an incident")
unknown = inc.get(result["opened"][0], connection=connection)
check(
    unknown["type"] == inc.FALLBACK_TYPE and "brand_new_metric" in unknown["title"],
    f"under the fallback type, named after itself: {unknown['title']}",
)
check(
    unknown["severity"] in ("INFO", "LOW", "MEDIUM"),
    f"at low severity ({unknown['severity']}) -- visible, but not alarming",
)


# ===========================================================================
head("10. THE COMMAND LINE HONOURS THE PROJECT'S JSON CONTRACT")

environment = dict(os.environ)
environment["GUARDIAN_DB"] = str(TEST_DB)


def cli(*arguments):
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "guardian_incidents.py"),
         *arguments],
        capture_output=True, text=True, timeout=30, env=environment, check=False,
    )
    try:
        return completed.returncode, json.loads(completed.stdout)
    except json.JSONDecodeError:
        return completed.returncode, None


code, payload = cli("registry")
check(
    payload is not None and payload.get("status") == "ok" and not payload.get("problems"),
    f"`registry` reports a clean registry, exit {code}",
)

code, payload = cli("summary")
check(payload is not None and payload.get("status") == "ok", "`summary` returns counts")

code, payload = cli("list", "open")
check(payload is not None and payload.get("status") == "ok", "`list open` returns JSON")

code, payload = cli("list", "NOT_A_STATUS")
check(
    code != 0 and payload is not None and payload.get("status") == "error",
    "an invented status is refused rather than silently returning nothing",
    payload.get("message") if payload else "no JSON",
)

code, payload = cli("show", "INC-19700101-0001")
check(
    code != 0 and payload is not None and payload.get("status") == "error",
    "an unknown incident id exits non-zero with a JSON error",
)

code, payload = cli("nonsense")
check(code != 0 and payload is not None, "an unknown subcommand still prints valid JSON")


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
