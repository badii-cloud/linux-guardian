#!/usr/bin/env python3
"""
Linux Guardian -- test_anomaly.py                          (Phase 7, step 3)

PROOF THAT THE DETECTOR IS RIGHT WHEN IT SPEAKS, AND SILENT WHEN IT SHOULD BE.

Run it live:   python3 test_anomaly.py

A detector is easy to write and hard to trust. The failures that matter are not
crashes -- they are the three ways it can be confidently wrong:

    it calls a real anomaly normal        (missed, the dangerous one)
    it calls ordinary noise an anomaly    (cried wolf, and gets switched off)
    it says "normal" when it means "I have not got enough data yet"

Every section below exists to close one of those. As with test_actions.py and
test_store.py this prints a readable table rather than a dot per test, and exits
0 only if every expectation held.

It runs entirely against synthetic data in a throwaway database, because a test
of "does it detect a 300% CPU spike" needs a 300% CPU spike that arrives on cue.
"""

import json
import math
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import guardian_store as store

# GUARDIAN_DB must be set BEFORE guardian_anomaly is imported, because settings()
# reads the config lazily but store.connect() would otherwise be pointed at the
# real database the first time anything touches it.
temporary = tempfile.TemporaryDirectory(prefix="guardian-anomaly-test-")
TEST_DB = Path(temporary.name) / "test.db"
os.environ["GUARDIAN_DB"] = str(TEST_DB)

import guardian_anomaly as anomaly  # noqa: E402  (must follow the line above)

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

# A fixed configuration, so a later edit to guardian.conf cannot change what
# these tests mean. The windows are short because the synthetic history is short.
CONFIG = {
    "recent_seconds": 120,
    "baseline_seconds": 1200,
    "min_samples": 20,
    "z_warning": 3.0,
    "z_critical": 4.0,
    "min_change_percent": 10.0,
    "trend_lookbacks": [60, 300, 900],
    "metrics": [],
}


def fresh():
    """A brand-new empty history. Each section starts from nothing."""
    connection = store.connect()
    connection.execute("DELETE FROM samples")
    connection.execute("DELETE FROM sample_runs")
    connection.commit()
    return connection


def plant(connection, ts, gauges=None, counters=None):
    """One synthetic tick."""
    store.store_sample(
        {
            "module": "metrics",
            "status": "ok",
            "timestamp": ts,
            "sample_duration_ms": 50.0,
            "source": {"interface": "eth0", "cpu_cores": 4},
            "gauges": gauges or {},
            "counters": counters or {},
        },
        connection=connection,
    )


def wobble(index, spread=1.0):
    """Deterministic pseudo-noise -- a sine, so the tests never flap.

    random.seed() would also be reproducible, but a sine makes the intent
    visible: this is a metric that varies smoothly around a level, which is what
    an idle machine's CPU actually looks like.
    """
    return spread * math.sin(index * 1.7)


# ===========================================================================
head("1. CHEBYSHEV -- the confidence is a real bound, not a guess")

# P(|X - mean| >= k*stddev) <= 1/k^2 for ANY distribution, so the confidence
# reported at k standard deviations is 1 - 1/k^2 exactly.
for z, expected in ((3.0, 1 - 1 / 9), (4.0, 1 - 1 / 16), (10.0, 1 - 1 / 100)):
    got = anomaly._confidence(z)
    check(
        abs(got - expected) < 1e-12,
        f"z={z}  ->  confidence {got * 100:.2f}%  (1 - 1/{z:.0f}^2)",
    )

check(
    anomaly._confidence(1.0) == 0.0 and anomaly._confidence(0.5) == 0.0,
    "at or below 1 standard deviation the bound says nothing, so confidence is 0",
    "Chebyshev at k=1 permits 100% of readings -- no information",
)
check(
    anomaly._confidence(3.0) < 0.997,
    f"3 sigma reports {anomaly._confidence(3.0) * 100:.1f}%, NOT the normal curve's 99.7%",
    "the smaller number is the honest one -- CPU usage is not a bell curve",
)


# ===========================================================================
head("2. THE SELF-TEACHING BUG -- the baseline must exclude what it judges")

# 100 ticks at 20%, then 20 ticks at 90% -- an anomaly long enough to fill the
# whole recent window. If the baseline included the recent window, its mean
# would be dragged up towards 90 and the deviation would shrink.
connection = fresh()
for index in range(100):
    plant(connection, NOW - 1300 + index * 10, {"cpu": 20 + wobble(index)})
for index in range(20):
    plant(connection, NOW - 115 + index * 6, {"cpu": 90 + wobble(index)})

result = anomaly.analyse("cpu", connection=connection, now=NOW, config=CONFIG)
check(
    abs(result["baseline"]["mean"] - 20) < 1.0,
    f"baseline mean is {result['baseline']['mean']:.2f} -- still the quiet period, not the spike",
    "the baseline window ends where the recent window begins",
)
check(
    abs(result["current"]["mean"] - 90) < 1.0,
    f"current mean is {result['current']['mean']:.2f} -- the spike, judged separately",
)
check(
    result["verdict"] == anomaly.CRITICAL,
    f"verdict {result['verdict']}, z={result['deviation']['z_score']:.1f}, "
    f"confidence {result['confidence'] * 100:.2f}%",
    result["reason"],
)
check(
    result["baseline"]["samples"] > 0
    and result["baseline"]["samples"] + result["current"]["samples"] <= 120,
    f"{result['baseline']['samples']} baseline + {result['current']['samples']} recent "
    f"readings, no reading counted twice",
)


# ===========================================================================
head("3. IT SAYS 'LEARNING', NOT 'NORMAL', BEFORE IT KNOWS ANYTHING")

connection = fresh()
for index in range(5):
    plant(connection, NOW - 300 + index * 10, {"cpu": 20 + wobble(index)})
plant(connection, NOW - 30, {"cpu": 95})

result = anomaly.analyse("cpu", connection=connection, now=NOW, config=CONFIG)
check(
    result["verdict"] == anomaly.LEARNING,
    f"5 baseline readings -> {result['verdict']}",
    result["reason"],
)
check(
    result["verdict"] != anomaly.NORMAL,
    "and it is NOT reported as NORMAL -- 'no idea yet' must not look like a clean bill of health",
)
check(result["confidence"] == 0.0, "no confidence is claimed while learning")


# ===========================================================================
head("4. THE NOISE DAMPENER -- a very steady metric must not cry wolf")

# A metric pinned at 3.00 for the whole baseline, moving to 3.05. The z-score is
# astronomical; the change is 1.7% and nobody cares.
connection = fresh()
for index in range(60):
    plant(connection, NOW - 1300 + index * 15, {"cpu": 3.00 + (0.001 if index % 2 else -0.001)})
for index in range(10):
    plant(connection, NOW - 115 + index * 10, {"cpu": 3.05})

result = anomaly.analyse("cpu", connection=connection, now=NOW, config=CONFIG)
check(
    result["verdict"] == anomaly.NORMAL,
    f"3.00 -> 3.05 with z={result['deviation']['z_score']:.0f} is still {result['verdict']}",
    result["reason"],
)
check(
    result["tests"]["statistical"] and not result["tests"]["material"],
    "the output shows WHICH test stopped it: statistical passed, material failed",
    f"tests: {result['tests']}",
)

# The same metric making a change that does matter must still fire.
connection = fresh()
for index in range(60):
    plant(connection, NOW - 1300 + index * 15, {"cpu": 3.00 + (0.001 if index % 2 else -0.001)})
for index in range(10):
    plant(connection, NOW - 115 + index * 10, {"cpu": 45.0})
result = anomaly.analyse("cpu", connection=connection, now=NOW, config=CONFIG)
check(
    result["verdict"] == anomaly.CRITICAL,
    f"the same steady metric jumping to 45.0 is {result['verdict']} -- the dampener "
    f"is not a blindfold",
)


# ===========================================================================
head("5. THE ZERO-VARIANCE BLIND SPOT -- found by testing, not by reading")

# A counter incrementing by exactly the same amount every tick has a rate with
# NO variance at all, so there is no standard deviation and no z-score. The
# first version of this detector reported a twentyfold traffic spike as NORMAL.
connection = fresh()
total = 5_000_000
for index in range(80):
    total += 10_000                       # exactly 1000 bytes/second, forever
    plant(connection, NOW - 1300 + index * 10, counters={"net_rx_bytes": total})
for index in range(12):
    total += 200_000                      # twenty times as much
    plant(connection, NOW - 115 + index * 10, counters={"net_rx_bytes": total})

result = anomaly.analyse("net_rx_bytes", connection=connection, now=NOW, config=CONFIG)
check(
    result["deviation"]["z_score"] is None and result["baseline"]["zero_variance"],
    "the baseline really does have zero variance, so no z-score exists",
    f"baseline {result['baseline']['minimum']:.0f} to {result['baseline']['maximum']:.0f} bytes/s",
)
check(
    result["verdict"] == anomaly.WARNING,
    f"a 20x rate change is still caught: {result['verdict']}",
    result["reason"],
)
check(
    result["confidence"] is None,
    "and NO confidence figure is invented for it -- the field is null, not a plausible number",
)
check(
    result["kind"] == "counter" and result["unit"] == "per second",
    "the counter was analysed as a rate, not as an odometer reading",
)


# ===========================================================================
head("6. TREND -- direction, the lookback table, and the timestamp trap")

connection = fresh()
for index in range(120):
    # A clean ramp: 10 -> 70 over twenty minutes.
    plant(connection, NOW - 1200 + index * 10, {"cpu": 10 + index * 0.5})
movement = anomaly.trend("cpu", connection, config=CONFIG, now=NOW)
check(movement["direction"] == "rising", f"a rising ramp reads as {movement['direction']}")
check(
    movement["points"]["300s"] is not None
    and movement["points"]["300s"] < movement["points"]["60s"],
    "the lookback table is ordered in time: 300s ago is lower than 60s ago",
    f"{ {k: round(v, 1) for k, v in movement['points'].items() if v is not None} }",
)

connection = fresh()
for index in range(120):
    plant(connection, NOW - 1200 + index * 10, {"cpu": 70 - index * 0.5})
check(
    anomaly.trend("cpu", connection, config=CONFIG, now=NOW)["direction"] == "falling",
    "a falling ramp reads as falling",
)

connection = fresh()
for index in range(120):
    plant(connection, NOW - 1200 + index * 10, {"cpu": 40 + wobble(index, 0.2)})
check(
    anomaly.trend("cpu", connection, config=CONFIG, now=NOW)["direction"] == "steady",
    "noise around a level reads as steady, not as a trend",
)

# THE TIMESTAMP TRAP. The slope formula squares (t - t_mean). Unix timestamps
# are ~1.8x10^9; squared they are 3.3x10^18, past 2^53 where a float stops being
# exact. guardian_anomaly shifts time to start at zero first. This proves the
# shift is doing something: the same maths on raw timestamps loses the answer.
points = [(NOW + index * 10, 20.0 + index * 20.0) for index in range(50)]
shifted = anomaly._slope_per_minute(points)


def unshifted_slope(pairs):
    """The same least-squares slope WITHOUT shifting time to zero."""
    times = [float(t) for t, _ in pairs]
    values = [v for _, v in pairs]
    t_mean = sum(times) / len(times)
    v_mean = sum(values) / len(values)
    # The expanded form, which is what makes it fragile: sum(t*v) and sum(t*t)
    # are both astronomically large before anything is subtracted.
    numerator = sum(t * v for t, v in zip(times, values)) - len(times) * t_mean * v_mean
    denominator = sum(t * t for t in times) - len(times) * t_mean * t_mean
    return (numerator / denominator) * 60.0 if denominator else None


naive = unshifted_slope(points)
check(
    abs(shifted - 120.0) < 1e-9,
    f"slope of a +20-per-10s ramp is {shifted:.9f} per minute (exactly 120)",
    "time is shifted to start at zero before it is squared",
)
check(
    naive is None or abs(naive - 120.0) > 1e-6,
    f"the same maths on raw unix timestamps gives {naive}",
    "which is why the shift is not decoration",
)


# ===========================================================================
head("7. SCANNING -- order, survival, and counting")

connection = fresh()
for index in range(80):
    plant(
        connection,
        NOW - 1300 + index * 10,
        {"calm": 50 + wobble(index), "spiky": 20 + wobble(index), "flat": 7.0},
    )
for index in range(12):
    plant(
        connection,
        NOW - 115 + index * 10,
        {"calm": 50 + wobble(index), "spiky": 88 + wobble(index), "flat": 7.0},
    )
# A metric with almost no history at all, to prove one LEARNING result does not
# push a real finding down the page.
plant(connection, NOW - 20, {"newborn": 1.0})

anomaly.settings = lambda: dict(CONFIG)
report = anomaly.scan(connection=connection, now=NOW)

check(report["checked"] == 4, f"{report['checked']} metrics scanned")
verdicts = {f["metric"]: f["verdict"] for f in report["findings"]}
check(
    verdicts.get("spiky") in (anomaly.WARNING, anomaly.CRITICAL),
    f"the metric that moved is flagged: spiky -> {verdicts.get('spiky')}",
)
check(verdicts.get("calm") == anomaly.NORMAL, "the metric that did not move is NORMAL")
check(verdicts.get("flat") == anomaly.NORMAL, "a perfectly constant metric is NORMAL")
check(
    verdicts.get("newborn") == anomaly.LEARNING,
    "the metric with no history is LEARNING",
)
check(
    report["findings"][0]["metric"] == "spiky",
    f"worst first: the list opens with {report['findings'][0]['metric']}",
    " -> ".join(f["metric"] for f in report["findings"]),
)
check(
    report["findings"][-1]["verdict"] == anomaly.LEARNING,
    "and LEARNING sorts last -- a state of the detector, not of the machine",
)
check(
    len(report["anomalies"]) == 1 and report["summary"]["NORMAL"] == 2,
    f"summary: {report['summary']}",
)

try:
    anomaly.analyse("does_not_exist", connection=connection, now=NOW, config=CONFIG)
    check(False, "an unknown metric was accepted")
except anomaly.AnomalyError as error:
    check(True, "an unknown metric is refused, not guessed at", f"refused: {error}")


# ===========================================================================
head("8. EVIDENCE IS SEPARATE FROM THE CONCLUSION  (brief section 14)")

connection = fresh()
for index in range(80):
    plant(connection, NOW - 1300 + index * 10, {"cpu": 20 + wobble(index)})
for index in range(12):
    plant(connection, NOW - 115 + index * 10, {"cpu": 86 + wobble(index)})
result = anomaly.analyse("cpu", connection=connection, now=NOW, config=CONFIG)

check(
    "evidence" in result and len(result["evidence"]) >= 4,
    f"{len(result['evidence'])} lines of evidence accompany the verdict",
)
for line in result["evidence"]:
    print(f"        - {line}")
check(
    result["thresholds"]["z_warning"] == CONFIG["z_warning"],
    "the thresholds that produced the verdict travel with it, so it can be re-checked",
)
check(
    result["verdict"] in (anomaly.WARNING, anomaly.CRITICAL) and result["reason"],
    "the inference is in 'verdict' and 'reason', never mixed into 'evidence'",
)


# ===========================================================================
head("9. THE COMMAND LINE HONOURS THE PROJECT'S JSON CONTRACT")

environment = dict(os.environ)
environment["GUARDIAN_DB"] = str(TEST_DB)


def cli(*arguments):
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "guardian_anomaly.py"), *arguments],
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
        check=False,
    )
    try:
        return completed.returncode, json.loads(completed.stdout)
    except json.JSONDecodeError:
        return completed.returncode, None


code, payload = cli("scan")
check(
    payload is not None and payload.get("status") == "ok",
    f"`scan` prints one JSON object, exit {code}",
    f"checked {payload.get('checked')} metrics" if payload else "no JSON",
)

code, payload = cli("check", "cpu")
check(
    payload is not None and payload.get("status") == "ok" and "evidence" in payload,
    "`check <metric>` returns a full analysis",
)

code, payload = cli("check", "no_such_metric")
check(
    code != 0 and payload is not None and payload.get("status") == "error",
    "an unknown metric exits non-zero with a JSON error",
    payload.get("message") if payload else "no JSON",
)

code, payload = cli("nonsense")
check(
    code != 0 and payload is not None and payload.get("status") == "error",
    f"an unknown subcommand exits {code} and still prints valid JSON",
)

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
