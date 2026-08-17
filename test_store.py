#!/usr/bin/env python3
"""
Linux Guardian -- test_store.py                            (Phase 7, step 2)

PROOF THAT THE HISTORY STORE REFUSES BAD DATA, COMPUTES THE RIGHT NUMBERS,
AND CANNOT FILL THE DISK.

Run it live:   python3 test_store.py

Same shape as test_actions.py and for the same reason: it prints a readable
table rather than a dot per test, because the point is to SHOW a professor the
hostile input and the exact sentence the store answers with. It exits 0 only if
every expectation held, so it doubles as a regression check.

IT NEVER TOUCHES THE REAL DATABASE. A test suite that pruned the machine's
actual history to prove that pruning works would be a strange kind of proof.
Two mechanisms keep it away, because the tests run in two different places:

  in this process   guardian_store.database_file is replaced with a lambda
                    returning a file in a fresh temporary directory;
  in a subprocess   the CLI tests set $GUARDIAN_DB, since a lambda cannot cross
                    a process boundary. The first version of this file assumed
                    it could, and quietly created the real data/guardian.db.

Both are cleaned up when the run ends, whether it passed or failed.
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


def check(ok, description, detail=""):
    print(f"  {record(ok)}  {description}")
    if detail:
        print(f"        {detail}")


# ---------------------------------------------------------------------------
# A private database for the duration of the run.
#
# database_file() is REPLACED rather than the config being edited, because
# editing config/guardian.conf from a test would leave the project changed if
# the run was interrupted -- and the one thing a safety test must not do is
# create the mess it is checking for.
# ---------------------------------------------------------------------------
temporary = tempfile.TemporaryDirectory(prefix="guardian-store-test-")
TEST_DB = Path(temporary.name) / "test.db"
store.database_file = lambda: TEST_DB


def sample(timestamp, cpu_idle=1000, rx=5_000_000, memory=30.0):
    """One synthetic metrics.sh document, in the exact shape the real one emits."""
    return {
        "module": "metrics",
        "status": "ok",
        "timestamp": timestamp,
        "timestamp_human": "synthetic",
        "sample_duration_ms": 50.0,
        "source": {
            "interface": "eth0",
            "disk_device": "sda1",
            "disk_mount": "/",
            "cpu_cores": 4,
            "clock_ticks_per_second": 100,
            "sector_bytes": 512,
        },
        "gauges": {"memory_used_percent": memory, "load_1min": 0.5},
        "counters": {"cpu_idle_ticks": cpu_idle, "net_rx_bytes": rx},
    }


# ===========================================================================
head("1. SCHEMA -- created on first use, and self-describing")

connection = store.connect()
version = store.schema_version(connection)
check(version == store.SCHEMA_VERSION, f"schema version recorded as {version}")

tables = {
    row["name"]
    for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
}
check(
    {"schema_meta", "sample_runs", "samples"} <= tables,
    "all three tables present",
    ", ".join(sorted(tables)),
)

journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
check(journal == "wal", f"journal_mode is {journal} -- readers never block on the writer")

auto_vacuum = connection.execute("PRAGMA auto_vacuum").fetchone()[0]
check(auto_vacuum == 2, f"auto_vacuum is {auto_vacuum} (2 = INCREMENTAL) -- prune can shrink the file")

foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
check(foreign_keys == 1, "foreign_keys enforcement is ON")


# ===========================================================================
head("2. HOSTILE AND MALFORMED PAYLOADS -- every one MUST be refused")

now = int(time.time())

hostile = [
    ("not a JSON object", "a string instead of a document"),
    ({"module": "system", "status": "ok", "timestamp": now,
      "gauges": {"a": 1}, "counters": {}}, "a different module's output"),
    ({"module": "metrics", "status": "error", "message": "failed at line 12"},
     "an error document handed over as data"),
    ({"module": "metrics", "status": "ok", "timestamp": now,
      "gauges": {"cpu; DROP TABLE samples": 1}, "counters": {}},
     "SQL in a metric name"),
    ({"module": "metrics", "status": "ok", "timestamp": now,
      "gauges": {"cpu_ok; DROP TABLE samples": 1}, "counters": {}},
     "SQL after a valid prefix (the unanchored-regex trap)"),
    ({"module": "metrics", "status": "ok", "timestamp": now,
      "gauges": {"../../etc/passwd": 1}, "counters": {}}, "path traversal as a metric name"),
    ({"module": "metrics", "status": "ok", "timestamp": now,
      "gauges": {"CPU_PERCENT": 1}, "counters": {}}, "uppercase -- not the allowed shape"),
    ({"module": "metrics", "status": "ok", "timestamp": now,
      "gauges": {"x" * 80: 1}, "counters": {}}, "80-character metric name"),
    ({"module": "metrics", "status": "ok", "timestamp": now,
      "gauges": {"cpu": "97"}, "counters": {}}, "a number sent as a string"),
    ({"module": "metrics", "status": "ok", "timestamp": now,
      "gauges": {"cpu": True}, "counters": {}}, "a boolean (bool is a subclass of int)"),
    ({"module": "metrics", "status": "ok", "timestamp": now,
      "gauges": {"cpu": float("nan")}, "counters": {}}, "nan -- would poison every average"),
    ({"module": "metrics", "status": "ok", "timestamp": now,
      "gauges": {"cpu": float("inf")}, "counters": {}}, "infinity"),
    ({"module": "metrics", "status": "ok", "timestamp": 100,
      "gauges": {"cpu": 1}, "counters": {}}, "timestamp in 1970 -- a wrong clock"),
    ({"module": "metrics", "status": "ok", "timestamp": now + 86400,
      "gauges": {"cpu": 1}, "counters": {}}, "timestamp a day in the future"),
    ({"module": "metrics", "status": "ok", "timestamp": now,
      "gauges": {}, "counters": {}}, "no measurements at all"),
    ({"module": "metrics", "status": "ok", "timestamp": now,
      "gauges": {"cpu": 1}, "counters": {"cpu": 1}}, "same name as both gauge and counter"),
]

for payload, description in hostile:
    try:
        store.store_sample(payload, connection=connection)
        check(False, description, "ACCEPTED -- this is a hole")
    except store.StoreError as error:
        check(True, description, f"refused: {error}")

rows_after = connection.execute("SELECT COUNT(*) AS n FROM samples").fetchone()["n"]
check(rows_after == 0, f"nothing was written by any of them ({rows_after} rows)")


# ===========================================================================
head("3. A GOOD SAMPLE IS STORED, AND STORED ATOMICALLY")

result = store.store_sample(sample(now), connection=connection)
check(result["stored"] == 4, f"4 measurements written for tick {result['timestamp']}")

kinds = dict(
    connection.execute("SELECT metric, kind FROM samples").fetchall()
)
check(
    kinds.get("memory_used_percent") == "gauge" and kinds.get("net_rx_bytes") == "counter",
    "gauge/counter classification survived the round trip",
    f"{kinds}",
)

# A counter arrives as an int and must come back as an int: NUMERIC affinity,
# not REAL. If this fails, large counters are silently losing their last digits.
stored_counter = connection.execute(
    "SELECT value FROM samples WHERE metric = 'net_rx_bytes'"
).fetchone()["value"]
check(
    isinstance(stored_counter, int),
    f"counter came back as {type(stored_counter).__name__}, not float",
    "NUMERIC affinity keeps integers exact near 2^53",
)

# A partial write must be impossible: the bad metric is the last one in the
# document, so a store that wrote as it went would leave the first two behind.
before = connection.execute("SELECT COUNT(*) AS n FROM samples").fetchone()["n"]
broken = sample(now + 1)
broken["gauges"]["Not A Metric"] = 1
try:
    store.store_sample(broken, connection=connection)
    check(False, "a document with one bad metric was accepted")
except store.StoreError:
    after = connection.execute("SELECT COUNT(*) AS n FROM samples").fetchone()["n"]
    check(before == after, f"one bad metric rolled the whole tick back ({before} rows, unchanged)")

# A missing sensor is null, and null is not zero.
with_null = sample(now + 2)
with_null["counters"]["net_rx_bytes"] = None
store.store_sample(with_null, connection=connection)
null_value = connection.execute(
    "SELECT value FROM samples WHERE metric='net_rx_bytes' AND ts=?", (now + 2,)
).fetchone()["value"]
check(null_value is None, "a missing sensor is stored as NULL, not 0")


# ===========================================================================
head("4. THE STATISTICS ARE ACTUALLY CORRECT")

connection.execute("DELETE FROM samples")
connection.execute("DELETE FROM sample_runs")
connection.commit()

# A known series: 10, 20, 30, 40, 50.  mean = 30.
# Sample standard deviation (divisor n-1) = sqrt(1000/4) = 15.811388...
known = [10.0, 20.0, 30.0, 40.0, 50.0]
for offset, value in enumerate(known):
    store.store_sample(sample(now - 100 + offset, memory=value), connection=connection)

stat = store.aggregate("memory_used_percent", seconds=3600, connection=connection)
expected_stddev = math.sqrt(1000 / 4)
check(stat["samples"] == 5, "5 samples in the window")
check(stat["mean"] == 30.0, f"mean is {stat['mean']} (expected 30.0)")
check(stat["minimum"] == 10.0 and stat["maximum"] == 50.0, "min 10.0, max 50.0")
check(
    abs(stat["stddev"] - expected_stddev) < 1e-9,
    f"stddev is {stat['stddev']:.9f} (expected {expected_stddev:.9f})",
    "sample standard deviation, divisor n-1, via Welford",
)

# ---------------------------------------------------------------------------
# WHY WELFORD AND NOT THE TEXTBOOK FORMULA -- demonstrated, not asserted.
#
# The comparison below is like for like: BOTH sides compute the POPULATION
# variance (divisor n), so any difference between them is arithmetic error and
# nothing else. The magnitude is 10^9 because that is the size counters in this
# project actually reach -- net_rx_bytes passes 10^9 after a gigabyte of
# traffic, which on a demo VM is an afternoon.
#
# The five values differ from each other by tens, so the true variance is 200.
# sum(x^2) reaches 5x10^18, past 2^53 where a float stops being exact, and the
# formula then subtracts two nearly equal huge numbers -- so what survives is
# mostly rounding error. At 10^10 it returns 0.0: no spread at all.
# ---------------------------------------------------------------------------
big = [1e9 + v for v in (10, 20, 30, 40, 50)]
naive_mean = sum(big) / len(big)
naive_population_variance = sum(x * x for x in big) / len(big) - naive_mean * naive_mean
true_population_variance = sum((x - naive_mean) ** 2 for x in big) / len(big)

connection.execute("DELETE FROM samples")
connection.execute("DELETE FROM sample_runs")
connection.commit()
for offset, value in enumerate(big):
    store.store_sample(sample(now - 50 + offset, memory=value), connection=connection)
big_stat = store.aggregate("memory_used_percent", seconds=3600, connection=connection)

# What the store returns is the SAMPLE standard deviation (divisor n-1), so the
# expectation is converted to match before comparing.
expected_big = math.sqrt(true_population_variance * len(big) / (len(big) - 1))
check(
    abs(big_stat["stddev"] - expected_big) / expected_big < 1e-9,
    f"stddev stays exact on 10^9-sized values: {big_stat['stddev']:.9f} "
    f"(expected {expected_big:.9f})",
    f"same five values, population variance: textbook formula "
    f"{naive_population_variance:.1f} vs true {true_population_variance:.1f} "
    f"-- {abs(naive_population_variance - true_population_variance) / true_population_variance * 100:.0f}% wrong",
)
check(
    abs(naive_population_variance - true_population_variance) / true_population_variance > 0.1,
    "the textbook formula really is wrong here -- this is not a straw man",
)

connection.execute("DELETE FROM samples")
connection.execute("DELETE FROM sample_runs")
connection.commit()
for offset, value in enumerate(known):
    store.store_sample(sample(now - 100 + offset, memory=value), connection=connection)

# A window with no data is not an error and does not invent a mean.
empty = store.aggregate("memory_used_percent", seconds=1, connection=connection)
check(
    empty["samples"] == 0 and empty["mean"] is None,
    "an empty window reports 0 samples and mean None, not 0.0",
)


# ===========================================================================
head("5. GAUGE vs COUNTER IS ENFORCED, NOT DECORATIVE")

try:
    store.aggregate("net_rx_bytes", seconds=3600, connection=connection)
    check(False, "averaging a counter was allowed")
except store.StoreError as error:
    check(True, "averaging a counter is refused", f"refused: {error}")

try:
    store.rate("memory_used_percent", seconds=3600, connection=connection)
    check(False, "rate() on a gauge was allowed")
except store.StoreError as error:
    check(True, "rate() on a gauge is refused", f"refused: {error}")

try:
    store.aggregate("no_such_metric", connection=connection)
    check(False, "an unknown metric was accepted")
except store.StoreError as error:
    check(True, "an unknown metric is refused, not defaulted", f"refused: {error}")


# ===========================================================================
head("6. RATES, AND WHAT HAPPENS WHEN THE MACHINE REBOOTS")

connection.execute("DELETE FROM samples")
connection.execute("DELETE FROM sample_runs")
connection.commit()

# 1,000,000 bytes gained over 10 seconds  ->  exactly 100000 bytes/second.
store.store_sample(sample(now - 10, rx=5_000_000), connection=connection)
store.store_sample(sample(now, rx=6_000_000), connection=connection)
throughput = store.rate("net_rx_bytes", seconds=3600, connection=connection)
check(
    throughput["per_second"] == 100000.0,
    f"1 MB over 10 s = {throughput['per_second']} bytes/second",
    f"delta {throughput['delta']} over {throughput['elapsed_seconds']} s",
)

# Now the counter goes backwards, which is what a reboot looks like.
store.store_sample(sample(now + 1, rx=400), connection=connection)
after_reboot = store.rate("net_rx_bytes", seconds=3600, connection=connection)
check(
    after_reboot["counter_reset"] is True and after_reboot["per_second"] is None,
    "a counter going backwards is reported as a reset, not as a negative rate",
    f"{after_reboot['samples']} samples, per_second={after_reboot['per_second']}",
)

# One reading is not a rate.
connection.execute("DELETE FROM samples")
connection.execute("DELETE FROM sample_runs")
connection.commit()
store.store_sample(sample(now, rx=1234), connection=connection)
single = store.rate("net_rx_bytes", seconds=3600, connection=connection)
check(single["per_second"] is None, "a single odometer reading yields no rate")


# ===========================================================================
head("7. RETENTION -- the store cannot fill the disk")

connection.execute("DELETE FROM samples")
connection.execute("DELETE FROM sample_runs")
connection.commit()

# 200 ticks, one every 30 s, reaching back well past any retention setting.
for index in range(200):
    store.store_sample(sample(now - 30 * (200 - index)), connection=connection)
planted = connection.execute("SELECT COUNT(*) AS n FROM samples").fetchone()["n"]
check(planted == 800, f"{planted} rows planted across 200 ticks")

# --- guard 1: by age --------------------------------------------------------
store.retention_seconds = lambda: 600          # keep ten minutes
store.max_rows = lambda: 1_000_000             # row cap out of the way
pruned = store.prune(connection=connection)
remaining = connection.execute("SELECT COUNT(*) AS n FROM samples").fetchone()["n"]
oldest = connection.execute("SELECT MIN(ts) AS t FROM samples").fetchone()["t"]
check(
    pruned["deleted_by_age"] > 0 and oldest >= pruned["cutoff"],
    f"age guard deleted {pruned['deleted_by_age']} rows; oldest survivor is at the cut-off",
    f"{remaining} rows remain",
)

orphans = connection.execute(
    "SELECT COUNT(*) AS n FROM samples WHERE ts NOT IN (SELECT ts FROM sample_runs)"
).fetchone()["n"]
check(orphans == 0, "no sample was left pointing at a deleted tick")

# --- guard 2: by row count, with a clock that has gone wrong ----------------
connection.execute("DELETE FROM samples")
connection.execute("DELETE FROM sample_runs")
connection.commit()
for index in range(100):
    store.store_sample(sample(now - 30 * (100 - index)), connection=connection)

# A retention of a thousand years: guard 1 is now incapable of deleting
# anything, which is exactly what a VM resuming with a 1970 clock does to it.
store.retention_seconds = lambda: 1000 * 365 * 86400
store.max_rows = lambda: 200
capped = store.prune(connection=connection)
left = connection.execute("SELECT COUNT(*) AS n FROM samples").fetchone()["n"]
check(
    capped["deleted_by_age"] == 0,
    "with an absurd retention the age guard deletes nothing -- as designed",
)
check(
    capped["deleted_by_row_cap"] > 0 and left <= 200 + 4,
    f"the row cap still cut the table to {left} rows (cap 200)",
    "the second guard does not consult the clock, so a wrong clock cannot disable it",
)

partial = connection.execute(
    """
    SELECT COUNT(*) AS n FROM (
        SELECT ts, COUNT(*) AS c FROM samples GROUP BY ts HAVING c <> 4
    )
    """
).fetchone()["n"]
check(partial == 0, "every surviving tick is whole -- no half-deleted moment in history")

store.retention_seconds = lambda: 168 * 3600
store.max_rows = lambda: 1_000_000


# ===========================================================================
head("7b. PRUNING RETURNS DISK, NOT JUST ROWS")

# THE TEST THAT MATTERS MOST IN THIS FILE, because the first version of prune()
# passed every check above while reclaiming nothing: the rows really were gone,
# the row counts really did drop, and the file on disk did not shrink by a
# single byte. A retention test that only counts rows proves the store tidy, not
# small -- and it is the size on disk that the DISK_CRITICAL alarm reacts to.
connection = store.connect()
connection.execute("DELETE FROM samples")
connection.execute("DELETE FROM sample_runs")
connection.commit()

# Enough rows that a page-level difference is unmistakable: 4000 ticks, half of
# them older than the retention window.
bulk_metrics = {f"gauge_{n}": float(n) for n in range(20)}
for index in range(4000):
    timestamp = (now - 1_000_000 + index) if index < 2000 else (now - 5000 + index)
    store.store_sample(
        {
            "module": "metrics",
            "status": "ok",
            "timestamp": timestamp,
            "sample_duration_ms": 50.0,
            "source": {"interface": "eth0", "cpu_cores": 4},
            "gauges": dict(bulk_metrics),
            "counters": {"counter_a": index * 1000},
        },
        connection=connection,
    )
connection.close()

pruned = store.prune()
shrank = pruned["bytes_before"] - pruned["bytes_after"]
check(
    pruned["deleted_by_age"] > 0,
    f"{pruned['deleted_by_age']:,} rows deleted by age",
)
check(
    shrank > 0,
    f"the database shrank by {shrank / 1024 / 1024:.2f} MB "
    f"({pruned['bytes_before'] / 1024 / 1024:.2f} -> {pruned['bytes_after'] / 1024 / 1024:.2f} MB)",
    "PRAGMA incremental_vacuum drained with fetchall(), then a WAL checkpoint",
)

on_disk = TEST_DB.stat().st_size
check(
    on_disk <= pruned["bytes_after"] * 1.1,
    f"the real file on disk is {on_disk / 1024 / 1024:.2f} MB -- it matches the page count",
    "proof the pages went back to the filesystem and not just to SQLite's free list",
)


# ===========================================================================
head("8. THE REAL SAMPLER, END TO END")

connection.close()

# The genuine linux/metrics.sh, its genuine output, through the genuine
# validator, into the throwaway database. This is the test that would catch a
# field being renamed in the shell script.
live = store.run_metrics()
stored = store.store_sample(live)
check(stored["stored"] >= 25, f"{stored['stored']} live measurements stored")

known_metrics = {row["metric"]: row["kind"] for row in store.metrics_known()}
expected = set(live["gauges"]) | set(live["counters"])
check(
    expected <= set(known_metrics),
    f"every metric metrics.sh emitted is queryable ({len(expected)} names)",
)

gauge_names = set(live["gauges"])
counter_names = set(live["counters"])
misfiled = [
    name
    for name, kind in known_metrics.items()
    if (kind == "gauge") != (name in gauge_names) and name in gauge_names | counter_names
]
check(not misfiled, "no metric was filed under the wrong kind", f"{misfiled}" if misfiled else "")

description = store.stats()
check(
    description["samples"] > 0 and description["bytes"] > 0,
    f"stats(): {description['ticks']} ticks, {description['samples']} samples, "
    f"{description['bytes']} bytes",
)


# ===========================================================================
head("9. THE COMMAND LINE HONOURS THE PROJECT'S JSON CONTRACT")

# The CLI is run as a REAL SUBPROCESS, because that is how the collection timer
# will run it -- and a CLI tested by calling main() in-process is not a CLI that
# has been tested.
#
# A lambda cannot cross a process boundary, so the monkey-patched
# database_file() above has no effect on the child. $GUARDIAN_DB is what points
# it at the throwaway file instead; see the docstring of database_file() for why
# that override exists and why it is the only one in the project.
environment = dict(os.environ)
environment["GUARDIAN_DB"] = str(Path(temporary.name) / "cli.db")


def cli(*arguments):
    """Run guardian_store.py as a subprocess and return (exit code, parsed JSON)."""
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "guardian_store.py"), *arguments],
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


code, payload = cli("stats")
check(
    payload is not None and payload.get("status") == "ok",
    f"`stats` prints one JSON object, exit {code}",
)

code, payload = cli("nonsense")
check(
    code != 0 and payload is not None and payload.get("status") == "error",
    f"an unknown subcommand exits {code} and still prints valid JSON",
    payload.get("message") if payload else "no JSON at all",
)

code, payload = cli("aggregate", "no_such_metric")
check(
    code != 0 and payload is not None and payload.get("status") == "error",
    "an unknown metric exits non-zero with a JSON error",
    payload.get("message") if payload else "no JSON at all",
)

code, payload = cli("series", "load_1min", "not-a-number")
check(
    code != 0 and payload is not None and payload.get("status") == "error",
    "a non-numeric window is refused",
    payload.get("message") if payload else "no JSON at all",
)


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
