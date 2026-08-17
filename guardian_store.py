#!/usr/bin/env python3
"""
Linux Guardian -- guardian_store.py                        (Phase 7, step 2)

THE PROJECT'S MEMORY.

Phases 1 to 6 were amnesiac. Every module measured, judged, displayed and then
threw the reading away, which is why nothing so far can answer the only
question that matters for anomaly detection:

    Is 86% CPU unusual ON THIS MACHINE?

A threshold cannot answer that. A threshold says "86 is above 70", which is
equally true on a build server that idles at 80 and on a laptop that idles at 3.
Answering it needs a record of what this machine normally does, and that record
is what this file keeps.

    linux/metrics.sh  ->  one JSON sample  ->  THIS FILE  ->  data/guardian.db
                                                    |
                                                    v
                                       series() / aggregate() / rate()
                                                    |
                                                    v
                                       Phase 7 step 3: is it abnormal?

WHERE THE LINE IS DRAWN -- and it is the same line as Phase 1 vs Phase 2.
    Phase 1 MEASURES, Phase 2 JUDGES.
    This file STORES AND COMPUTES. It works out counts, averages, minima,
    maxima, standard deviations and rates -- arithmetic with a right answer.
    It never decides that a number is bad. "Bad" is an opinion, opinions need
    thresholds, and thresholds live in guardian.conf and are applied by the
    detector, exactly as diagnosis.sh applies them today.

THE SAFETY RULES THIS LAYER ENFORCES FOR ITSELF
-----------------------------------------------
The project's principle is that every layer re-checks its own inputs rather
than trusting the layer above. For a database layer that means three things:

  1. NO SQL IS EVER BUILT BY STRING CONCATENATION. Every value reaches SQLite
     through a "?" placeholder. There is no function in this file that accepts
     SQL from a caller, so there is nowhere for an injected query to enter.
  2. A metric NAME is checked against an anchored character allow-list before
     it is used, even though it arrives as a bound parameter and could not
     inject anything anyway. Same reasoning as the sandbox filename check in
     guardian_actions.py: the allow-list is what stops a typo or a hostile
     model quietly creating a second, parallel history under a junk name.
  3. THE PAYLOAD FROM metrics.sh IS NOT TRUSTED. It is a JSON document produced
     by a script that could be edited, replaced, or run against a different
     kernel. Its module name, status, timestamp and every single value are
     re-validated here before a row is written.
"""

import json
import math
import os
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# WHERE THINGS ARE
#
# config_path() and read_config() are IMPORTED, not re-implemented. guardian.conf
# is already parsed in exactly one place and guardian_nlp.py and
# guardian_ollama.py both import it from here, so following the same route keeps
# one parser in the project instead of adding a third.
#
# HONEST NOTE ON THE COUPLING: importing guardian_actions also loads
# actions.json, which this file has no use for. That is a real, if small, price
# -- a broken registry would stop the history store importing. It is accepted
# because the alternative, a fourth copy of the config reader, breaks rule 3 of
# CLAUDE.md ("nothing is hard-coded that belongs in the config") in a way that
# rots silently: two parsers that disagree are far worse than one import.
# ---------------------------------------------------------------------------
from guardian_config import config_path, read_config

PROJECT_ROOT = Path(__file__).resolve().parent
LINUX_DIR = PROJECT_ROOT / "linux"
METRICS_SCRIPT = LINUX_DIR / "metrics.sh"

# VERSION 1 was metrics only. VERSION 2 adds the incident tables (Phase 8).
#
# THE UPGRADE FROM 1 TO 2 NEEDS NO MIGRATION CODE, and that is not luck: every
# statement in _SCHEMA is CREATE ... IF NOT EXISTS, so running the version 2
# schema against a version 1 file simply adds the two tables that are missing
# and leaves the three that exist untouched. The recorded version is then
# updated to match. A future change that ALTERS an existing table would not be
# so lucky, and that is exactly why the number is written down: the day a real
# migration is needed, the file can say which one it needs.
SCHEMA_VERSION = 2

# metrics.sh returns in about 50 ms. Ten seconds is not a guess about how long
# it takes; it is the point at which we conclude it is never coming back --
# because a sampler that hangs must not be able to hang the daemon that calls it.
METRICS_TIMEOUT_SECONDS = 10

# How long to wait for another process to release the database before giving up.
# The daemon writes every 30 s while Flask reads on every page load, so the two
# WILL meet. SQLite handles that by making the second one wait; without a
# timeout it would instead raise "database is locked" immediately.
BUSY_TIMEOUT_SECONDS = 5.0

# ---------------------------------------------------------------------------
# The character allow-list for a metric name.
#
#   ^                anchored at the start
#   [a-z]            must begin with a lowercase letter
#   [a-z0-9_]{0,63}  then up to 63 more of lowercase, digits, underscore
#   $                anchored at the end
#
# BOTH ANCHORS MATTER. re.match() alone only anchors the start, so without the
# trailing $ the name "cpu_ticks; DROP TABLE samples" would MATCH on its first
# eight characters. That is the single most common way a validating regex turns
# out not to validate anything, and it is why every pattern in this project is
# written with both anchors.
# ---------------------------------------------------------------------------
_SAFE_METRIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

# The two kinds of number this project stores, and the reason the distinction is
# in the schema instead of in a comment. See the header of linux/metrics.sh: a
# gauge is true on its own and may be averaged; a counter only goes up since
# boot and is meaningless until two readings are subtracted. Recording which is
# which lets aggregate() REFUSE to average a counter, so the mistake is caught
# by the database layer rather than showing up as a nonsensical graph.
KIND_GAUGE = "gauge"
KIND_COUNTER = "counter"
_KINDS = (KIND_GAUGE, KIND_COUNTER)

# Sanity window for a timestamp. Anything outside it is a clock, not a reading.
# The floor is 2020-01-01: this project cannot have produced a sample before it
# existed, so an "older" one means the VM resumed with its clock reset -- a
# thing VMware really does. The ceiling allows five minutes of drift.
_EPOCH_FLOOR = 1577836800
_FUTURE_TOLERANCE_SECONDS = 300


class StoreError(Exception):
    """A refusal by this layer: bad payload, bad metric name, unusable database.

    A distinct exception type, for the same reason guardian_actions.py has
    SandboxError: callers can catch OUR refusal and report it as a clean error
    card, while a genuine sqlite3 or OS failure keeps its own identity instead
    of being flattened into one indistinguishable "something went wrong".
    """


# ===========================================================================
#  1. CONFIGURATION
# ===========================================================================
def database_file():
    """The one file this project's history lives in.

    $GUARDIAN_DB OVERRIDES THE CONFIG, and it is the only environment variable
    this project honours. It exists so that test_store.py can exercise the
    command line -- pruning, capping, refusing -- against a throwaway file in
    /tmp. Without it the only way to test the CLI would be to run it against the
    machine's real history, and a test that deletes real data to prove that
    deletion works is not a test anybody should trust.

    IS AN ENVIRONMENT OVERRIDE A HOLE? It names a database file, not a command,
    and anything able to set this process's environment can already run
    arbitrary code as this user -- so it grants nothing that was not already
    granted. It is also the standard Debian pattern (/etc/default/*), which is
    the convention this project follows elsewhere. What it must NOT become is a
    precedent: no threshold, no allow-list and no service name is readable from
    the environment, because those are policy and policy lives in guardian.conf.
    """
    override = os.environ.get("GUARDIAN_DB", "").strip()
    if override:
        return Path(override)
    return config_path("HISTORY_DB", str(PROJECT_ROOT / "data" / "guardian.db"))


def _config_int(key, default, minimum=1):
    """Read one integer setting, refusing values that would disable a guard.

    A retention of 0 hours, or a row cap of -1, would silently switch off the
    protection the setting exists to provide. A typo must not be able to do
    that quietly, so an unusable value falls back to the documented default.
    """
    raw = read_config().get(key, "")
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


def retention_seconds():
    """How long a sample is kept, in seconds."""
    return _config_int("HISTORY_RETENTION_HOURS", 168) * 3600


def max_rows():
    """The clock-independent backstop on table size."""
    return _config_int("HISTORY_MAX_ROWS", 1_000_000, minimum=1000)


def recent_seconds():
    """The default 'recent' window, in seconds."""
    return _config_int("HISTORY_RECENT_SECONDS", 300, minimum=10)


# ===========================================================================
#  2. THE CONNECTION AND THE SCHEMA
# ===========================================================================
class _StdDev:
    """A custom SQLite aggregate: the sample standard deviation.

    SQLite has no built-in stddev, so it is registered from Python with
    conn.create_aggregate(). SQLite calls step() once per row and finalize()
    once at the end, so the rows are consumed as they stream out of the table
    and never all exist in memory at once.

    WHY WELFORD'S ALGORITHM AND NOT THE TEXTBOOK FORMULA.
    The formula every statistics course teaches is

        variance = sum(x^2)/n - (sum(x)/n)^2

    and it is a genuinely bad idea for THIS data. net_rx_bytes on this VM is
    already about 10^7. Squaring it gives 10^14, and summing that over a week of
    samples reaches 10^18 -- past 2^53, the largest integer a 64-bit float
    represents exactly. The two large terms are then subtracted from each other
    and the small difference between them is mostly rounding error. It can even
    return a negative variance, whose square root is not a number at all.

    Welford's method never squares the raw value. It carries a running mean and
    a running sum of squared deviations FROM that mean, so every quantity it
    holds stays the size of the data rather than the square of it.

    The divisor is (n - 1), not n: these rows are a SAMPLE of the machine's
    behaviour taken every thirty seconds, not every state it passed through, and
    (n - 1) is the estimator that does not systematically under-report the
    spread of the population it was drawn from.
    """

    def __init__(self):
        self.count = 0
        self.mean = 0.0
        self.sum_squared_deviations = 0.0

    def step(self, value):
        # A missing reading (json null -> SQL NULL -> Python None) is skipped
        # rather than counted as zero, which would drag the mean towards 0 and
        # invent a spread that the machine never had.
        if value is None:
            return
        number = float(value)
        self.count += 1
        delta = number - self.mean
        self.mean += delta / self.count
        self.sum_squared_deviations += delta * (number - self.mean)

    def finalize(self):
        # One reading has no spread to speak of, and (n - 1) would be a division
        # by zero. None is the honest answer, and it travels back as SQL NULL.
        if self.count < 2:
            return None
        return math.sqrt(self.sum_squared_deviations / (self.count - 1))


def connect():
    """Open the database, creating and configuring it on first use.

    A FRESH CONNECTION PER OPERATION, NEVER A GLOBAL ONE. A module-level
    connection would be shared by every Flask request thread, and sqlite3
    objects are not safe to use from a thread other than the one that made them.
    Opening a SQLite file is a filesystem open, not a network handshake, so the
    cost of doing it per call is negligible and it removes an entire category of
    threading bug rather than managing it.
    """
    path = database_file()

    # parents=True creates data/ the first time. exist_ok=True means a second
    # run is not an error -- the directory already being there is success.
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(path), timeout=BUSY_TIMEOUT_SECONDS)

    # Rows come back as tuples by default, so code reads row[3] and breaks the
    # moment a column is added. sqlite3.Row allows row["value"] instead.
    connection.row_factory = sqlite3.Row
    connection.create_aggregate("stddev", 1, _StdDev)

    # THE ORDER OF THE NEXT THREE LINES IS LOAD-BEARING, and it cost a failing
    # test to find out. auto_vacuum is stored in the database HEADER, and the
    # header is written the first time anything touches the file. Setting
    # journal_mode = WAL touches it -- so if _configure() runs first, the header
    # is already committed with auto_vacuum = 0 (NONE) and the later PRAGMA is
    # silently ignored. Not an error, not a warning: the pragma simply has no
    # effect, and the only visible symptom would have been a database file that
    # never shrinks however much is pruned from it.
    #
    # Changing it afterwards is possible only by running a full VACUUM, which
    # rewrites the entire file under an exclusive lock. Getting the order right
    # here costs nothing; getting it wrong costs a rewrite of a 40 MB file.
    if _is_new_database(connection):
        connection.execute("PRAGMA auto_vacuum = INCREMENTAL")
    _configure(connection)
    _ensure_schema(connection)
    return connection


def _is_new_database(connection):
    """True when this file has no tables yet, so the header is still unwritten."""
    return not _table_exists(connection, "samples")


def _configure(connection):
    """The PRAGMAs, each of which fixes a specific real problem.

    journal_mode = WAL   Write-Ahead Logging. In SQLite's default rollback mode
                         a writer BLOCKS every reader for the duration of its
                         transaction. This project has a daemon writing every 30
                         seconds and a dashboard reading on every page load and
                         every 10-second refresh, so in the default mode the
                         page would intermittently stall behind the sampler.
                         Under WAL, readers see the last committed state and
                         never wait for the writer at all. WAL persists in the
                         file, so this is really only needed once, but setting
                         it every time makes the file self-repairing if it is
                         ever copied or recreated.

    synchronous = NORMAL A deliberate, stated trade. FULL makes SQLite wait for
                         the disk to confirm every commit; NORMAL lets the OS
                         schedule the write. Under WAL, NORMAL is still safe
                         against a crashing APPLICATION -- the database cannot
                         be corrupted -- and risks only the last few seconds of
                         commits if the power is cut. For a metrics history
                         sampled every 30 seconds, losing the newest sample to a
                         power cut costs nothing; making the sampler wait for
                         the disk 2,880 times a day costs real I/O. For the
                         audit trail in a later phase, the answer would be FULL,
                         and that is a different table's decision.

    foreign_keys = ON    SQLite ships with foreign key enforcement OFF for
                         backwards compatibility, PER CONNECTION. A declared
                         REFERENCES clause is therefore decoration until this
                         pragma is set -- one of the sharpest edges in SQLite,
                         and the reason it is set here rather than assumed.

    auto_vacuum          Set inside _ensure_schema, because it can only be
                         chosen before the first table exists. See there.
    """
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    connection.execute("PRAGMA foreign_keys = ON")


# The schema, as one statement per table so a failure names the table it was on.
#
# WHY ONE ROW PER METRIC INSTEAD OF ONE COLUMN PER METRIC.
# The obvious design is a wide table: ts, cpu, memory, disk, load, ... one column
# each. It is rejected because every new measurement would then be a schema
# change -- an ALTER TABLE, a migration, and an old database that no longer
# matches the code. With one row per metric, adding a field to metrics.sh needs
# no change here at all: the new name simply starts appearing. It also makes the
# statistics generic, so aggregate() works for any metric without being told the
# column names in advance, which is exactly what a baseline engine needs.
# The cost is rows -- about 30 per sample -- and rows are what SQLite is good at.
_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    # One row per SAMPLING TICK: the metadata that describes the whole reading
    # rather than any one number in it. Splitting it out means the interface
    # name and the sampler's cost are stored once per tick instead of being
    # repeated against all thirty metrics.
    #
    # ts IS THE PRIMARY KEY, so a second sample within the same second is a
    # collision. That is treated as a replacement, not an error: two readings
    # one second apart describe the same second, and the later one is the more
    # accurate. store_sample() therefore deletes and re-inserts inside one
    # transaction, which also keeps samples and sample_runs consistent.
    """
    CREATE TABLE IF NOT EXISTS sample_runs (
        ts                     INTEGER PRIMARY KEY,
        duration_ms            REAL,
        interface              TEXT,
        disk_device            TEXT,
        cpu_cores              INTEGER,
        clock_ticks_per_second INTEGER,
        stored_at              INTEGER NOT NULL
    )
    """,
    # One row per metric per tick.
    #
    # value IS DECLARED NUMERIC, NOT REAL. SQLite's NUMERIC affinity keeps an
    # integer as an integer when it can be stored losslessly, so a counter of
    # 9,900,122 comes back as the Python int 9900122 rather than 9900122.0.
    # REAL would convert everything to float on the way in, which for counters
    # near 2^53 would silently lose the last digits -- the exact digits a delta
    # between two consecutive samples depends on.
    #
    # NULL IS ALLOWED ON PURPOSE. metrics.sh emits null for a sensor it could
    # not read, and that must survive storage: a missing reading is a fact, and
    # writing 0 instead would look like a real measurement of zero.
    #
    # PRIMARY KEY (metric, ts) + WITHOUT ROWID: in a WITHOUT ROWID table the
    # primary key IS the physical order of the data, so the rows of one metric
    # sit next to each other on disk, in time order. That is precisely the shape
    # of every query this project makes -- "metric X over the last N seconds" --
    # so the hot path becomes one contiguous range read with no separate index
    # to maintain and no second copy of the key to store.
    """
    CREATE TABLE IF NOT EXISTS samples (
        metric TEXT    NOT NULL,
        ts     INTEGER NOT NULL,
        kind   TEXT    NOT NULL,
        value  NUMERIC,
        PRIMARY KEY (metric, ts),
        FOREIGN KEY (ts) REFERENCES sample_runs(ts)
    ) WITHOUT ROWID
    """,
    # The one secondary index, and it exists for retention rather than for
    # reading. Pruning asks "every sample older than T", which does not mention
    # a metric, so without this index it would scan the whole table -- and it
    # would do that every time the daemon ticked. With it, the prune is a range
    # scan over exactly the rows about to be deleted.
    """
    CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts)
    """,
    # -----------------------------------------------------------------------
    #  VERSION 2 -- INCIDENTS  (Phase 8)
    #
    # An incident is not an anomaly. An anomaly is one metric behaving oddly at
    # one instant; an incident is a THING THAT IS HAPPENING TO THIS MACHINE,
    # which usually shows up as several anomalies at once and persists across
    # many samples. Two consequences shape this table:
    #
    #   it has a LIFETIME       created_at, updated_at, resolved_at and a status
    #                           that moves through a fixed set of states, so the
    #                           same event is one row that evolves rather than a
    #                           new row every thirty seconds.
    #   it has a FINGERPRINT    the identity used to recognise "this is the same
    #                           thing that was happening a minute ago". Without
    #                           it, a CPU problem lasting an hour would produce
    #                           120 identical incidents and the list would be
    #                           useless exactly when it mattered most.
    #
    # THE JSON COLUMNS (evidence, symptoms, detail) ARE A DELIBERATE CHOICE, and
    # the deliberate limit on it is that NOTHING IS EVER QUERIED OUT OF THEM.
    # Every field the code filters, sorts or counts on -- status, severity,
    # component, fingerprint -- is a real column with a real type. The JSON holds
    # the supporting material a human reads once the row has already been found.
    # Storing queryable state in a JSON blob is how a schema quietly stops being
    # a schema; storing a snapshot of evidence in one is just a document.
    """
    CREATE TABLE IF NOT EXISTS incidents (
        id           TEXT    PRIMARY KEY,
        fingerprint  TEXT    NOT NULL,
        type         TEXT    NOT NULL,
        title        TEXT    NOT NULL,
        category     TEXT    NOT NULL,
        component    TEXT    NOT NULL,
        status       TEXT    NOT NULL,
        severity     TEXT    NOT NULL,
        risk_score   INTEGER,
        risk_level   TEXT,
        confidence   REAL,
        occurrences  INTEGER NOT NULL DEFAULT 1,
        created_at   INTEGER NOT NULL,
        updated_at   INTEGER NOT NULL,
        resolved_at  INTEGER,
        description  TEXT,
        symptoms     TEXT,
        evidence     TEXT,
        detail       TEXT
    )
    """,
    # The lookup that deduplication depends on: "is there an OPEN incident with
    # this fingerprint?" runs on every scan, so it gets its own index rather
    # than a scan of the whole table.
    """
    CREATE INDEX IF NOT EXISTS idx_incidents_open
        ON incidents(fingerprint, status)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_incidents_status
        ON incidents(status, created_at DESC)
    """,
    # THE TIMELINE -- section 27 of the brief, and the reason an incident can be
    # explained after the fact rather than merely reported.
    #
    # APPEND-ONLY BY CONVENTION AND BY INTENT: nothing in this project updates or
    # deletes a timeline row. The incident row holds the CURRENT state; this
    # table holds how it got there. That separation is what makes the question
    # "why did Guardian restart apache2?" answerable in six months.
    """
    CREATE TABLE IF NOT EXISTS incident_timeline (
        id          INTEGER PRIMARY KEY,
        incident_id TEXT    NOT NULL,
        ts          INTEGER NOT NULL,
        kind        TEXT    NOT NULL,
        status      TEXT,
        message     TEXT    NOT NULL,
        detail      TEXT,
        FOREIGN KEY (incident_id) REFERENCES incidents(id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_timeline_incident
        ON incident_timeline(incident_id, ts)
    """,
)


def _ensure_schema(connection):
    """Create the tables on first use and record the schema version.

    WHY auto_vacuum = INCREMENTAL IS SET AT ALL (in connect(), just above): a
    plain DELETE in SQLite frees pages for reuse INSIDE the file but never hands
    them back to the filesystem, so a naive "delete the old rows" store grows
    for ever and only looks pruned from the inside. With INCREMENTAL, prune()
    can return pages with PRAGMA incremental_vacuum, a few at a time, without
    the long exclusive lock a full VACUUM would take.
    """
    with connection:
        for statement in _SCHEMA:
            connection.execute(statement)

        # created_at uses INSERT OR IGNORE: it records when the FILE was made
        # and must never be rewritten by a later run.
        connection.execute(
            "INSERT OR IGNORE INTO schema_meta (key, value) VALUES (?, ?)",
            ("created_at", str(int(time.time()))),
        )

        # schema_version uses INSERT OR REPLACE, which is the opposite decision
        # and the one that makes the upgrade work. Every statement above is
        # CREATE ... IF NOT EXISTS, so a version 1 file has just been given the
        # version 2 tables; the recorded version must now say so, or the file
        # would claim to be version 1 for ever while holding a version 2 schema.
        # A version that lies about the file is worse than no version at all.
        connection.execute(
            "INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )


def _table_exists(connection, name):
    """Is this table already in the database?

    sqlite_master is SQLite's own catalogue of what the file contains. The name
    is bound as a parameter like any other value -- it is a lookup, not a piece
    of SQL being assembled.
    """
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone()
    return row is not None


def schema_version(connection):
    """The schema version recorded in the file, or 0 for a database with none."""
    row = connection.execute(
        "SELECT value FROM schema_meta WHERE key = ?", ("schema_version",)
    ).fetchone()
    return int(row["value"]) if row else 0


# ===========================================================================
#  3. VALIDATING WHAT metrics.sh SENT
# ===========================================================================
def _check_metric_name(name):
    """Refuse anything that is not a plain lowercase metric identifier."""
    if not isinstance(name, str) or not _SAFE_METRIC.match(name):
        raise StoreError(f"refused metric name: {name!r}")
    return name


def _check_value(name, value):
    """Refuse anything that is not a number or an explicit 'no reading'.

    THE isinstance(value, bool) TEST IS NOT REDUNDANT, and it is the one line in
    this function a reader should stop at. In Python, bool is a SUBCLASS of int:
    isinstance(True, int) is True, and True + 1 is 2. Without the explicit
    rejection, a JSON `true` would be stored as the number 1 and would then be
    averaged, differenced and plotted as though someone had measured it. Every
    value in this project's history is a measurement, and a flag is not one.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise StoreError(f"metric {name}: boolean is not a measurement")
    if not isinstance(value, (int, float)):
        raise StoreError(f"metric {name}: value is {type(value).__name__}, not a number")
    # inf and nan are floats as far as isinstance is concerned, survive a JSON
    # round trip through Python, and poison every average they touch -- one nan
    # makes the mean of a whole week nan. They cannot come from metrics.sh,
    # which is exactly why they are worth refusing: their presence would mean
    # the payload did not come from metrics.sh.
    if isinstance(value, float) and not math.isfinite(value):
        raise StoreError(f"metric {name}: value is not finite")
    return value


def _check_timestamp(value):
    """Refuse a timestamp that describes a clock rather than a reading."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise StoreError("payload timestamp is missing or not an integer")
    if value < _EPOCH_FLOOR:
        raise StoreError(f"payload timestamp {value} predates this project -- check the clock")
    if value > int(time.time()) + _FUTURE_TOLERANCE_SECONDS:
        raise StoreError(f"payload timestamp {value} is in the future -- check the clock")
    return value


def _check_payload(payload):
    """Validate one metrics.sh document and return (ts, source, gauges, counters).

    Re-checking a document this project produced itself looks like paranoia
    until you name the ways it can arrive wrong: metrics.sh edited by hand, a
    stale sample replayed from a file, an error document ({"status":"error"})
    handed over as though it were data, or simply a different module's output
    piped in by mistake. The module and status fields are checked because they
    are the sample's own claim about what it is, and the cheapest moment to
    catch a wrong claim is before it becomes a row.
    """
    if not isinstance(payload, dict):
        raise StoreError("payload is not a JSON object")
    if payload.get("module") != "metrics":
        raise StoreError(f"payload is from module {payload.get('module')!r}, expected 'metrics'")
    if payload.get("status") != "ok":
        raise StoreError(f"payload status is {payload.get('status')!r}, expected 'ok'")

    timestamp = _check_timestamp(payload.get("timestamp"))

    gauges = payload.get("gauges")
    counters = payload.get("counters")
    if not isinstance(gauges, dict) or not isinstance(counters, dict):
        raise StoreError("payload is missing its gauges or counters object")
    if not gauges and not counters:
        raise StoreError("payload contains no measurements at all")

    # A name appearing in both groups would mean the same series was sometimes a
    # gauge and sometimes a counter -- averageable on Monday and not on Tuesday.
    # There is no sane way to store that, so it is refused rather than resolved.
    clash = set(gauges) & set(counters)
    if clash:
        raise StoreError(f"metric declared as both gauge and counter: {sorted(clash)}")

    source = payload.get("source")
    if not isinstance(source, dict):
        source = {}
    return timestamp, source, gauges, counters


def _source_text(source, key):
    """One optional string field of the source block, or None.

    Length-capped because it is written to the database: an interface name is a
    handful of characters, and anything longer is not an interface name.
    """
    value = source.get(key)
    if not isinstance(value, str) or not value:
        return None
    return value[:64]


def _source_int(source, key):
    """One optional integer field of the source block, or None."""
    value = source.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


# ===========================================================================
#  4. WRITING
# ===========================================================================
def store_sample(payload, connection=None):
    """Validate one metrics.sh document and write it as one atomic transaction.

    ATOMIC MATTERS HERE. A sample is one tick plus its thirty measurements. If
    the process were killed halfway, a partial tick would look to the baseline
    engine like a moment when half the machine's sensors stopped -- and it would
    faithfully report that as an anomaly. `with connection:` wraps the whole
    write: either every row lands or none of them does.
    """
    timestamp, source, gauges, counters = _check_payload(payload)

    # Everything is validated BEFORE anything is written. Building the full list
    # of rows first means a bad value in the last metric cannot leave the first
    # twenty-nine already committed.
    rows = []
    for kind, group in ((KIND_GAUGE, gauges), (KIND_COUNTER, counters)):
        for name, value in group.items():
            _check_metric_name(name)
            rows.append((name, timestamp, kind, _check_value(name, value)))

    owned = connection is None
    connection = connection or connect()
    try:
        with connection:
            # DELETE-then-INSERT rather than INSERT OR REPLACE, because a second
            # sample for the same second may legitimately carry FEWER metrics
            # than the first (a sensor that has since failed). REPLACE would
            # overwrite the metrics present in both and leave the vanished ones
            # behind as stale rows dated to this tick. Deleting first means the
            # stored tick is exactly the tick that was measured.
            connection.execute("DELETE FROM samples WHERE ts = ?", (timestamp,))
            connection.execute("DELETE FROM sample_runs WHERE ts = ?", (timestamp,))
            connection.execute(
                """
                INSERT INTO sample_runs
                    (ts, duration_ms, interface, disk_device,
                     cpu_cores, clock_ticks_per_second, stored_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    payload.get("sample_duration_ms") if isinstance(
                        payload.get("sample_duration_ms"), (int, float)
                    ) else None,
                    _source_text(source, "interface"),
                    _source_text(source, "disk_device"),
                    _source_int(source, "cpu_cores"),
                    _source_int(source, "clock_ticks_per_second"),
                    int(time.time()),
                ),
            )
            # executemany hands the whole batch to SQLite as one prepared
            # statement executed N times, instead of parsing the same INSERT
            # thirty times. Still parameter-bound, so the safety is unchanged.
            connection.executemany(
                "INSERT INTO samples (metric, ts, kind, value) VALUES (?, ?, ?, ?)",
                rows,
            )
    finally:
        # Only close what we opened. A caller that passed its own connection --
        # the test suite, or a loop importing many samples -- keeps it.
        if owned:
            connection.close()

    return {"timestamp": timestamp, "stored": len(rows)}


def run_metrics():
    """Run linux/metrics.sh and return its parsed JSON.

    THE COMMAND IS A LIST AND THERE IS NO shell=True. This is the project's
    architectural rule (section 3 of the brief) applied to a call with no user
    input in it at all: the path is derived from this file's own location and no
    argument is ever appended, so there is no string for anything to be injected
    into. Writing it as a list anyway means the rule holds by construction
    rather than by the current absence of a parameter.
    """
    if not METRICS_SCRIPT.exists():
        raise StoreError(f"sampler not found: {METRICS_SCRIPT}")
    try:
        completed = subprocess.run(
            [str(METRICS_SCRIPT)],
            capture_output=True,
            text=True,
            timeout=METRICS_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise StoreError(f"sampler timed out after {METRICS_TIMEOUT_SECONDS}s") from None
    except OSError as error:
        raise StoreError(f"sampler could not be run: {error}") from None

    # The exit status is deliberately NOT checked here. metrics.sh honours the
    # project's failure contract: on error it prints a valid JSON object saying
    # so and exits 1. Parsing it and letting _check_payload reject a non-"ok"
    # status gives a message that names the failing line of the script, which is
    # strictly more useful than "exit code 1".
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise StoreError(f"sampler did not return JSON: {error}") from None


def ingest(connection=None):
    """Take one sample and store it. The whole job of the collection timer."""
    return store_sample(run_metrics(), connection=connection)


def _headline(incidents, connection):
    """One plain sentence about what changed this tick, or None if nothing did.

    WHY A PRE-FORMATTED STRING RATHER THAN LETTING THE CALLER BUILD ONE: the
    caller is guardian-daemon.sh, a Bash script that must keep working on a
    machine where jq was never installed. Extracting one quoted field with sed
    is something Bash can do honestly; assembling a sentence out of a nested
    JSON document is not. So the sentence is built here, where the data already
    is, and the daemon only has to lift it out.

    It is None -- not an empty string -- when nothing happened, so that the
    daemon's sed finds no match and stays silent. A tick where the machine is
    fine should produce no log line at all.
    """
    opened = incidents.get("opened") or []
    resolved = incidents.get("resolved") or []
    if not opened and not resolved:
        return None

    pieces = []
    for incident_id in opened:
        row = connection.execute(
            "SELECT title, severity, risk_score, risk_level FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        pieces.append(
            f"opened {incident_id} {row['title']} "
            f"({row['severity']}, risk {row['risk_score']} {row['risk_level']})"
            if row else f"opened {incident_id}"
        )
    for incident_id in resolved:
        pieces.append(f"resolved {incident_id}")
    return "; ".join(pieces)


def observe(connection=None):
    """Sample, then detect, then raise or update incidents. One tick's work.

    THE ONE CALL THE DAEMON MAKES, and it lives here rather than in the daemon
    so that the sequence -- and its failure behaviour -- is written down once in
    Python instead of being assembled from three shell invocations.

    DETECTION IS OPTIONAL, COLLECTION IS NOT. The sample is stored first and
    unconditionally; if the detector or the incident engine then fails, the
    reading is still safely in the history and the next tick will try again.
    A failure to interpret data must never cost us the data.

    The imports are inside the function on purpose: guardian_store is the bottom
    layer and the two modules below import IT. Importing them at module scope
    would make the dependency circular, and it would mean anything that merely
    wants to write a row has to load the detector first.
    """
    owned = connection is None
    connection = connection or connect()
    try:
        stored = store_sample(run_metrics(), connection=connection)
        result = {
            "stored": stored, "detected": None, "incidents": None,
            "headline": None, "message": None,
        }

        try:
            import guardian_anomaly
            import guardian_incidents

            report = guardian_anomaly.scan(connection=connection)
            result["detected"] = report["summary"]
            result["incidents"] = guardian_incidents.process(report, connection=connection)
            result["headline"] = _headline(result["incidents"], connection)
        except Exception as error:                       # noqa: BLE001
            # A DELIBERATELY BROAD except, and the one place in this project
            # that has one. Everything above has a known, enumerated failure
            # set; here the whole detection and incident stack sits behind one
            # call, and the contract being defended is "the daemon keeps
            # collecting no matter what". Narrowing this to the exceptions
            # thought of today would mean tomorrow's unforeseen one stops the
            # history. The error is reported, never swallowed.
            result["message"] = f"detection failed: {type(error).__name__}: {error}"
        return result
    finally:
        if owned:
            connection.close()


# ===========================================================================
#  5. READING
# ===========================================================================
def _window_start(seconds, now=None):
    """Turn 'the last N seconds' into an absolute cut-off timestamp."""
    now = int(time.time()) if now is None else int(now)
    return now - int(seconds)


def series(metric, seconds=None, connection=None):
    """Every stored reading of one metric in the last N seconds, oldest first.

    Oldest first because every consumer of this list either plots it left to
    right or differences consecutive entries, and both want time to run forwards.
    """
    _check_metric_name(metric)
    seconds = recent_seconds() if seconds is None else seconds
    owned = connection is None
    connection = connection or connect()
    try:
        rows = connection.execute(
            """
            SELECT ts, value, kind
              FROM samples
             WHERE metric = ? AND ts >= ?
             ORDER BY ts ASC
            """,
            (metric, _window_start(seconds)),
        ).fetchall()
    finally:
        if owned:
            connection.close()
    return [{"ts": r["ts"], "value": r["value"], "kind": r["kind"]} for r in rows]


def latest(metric, connection=None):
    """The most recent reading of one metric, or None if there is none.

    ORDER BY ts DESC LIMIT 1 rather than max(ts): with the WITHOUT ROWID key
    (metric, ts) this walks the index backwards from the end of that metric's
    range and stops at the first row, so it reads exactly one row no matter how
    long the history is.
    """
    _check_metric_name(metric)
    owned = connection is None
    connection = connection or connect()
    try:
        row = connection.execute(
            """
            SELECT ts, value, kind
              FROM samples
             WHERE metric = ?
             ORDER BY ts DESC
             LIMIT 1
            """,
            (metric,),
        ).fetchone()
    finally:
        if owned:
            connection.close()
    return None if row is None else {"ts": row["ts"], "value": row["value"], "kind": row["kind"]}


def aggregate(metric, seconds=None, connection=None):
    """Count, average, minimum, maximum and standard deviation over a window.

    THIS IS THE BASELINE. Phase 7 step 3 compares the current reading against
    what comes back from here, and the shape of the answer is what makes that
    comparison possible: an average says what normal is, a standard deviation
    says how much this machine normally wanders, and the two together are what
    turn "86%" into "four standard deviations above where this machine sits".

    THE ARITHMETIC IS DONE BY SQLite, NOT BY PYTHON. Selecting a week of rows
    and averaging them in a Python loop would move about 600,000 rows across the
    process boundary to produce five numbers. SQLite computes them while
    scanning the range it was already reading.

    IT REFUSES TO AVERAGE A COUNTER, and that refusal is the point of storing
    'kind' at all. The average of an odometer is the average odometer reading,
    which is a real number with no meaning whatsoever -- it says roughly how
    long the machine has been up. Anything wanting a counter's behaviour over
    time wants rate(), and being told so is better than being handed a
    plausible-looking number that answers a different question.
    """
    _check_metric_name(metric)
    seconds = recent_seconds() if seconds is None else seconds
    owned = connection is None
    connection = connection or connect()
    try:
        kind = _kind_of(metric, connection)
        if kind == KIND_COUNTER:
            raise StoreError(
                f"{metric} is a counter; averaging it is meaningless -- use rate()"
            )
        row = connection.execute(
            """
            SELECT COUNT(value)  AS samples,
                   AVG(value)    AS mean,
                   MIN(value)    AS minimum,
                   MAX(value)    AS maximum,
                   stddev(value) AS deviation,
                   MIN(ts)       AS first_ts,
                   MAX(ts)       AS last_ts
              FROM samples
             WHERE metric = ? AND ts >= ?
            """,
            (metric, _window_start(seconds)),
        ).fetchone()
    finally:
        if owned:
            connection.close()

    # COUNT(value) counts non-NULL values, so a window in which every reading
    # was a failed sensor reports 0 samples rather than pretending to a mean.
    return {
        "metric": metric,
        "kind": kind,
        "window_seconds": int(seconds),
        "samples": row["samples"],
        "mean": row["mean"],
        "minimum": row["minimum"],
        "maximum": row["maximum"],
        "stddev": row["deviation"],
        "first_ts": row["first_ts"],
        "last_ts": row["last_ts"],
    }


def rate(metric, seconds=None, connection=None):
    """Turn a counter's readings into a per-second rate over the window.

    This is the other half of the design decision made in metrics.sh: counters
    are shipped raw and differenced at read time. Here is the read time.

        rate = (last - first) / (last_ts - first_ts)

    A COUNTER GOING BACKWARDS MEANS THE MACHINE REBOOTED. Every counter in
    /proc counts since boot, so a reboot resets it to zero; net_rx_bytes drops
    from 9,900,122 to 400. Subtracting gives a large negative number, and
    dividing it by the window would report a spectacular negative throughput.
    That is reported as None with a reset flag rather than as a number: "the
    machine restarted during this window" is the truth, and it is information
    the incident engine in a later phase will want, not noise to smooth over.
    """
    _check_metric_name(metric)
    seconds = recent_seconds() if seconds is None else seconds
    owned = connection is None
    connection = connection or connect()
    try:
        kind = _kind_of(metric, connection)
        if kind == KIND_GAUGE:
            raise StoreError(f"{metric} is a gauge; it is already a value -- use series()")
        rows = connection.execute(
            """
            SELECT ts, value
              FROM samples
             WHERE metric = ? AND ts >= ? AND value IS NOT NULL
             ORDER BY ts ASC
            """,
            (metric, _window_start(seconds)),
        ).fetchall()
    finally:
        if owned:
            connection.close()

    result = {
        "metric": metric,
        "kind": kind,
        "window_seconds": int(seconds),
        "samples": len(rows),
        "per_second": None,
        "delta": None,
        "elapsed_seconds": None,
        "counter_reset": False,
    }
    # Two readings are the minimum: one odometer reading is not a distance.
    if len(rows) < 2:
        return result

    first, last = rows[0], rows[-1]
    elapsed = last["ts"] - first["ts"]
    if elapsed <= 0:
        return result

    delta = last["value"] - first["value"]
    result["elapsed_seconds"] = elapsed
    if delta < 0:
        result["counter_reset"] = True
        return result

    result["delta"] = delta
    result["per_second"] = delta / elapsed
    return result


def rate_series(metric, seconds=None, connection=None):
    """A counter's history expressed as per-second rates, oldest first.

    rate() above collapses a whole window into one number -- the average over
    the window. That is the right answer for "how much traffic in the last five
    minutes", and the wrong one for anomaly detection, which needs to know what
    the rate has looked like OVER TIME in order to say whether the current rate
    is unusual. This turns a counter into something shaped like a gauge:

        counter:  9,900,122   9,900,540   9,901,001   9,901,470
        rates:           13.9        15.4        15.6

    so every statistic that works on a gauge works on a counter's throughput.

    Each point is dated with the LATER of the two samples it came from, because
    a rate describes the interval that has just ended -- dating it with the
    earlier sample would place a burst of traffic before it happened.

    Intervals spanning a counter reset are DROPPED, not clamped to zero. A
    reboot is not a moment of no traffic; it is a moment we cannot measure, and
    the two must not look the same in a graph.
    """
    _check_metric_name(metric)
    seconds = recent_seconds() if seconds is None else seconds
    owned = connection is None
    connection = connection or connect()
    try:
        kind = _kind_of(metric, connection)
        if kind == KIND_GAUGE:
            raise StoreError(f"{metric} is a gauge; it is already a value -- use series()")
        rows = connection.execute(
            """
            SELECT ts, value
              FROM samples
             WHERE metric = ? AND ts >= ? AND value IS NOT NULL
             ORDER BY ts ASC
            """,
            (metric, _window_start(seconds)),
        ).fetchall()
    finally:
        if owned:
            connection.close()

    points = []
    resets = 0
    # zip(rows, rows[1:]) walks CONSECUTIVE PAIRS -- the Python idiom for
    # "every adjacent two", and clearer than indexing with range(len(rows) - 1)
    # because there is no index arithmetic to get wrong at either end.
    for earlier, later in zip(rows, rows[1:]):
        elapsed = later["ts"] - earlier["ts"]
        if elapsed <= 0:
            continue
        delta = later["value"] - earlier["value"]
        if delta < 0:
            resets += 1
            continue
        points.append(
            {"ts": later["ts"], "value": delta / elapsed, "seconds": elapsed}
        )
    return {"metric": metric, "kind": kind, "points": points, "counter_resets": resets}


def _kind_of(metric, connection):
    """Is this metric stored as a gauge or a counter?

    Read from the newest row rather than assumed, so the answer describes what
    is actually in the table. An unknown metric raises rather than defaulting to
    a kind, because guessing here would let aggregate() silently average a
    counter that simply has not been stored yet.
    """
    row = connection.execute(
        "SELECT kind FROM samples WHERE metric = ? ORDER BY ts DESC LIMIT 1",
        (metric,),
    ).fetchone()
    if row is None:
        raise StoreError(f"no history for metric {metric!r}")
    return row["kind"]


def metrics_known(connection=None):
    """Every metric name the database has ever seen, with its kind and depth.

    Used by the dashboard to offer a metric list, and by the test suite to check
    that what metrics.sh emits is what actually arrived. DISTINCT over a
    WITHOUT ROWID table keyed on (metric, ts) walks one entry per metric rather
    than reading every row.
    """
    owned = connection is None
    connection = connection or connect()
    try:
        rows = connection.execute(
            """
            SELECT metric,
                   MAX(kind) AS kind,
                   COUNT(*)  AS samples,
                   MIN(ts)   AS first_ts,
                   MAX(ts)   AS last_ts
              FROM samples
             GROUP BY metric
             ORDER BY metric
            """
        ).fetchall()
    finally:
        if owned:
            connection.close()
    return [dict(row) for row in rows]


# ===========================================================================
#  6. RETENTION -- section 55 of the brief
# ===========================================================================
def prune(connection=None, now=None):
    """Enforce both retention guards and hand the freed pages back to the disk.

    THE AUDIT SYSTEM MUST NOT BECOME THE DISK PROBLEM IT EXISTS TO REPORT. A
    store that only ever inserts will, on a 30-second timer, eventually trip the
    DISK_CRITICAL alarm in diagnosis.sh -- and the incident it raises would be
    its own fault. So pruning is not housekeeping here; it is part of being
    correct.

    TWO GUARDS THAT FAIL IN DIFFERENT WAYS, applied in order:

      1. BY AGE. Delete anything older than HISTORY_RETENTION_HOURS. This is the
         one that expresses the intent -- "a week of history" -- and it is the
         one that is useless if the clock is wrong.
      2. BY COUNT. If more than HISTORY_MAX_ROWS sample rows remain, delete the
         oldest ticks until they do not. This does not consult the clock at all,
         so a VM that resumes from suspend believing it is 1970 -- which stops
         guard 1 deleting anything ever -- still cannot fill the disk.

    Whole TICKS are deleted, never individual rows: removing some of a tick's
    metrics would leave a moment in history where the machine appears to have
    had fewer sensors, and the baseline engine would read that as a change in
    the machine rather than a change in the retention policy.
    """
    owned = connection is None
    connection = connection or connect()
    now = int(time.time()) if now is None else int(now)
    try:
        cutoff = now - retention_seconds()
        bytes_before = (
            connection.execute("PRAGMA page_count").fetchone()[0]
            * connection.execute("PRAGMA page_size").fetchone()[0]
        )
        with connection:
            # --- guard 1: by age ---------------------------------------------
            # Children before parents: the FOREIGN KEY on samples(ts) means
            # SQLite would refuse to delete a sample_runs row that still has
            # samples pointing at it. That refusal is the integrity constraint
            # doing its job, and obeying the order is how the constraint stays
            # switched on rather than being worked around.
            aged_samples = connection.execute(
                "DELETE FROM samples WHERE ts < ?", (cutoff,)
            ).rowcount
            aged_runs = connection.execute(
                "DELETE FROM sample_runs WHERE ts < ?", (cutoff,)
            ).rowcount

            # --- guard 2: by row count ---------------------------------------
            capped_samples = 0
            capped_runs = 0
            total = connection.execute("SELECT COUNT(*) AS n FROM samples").fetchone()["n"]
            if total > max_rows():
                # Work out WHICH TICK to cut at rather than how many rows to
                # delete, so a tick is never half removed. The subquery finds
                # the timestamps of the oldest ticks and takes the newest of
                # them as the new cut-off.
                #
                # excess / metrics_per_tick is how many ticks are surplus. It is
                # deliberately a rough estimate: one prune does not have to
                # reach the cap exactly, because it runs again on every sample.
                per_tick = max(1, len(metrics_known(connection=connection)))
                surplus_ticks = max(1, (total - max_rows()) // per_tick + 1)
                row = connection.execute(
                    """
                    SELECT MAX(ts) AS cut FROM (
                        SELECT ts FROM sample_runs ORDER BY ts ASC LIMIT ?
                    )
                    """,
                    (surplus_ticks,),
                ).fetchone()
                if row["cut"] is not None:
                    cap_cutoff = row["cut"]
                    capped_samples = connection.execute(
                        "DELETE FROM samples WHERE ts <= ?", (cap_cutoff,)
                    ).rowcount
                    capped_runs = connection.execute(
                        "DELETE FROM sample_runs WHERE ts <= ?", (cap_cutoff,)
                    ).rowcount

        # --- give the pages back to the filesystem ---------------------------
        # OUTSIDE the transaction above, and both details here were found by
        # measuring the file rather than by reading the documentation.
        #
        # 1. incremental_vacuum CANNOT RUN INSIDE A TRANSACTION. Called within
        #    the `with connection:` block above it silently does nothing at all
        #    -- no error, no warning, just a file that never shrinks.
        #
        # 2. .fetchall() IS NOT DECORATION. PRAGMA incremental_vacuum is a
        #    statement that does its work one page per step, and Python's
        #    sqlite3 execute() steps a statement once. Without draining the
        #    cursor this reclaims exactly ONE page -- 4 KB -- per prune, which
        #    on a database growing by megabytes a day is indistinguishable from
        #    doing nothing. Measured: 12.39 MB -> 12.39 MB with execute() alone,
        #    12.39 MB -> 4.14 MB with the fetchall().
        connection.execute("PRAGMA incremental_vacuum").fetchall()

        # 3. AND THEN THE WAL HAS TO BE CHECKPOINTED. Under WAL the vacuum's
        #    effect lands in the write-ahead log first, so the .db file on disk
        #    is unchanged until a checkpoint moves it home. TRUNCATE also
        #    resets the -wal file itself, which is real disk usage too. If
        #    another connection is mid-read, SQLite reports busy and skips it
        #    rather than waiting -- the pages simply come back at the next
        #    prune, which is the right way for housekeeping to fail.
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()

        page_count = connection.execute("PRAGMA page_count").fetchone()[0]
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]

        return {
            "cutoff": cutoff,
            "deleted_samples": aged_samples + capped_samples,
            "deleted_runs": aged_runs + capped_runs,
            "deleted_by_age": aged_samples,
            "deleted_by_row_cap": capped_samples,
            "bytes_before": bytes_before,
            "bytes_after": page_count * page_size,
        }
    finally:
        if owned:
            connection.close()


def stats(connection=None):
    """A description of the store itself, for the Settings and Automation pages."""
    owned = connection is None
    connection = connection or connect()
    try:
        runs = connection.execute(
            "SELECT COUNT(*) AS n, MIN(ts) AS first_ts, MAX(ts) AS last_ts FROM sample_runs"
        ).fetchone()
        sample_count = connection.execute("SELECT COUNT(*) AS n FROM samples").fetchone()["n"]
        version = schema_version(connection)
        # page_count x page_size is the size of the database proper. The -wal
        # file alongside it is counted separately below, because during a busy
        # period it is real disk usage that a size check would otherwise miss.
        page_count = connection.execute("PRAGMA page_count").fetchone()[0]
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
    finally:
        if owned:
            connection.close()

    path = database_file()
    wal = path.with_name(path.name + "-wal")
    return {
        "database": str(path),
        "schema_version": version,
        "ticks": runs["n"],
        "samples": sample_count,
        "first_ts": runs["first_ts"],
        "last_ts": runs["last_ts"],
        "span_seconds": (runs["last_ts"] - runs["first_ts"]) if runs["n"] else 0,
        "bytes": page_count * page_size,
        "wal_bytes": wal.stat().st_size if wal.exists() else 0,
        "retention_hours": retention_seconds() // 3600,
        "max_rows": max_rows(),
    }


# ===========================================================================
#  7. COMMAND LINE
# ===========================================================================
#
# WHY THIS MODULE HAS A CLI AT ALL. The collection timer in the next step needs
# to run one command, and a shell one-liner that imports Python is not something
# a systemd unit should contain. It also means the whole store can be exercised
# and demonstrated from a terminal, with no Flask running, which is how the
# viva will actually be conducted.
#
# THE OUTPUT IS THE SAME CONTRACT THE BASH MODULES HONOUR: exactly one JSON
# object on stdout, a "status" of "ok" or "error", and a non-zero exit on
# failure. That is not decoration -- it means guardian_store.py composes with
# `jq` and with everything else in this project instead of being a special case.
# ---------------------------------------------------------------------------
_USAGE = "ingest [-] | observe | prune | stats | series <metric> [seconds] | " \
         "aggregate <metric> [seconds] | rate <metric> [seconds] | " \
         "rates <metric> [seconds] | metrics"


def _emit(payload, exit_code=0):
    """Print one JSON object and exit. The single exit point of the CLI."""
    print(json.dumps(payload, indent=2))
    sys.exit(exit_code)


def main(argv):
    """Dispatch one subcommand.

    The command name is matched against a fixed set of literals. There is no
    getattr(module, name) lookup, which would turn any function in this file --
    including the private ones -- into a callable subcommand.
    """
    if not argv:
        _emit({"module": "store", "status": "error", "message": f"usage: {_USAGE}"}, 2)

    command, arguments = argv[0], argv[1:]

    def optional_seconds(default=None):
        """The trailing [seconds] argument, if one was given."""
        if not arguments[1:]:
            return default
        try:
            return max(1, int(arguments[1]))
        except ValueError:
            raise StoreError(f"seconds must be a whole number, got {arguments[1]!r}") from None

    try:
        if command == "ingest":
            # "-" reads a sample from stdin instead of running the sampler, so a
            # captured or hand-written payload can be replayed. It is the same
            # validation path either way: nothing skips _check_payload.
            if arguments and arguments[0] == "-":
                result = store_sample(json.loads(sys.stdin.read()))
            else:
                result = ingest()
        elif command == "observe":
            result = observe()
        elif command == "prune":
            result = prune()
        elif command == "stats":
            result = stats()
        elif command == "metrics":
            result = {"metrics": metrics_known()}
        elif command in ("series", "aggregate", "rate", "rates"):
            if not arguments:
                raise StoreError(f"{command} needs a metric name")
            metric = arguments[0]
            if command == "series":
                result = {"metric": metric, "points": series(metric, optional_seconds())}
            elif command == "aggregate":
                result = aggregate(metric, optional_seconds())
            elif command == "rates":
                result = rate_series(metric, optional_seconds())
            else:
                result = rate(metric, optional_seconds())
        else:
            raise StoreError(f"unknown command {command!r} -- usage: {_USAGE}")
    except StoreError as error:
        _emit({"module": "store", "status": "error", "message": str(error)}, 1)
    except (sqlite3.Error, json.JSONDecodeError, OSError) as error:
        # Everything this layer can fail on, reported in the project's error
        # shape rather than as a Python traceback on stdout -- which would not
        # be JSON and would break any caller parsing it.
        _emit(
            {
                "module": "store",
                "status": "error",
                "message": f"{type(error).__name__}: {error}",
            },
            1,
        )

    result["module"] = "store"
    result["status"] = "ok"
    _emit(result)


if __name__ == "__main__":
    main(sys.argv[1:])
