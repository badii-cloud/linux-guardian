#!/usr/bin/env python3
"""
Linux Guardian -- guardian_anomaly.py                      (Phase 7, step 3)

IS THIS UNUSUAL FOR THIS MACHINE?

diagnosis.sh already answers a different question, and answers it well: is this
value above a threshold somebody wrote down? That question has a fixed answer
regardless of the machine, which is its strength and its blind spot:

    a build server that idles at 80% CPU trips CPU_WARNING every minute of a
    perfectly healthy day, and a laptop that idles at 3% can quadruple its load
    to 12% -- a genuine change in what the machine is doing -- without any
    threshold noticing at all.

This module answers the complementary question by comparing the machine against
its own recent past instead of against a constant. Both answers matter and
NEITHER REPLACES THE OTHER:

    threshold : "is this BAD?"        95% disk is bad, and may be entirely normal
    anomaly   : "is this ABNORMAL?"   40% CPU on a 3% machine is abnormal,
                                      and may be entirely harmless

    linux/metrics.sh -> guardian_store.py -> THIS FILE -> a verdict + evidence

WHAT THIS MODULE MAY AND MAY NOT CLAIM
--------------------------------------
Section 14 of the brief requires that an observed fact, an inference and a
recommendation are never presented as the same kind of statement. That rule is
built into the output shape here: every result carries `evidence` (numbers read
out of the database, which are facts) separately from `verdict` and `reason`
(what those numbers were taken to mean, which is an inference). Nothing in this
file recommends an action, and nothing in it can perform one -- it is as
read-only as Phase 1.

THE THREE WAYS A NAIVE DETECTOR GOES WRONG, AND WHAT IS DONE ABOUT THEM
-----------------------------------------------------------------------
 1. IT TEACHES ITSELF THAT THE ANOMALY IS NORMAL. If the baseline window
    includes the reading being judged, the spike is inside its own average.
    Fixed by making the baseline window END where the recent window BEGINS.

 2. IT SHOUTS ABOUT NOTHING. A metric that has been flat all hour has a
    standard deviation near zero, so any movement at all produces an enormous
    z-score. Fixed by requiring a minimum percentage change as well.

 3. IT ANSWERS BEFORE IT KNOWS ANYTHING. With four readings, "normal" is not a
    finding, it is a guess -- and it is indistinguishable from a clean bill of
    health. Fixed by reporting LEARNING until there are enough samples, which is
    a different word on purpose.
"""

import json
import math
import sys

import guardian_store as store
from guardian_config import read_config

# The verdicts. NORMAL/WARNING/CRITICAL deliberately echo the PASS/WARNING/FAIL
# vocabulary diagnosis.sh already uses, so the dashboard has one severity
# language rather than two. LEARNING is the one that does not map onto anything
# in Phase 2, because Phase 2 always has an answer and this module does not.
LEARNING = "LEARNING"
NORMAL = "NORMAL"
WARNING = "WARNING"
CRITICAL = "CRITICAL"


class AnomalyError(Exception):
    """A refusal by this layer: unknown metric, unusable configuration."""


# ===========================================================================
#  1. CONFIGURATION
# ===========================================================================
def _setting(key, default, minimum=None):
    """Read one numeric setting, falling back when it is absent or unusable."""
    raw = read_config().get(key, "")
    try:
        value = float(str(raw).strip())
    except (TypeError, ValueError):
        return default
    if minimum is not None and value < minimum:
        return default
    return value


def settings():
    """Every tunable this module uses, resolved once, in one place.

    Returned as a dictionary rather than read where needed so that a result can
    carry the settings that produced it. A verdict without the thresholds that
    generated it cannot be checked by the person reading it, and section 14 of
    the brief requires the evidence to travel with the conclusion.
    """
    lookbacks = read_config().get("ANOMALY_TREND_LOOKBACKS", "60 300 900 3600").split()
    parsed = []
    for word in lookbacks:
        try:
            seconds = int(word)
        except ValueError:
            continue
        if seconds > 0:
            parsed.append(seconds)

    return {
        "recent_seconds": int(_setting("ANOMALY_RECENT_SECONDS", 300, minimum=10)),
        "baseline_seconds": int(_setting("ANOMALY_BASELINE_SECONDS", 3600, minimum=60)),
        "min_samples": int(_setting("ANOMALY_MIN_SAMPLES", 20, minimum=2)),
        "z_warning": _setting("ANOMALY_Z_WARNING", 3.0, minimum=0.1),
        "z_critical": _setting("ANOMALY_Z_CRITICAL", 4.0, minimum=0.1),
        "min_change_percent": _setting("ANOMALY_MIN_CHANGE_PERCENT", 10.0, minimum=0),
        "trend_lookbacks": sorted(parsed) or [60, 300, 900, 3600],
        "metrics": read_config().get("ANOMALY_METRICS", "").split(),
    }


# ===========================================================================
#  2. GETTING A COMPARABLE SERIES OUT OF THE STORE
# ===========================================================================
def observations(metric, seconds, connection):
    """Every reading of one metric in the last N seconds, as (ts, value) pairs.

    A GAUGE IS USED DIRECTLY; A COUNTER IS CONVERTED TO ITS RATE FIRST. That
    conversion is what makes the rest of this file kind-agnostic: net_rx_bytes
    is an odometer and averaging it is meaningless, but bytes-per-second is an
    ordinary quantity that can be averaged, deviated and trended exactly like
    a percentage. Without it, half the metrics collected would be undetectable.
    """
    kind = store._kind_of(metric, connection)          # raises on an unknown metric
    if kind == store.KIND_GAUGE:
        points = store.series(metric, seconds=seconds, connection=connection)
        return kind, [(p["ts"], p["value"]) for p in points if p["value"] is not None]

    derived = store.rate_series(metric, seconds=seconds, connection=connection)
    return kind, [(p["ts"], p["value"]) for p in derived["points"]]


def _describe(values):
    """count, mean, min, max and sample standard deviation of a list of numbers.

    Computed here rather than by store.aggregate() for one reason: a counter's
    rates do not exist as rows in the database, so there is no SQL statement
    that could average them. Using the same Welford recurrence as the store's
    custom aggregate means a gauge and a counter's rate are described by
    identical arithmetic, and the two can be compared without wondering whether
    a difference came from the data or from the method.
    """
    count = 0
    mean = 0.0
    sum_squared_deviations = 0.0
    smallest = None
    largest = None

    for value in values:
        number = float(value)
        count += 1
        delta = number - mean
        mean += delta / count
        sum_squared_deviations += delta * (number - mean)
        smallest = number if smallest is None else min(smallest, number)
        largest = number if largest is None else max(largest, number)

    return {
        "samples": count,
        "mean": mean if count else None,
        "minimum": smallest,
        "maximum": largest,
        "stddev": math.sqrt(sum_squared_deviations / (count - 1)) if count > 1 else None,
    }


# ===========================================================================
#  3. TREND -- section 10 of the brief
# ===========================================================================
def _slope_per_minute(points):
    """Least-squares slope of value against time, in units per minute.

    WHY A REGRESSION AND NOT last MINUS first: two readings can straddle a
    single spike and report a steep trend that the other fifty readings
    contradict. A least-squares line uses every point in the window, so one
    outlier moves it a little instead of defining it.

    The formula is the standard one:

        slope = sum((t - t_mean) * (v - v_mean)) / sum((t - t_mean)^2)

    Time is shifted to start at zero before anything is squared. Unix
    timestamps are around 1.8x10^9, and squaring them lands at 3x10^18 -- past
    the range where a float is exact, which is the same trap the standard
    deviation avoids by using Welford. Subtracting the first timestamp makes the
    numbers small and the arithmetic exact, and it cannot change the slope,
    because sliding a line sideways does not tilt it.
    """
    if len(points) < 2:
        return None

    origin = points[0][0]
    times = [(ts - origin) for ts, _ in points]
    values = [value for _, value in points]

    time_mean = sum(times) / len(times)
    value_mean = sum(values) / len(values)

    numerator = sum((t - time_mean) * (v - value_mean) for t, v in zip(times, values))
    denominator = sum((t - time_mean) ** 2 for t in times)
    if denominator == 0:
        # Every reading carries the same timestamp, so there is no time axis to
        # have a slope along. Not an error -- just nothing to say.
        return None
    return (numerator / denominator) * 60.0


def trend(metric, connection, config=None, now=None):
    """Which way the metric is moving, and what it read at each lookback point.

    The lookback table is what section 10 of the brief asks for -- the value
    now, one minute ago, five, fifteen, sixty -- and it is the part a human
    actually reads. The slope is what a program reads.

    EACH LOOKBACK IS THE NEAREST READING AT OR BEFORE THAT MOMENT, not an
    average around it. "What did it say fifteen minutes ago" should be answered
    with a reading that was really taken, so that a number on the dashboard can
    always be traced back to a row in the database.
    """
    config = config or settings()
    now = int(store.time.time()) if now is None else int(now)
    longest = max(config["trend_lookbacks"])

    _, points = observations(metric, longest + config["recent_seconds"], connection)
    if not points:
        return {"direction": "unknown", "slope_per_minute": None, "points": {}}

    table = {}
    for lookback in config["trend_lookbacks"]:
        target = now - lookback
        # The most recent reading that is not newer than the target moment.
        # max() over a generator with a default avoids materialising a filtered
        # copy of the list for each of the four lookbacks.
        candidates = [(ts, value) for ts, value in points if ts <= target]
        table[f"{lookback}s"] = candidates[-1][1] if candidates else None

    recent = [(ts, value) for ts, value in points if ts >= now - config["recent_seconds"]]
    slope = _slope_per_minute(recent if len(recent) >= 2 else points)

    # The slope is judged against the spread of the data it came from, not
    # against a fixed number: "rising by 2 a minute" is dramatic for a metric
    # that normally varies by 0.1 and invisible for one that swings by 50. A
    # move of less than a tenth of a standard deviation per minute is called
    # steady.
    description = _describe([value for _, value in recent]) if recent else _describe([])
    spread = description["stddev"] or 0.0
    if slope is None:
        direction = "unknown"
    elif spread > 0 and abs(slope) < 0.1 * spread:
        direction = "steady"
    elif spread == 0 and slope == 0:
        direction = "steady"
    elif slope > 0:
        direction = "rising"
    else:
        direction = "falling"

    return {
        "direction": direction,
        "slope_per_minute": slope,
        "points": table,
        "window_seconds": config["recent_seconds"],
    }


# ===========================================================================
#  4. THE VERDICT
# ===========================================================================
def _confidence(z_score):
    """How confident the claim "this is unusual" is, from Chebyshev's inequality.

    CHEBYSHEV IS CHOSEN OVER THE NORMAL DISTRIBUTION, and this is the single
    most defensible decision in the file. The obvious move is to treat the
    z-score as a bell curve and report "3 sigma = 99.7% confidence". That number
    would be a fabrication: it is only true if the data is normally distributed,
    and CPU usage plainly is not. It is bounded at 0 and 100, it is heavily
    skewed towards idle, and it arrives in bursts. Quoting a normal-curve
    probability for it is inventing precision the data does not contain.

    Chebyshev's inequality makes no assumption about the distribution at all.
    For ANY distribution with a finite mean and variance:

        P(|X - mean| >= k * stddev)  <=  1 / k^2

    So at k = 3, AT MOST 11% of this machine's readings can be this far from its
    own average; at k = 4, at most 6.25%. The confidence reported is the other
    side of that bound -- at least 1 - 1/k^2 of normal readings are closer to
    the average than this one is.

    It is deliberately more modest than a normal-curve figure would be: 89%
    where a bell curve would claim 99.7%. That is the honest cost of not
    assuming the shape of the data, and a smaller number that is actually true
    is worth more in a viva than a larger one that is not.
    """
    if z_score is None or abs(z_score) <= 1:
        # Chebyshev says nothing useful at k <= 1: the bound is 1/1 = 100%,
        # i.e. "at most all of the readings", which is no information.
        return 0.0
    return 1.0 - (1.0 / (z_score * z_score))


def analyse(metric, connection=None, now=None, config=None):
    """Judge one metric against its own history. Returns evidence AND a verdict.

    THE TWO TESTS THAT BOTH HAVE TO PASS
      1. STATISTICAL -- the current average is at least z_warning standard
         deviations from the baseline average. This is what makes it "unusual
         for this machine" rather than "above a number someone chose".
      2. MATERIAL -- the change is also at least min_change_percent of the
         baseline. Without this, a metric that has been perfectly flat has a
         near-zero standard deviation and reports a z-score in the hundreds for
         a movement of half a percent.

    Failing either one is NORMAL. Reporting both separately in the output means
    a reader can see which of the two stopped a verdict, rather than being told
    only the conclusion.
    """
    config = config or settings()
    owned = connection is None
    connection = connection or store.connect()
    now = int(store.time.time()) if now is None else int(now)

    try:
        try:
            kind, recent_points = observations(metric, config["recent_seconds"], connection)
        except store.StoreError as error:
            raise AnomalyError(str(error)) from None

        # THE TWO WINDOWS, AND THE GAP BETWEEN THEM.
        # The baseline query asks for everything back to (recent + baseline)
        # seconds, then keeps only what is OLDER than the recent window. The
        # result is the hour BEFORE the last five minutes, with no overlap: the
        # readings being judged are not part of what they are judged against.
        _, all_points = observations(
            metric, config["recent_seconds"] + config["baseline_seconds"], connection
        )
        boundary = now - config["recent_seconds"]
        baseline_points = [(ts, value) for ts, value in all_points if ts < boundary]

        baseline = _describe([value for _, value in baseline_points])
        current = _describe([value for _, value in recent_points])
        movement = trend(metric, connection, config=config, now=now)
    finally:
        if owned:
            connection.close()

    result = {
        "metric": metric,
        "kind": kind,
        "unit": "per second" if kind == store.KIND_COUNTER else "value",
        "verdict": LEARNING,
        "confidence": 0.0,
        "reason": "",
        "current": current,
        "baseline": dict(baseline, window_seconds=config["baseline_seconds"]),
        "deviation": {"absolute": None, "percent": None, "z_score": None},
        "trend": movement,
        "tests": {"statistical": False, "material": False},
        "thresholds": {
            "z_warning": config["z_warning"],
            "z_critical": config["z_critical"],
            "min_change_percent": config["min_change_percent"],
            "min_samples": config["min_samples"],
        },
    }

    # --- can we say anything at all? ---------------------------------------
    if current["samples"] == 0:
        result["reason"] = "no readings in the recent window"
        return result
    if baseline["samples"] < config["min_samples"]:
        result["reason"] = (
            f"only {baseline['samples']} baseline reading(s), "
            f"{config['min_samples']} needed before a verdict"
        )
        return result

    # --- the arithmetic ----------------------------------------------------
    absolute = current["mean"] - baseline["mean"]
    result["deviation"]["absolute"] = absolute

    # A percentage change against a baseline of zero is undefined, not infinite.
    # It is left as None and handled as its own case below, because "this metric
    # has never been anything but zero and now is not" is a real finding that
    # deserves its own sentence rather than a division by zero.
    if baseline["mean"] not in (0, None):
        result["deviation"]["percent"] = 100.0 * absolute / abs(baseline["mean"])

    deviation = baseline["stddev"]
    if deviation and deviation > 0:
        result["deviation"]["z_score"] = absolute / deviation

    z_score = result["deviation"]["z_score"]
    percent = result["deviation"]["percent"]

    # A BASELINE WITH NO VARIATION AT ALL -- the blind spot this detector had
    # until a test caught it, and the one worth explaining out loud.
    #
    # If every baseline reading was identical, the standard deviation is exactly
    # zero and there is no z-score to compute: the division is undefined. The
    # first version of this file therefore reported such a metric NORMAL no
    # matter what it did next -- and it went NORMAL for a twentyfold jump in
    # network throughput, because the baseline had been a perfectly steady
    # 1000 bytes/second and dividing by zero produced None, which failed the
    # statistical test, which meant no verdict.
    #
    # That is precisely backwards. A metric that has never once moved and has
    # now moved is MORE surprising than a noisy one that has wandered further.
    # So when there is no variance to measure against, the test becomes a
    # different and simpler one: is the current value outside everything the
    # baseline ever saw? That question needs no standard deviation.
    zero_variance = baseline["stddev"] is None or baseline["stddev"] == 0
    outside_range = (
        baseline["minimum"] is not None
        and (current["mean"] < baseline["minimum"] or current["mean"] > baseline["maximum"])
    )
    result["baseline"]["zero_variance"] = zero_variance

    # --- test 1: is it statistically unusual? ------------------------------
    result["tests"]["statistical"] = (
        z_score is not None and abs(z_score) >= config["z_warning"]
    ) or (zero_variance and outside_range)

    # --- test 2: is it big enough to matter? -------------------------------
    if percent is not None:
        result["tests"]["material"] = abs(percent) >= config["min_change_percent"]
    else:
        # baseline mean is exactly zero. Any non-zero current reading is a
        # change from a metric that has been flat at zero for the whole window,
        # which is material by definition -- there is no proportion to take.
        result["tests"]["material"] = current["mean"] != 0

    # --- the verdict -------------------------------------------------------
    if not result["tests"]["statistical"] and not result["tests"]["material"]:
        result["verdict"] = NORMAL
        result["reason"] = "within this machine's usual range"
    elif not result["tests"]["material"]:
        result["verdict"] = NORMAL
        result["reason"] = (
            f"statistically unusual (z={z_score:.1f}) but the change is only "
            f"{abs(percent):.1f}%, under the {config['min_change_percent']:.0f}% "
            f"needed to matter -- this metric is simply very steady"
        )
    elif not result["tests"]["statistical"]:
        result["verdict"] = NORMAL
        result["reason"] = (
            "a large change, but not large relative to how much this metric "
            "normally varies"
        )
    elif z_score is None:
        # The zero-variance path. There is a real deviation and it is outside
        # everything the baseline recorded, but there is no spread to score it
        # against, so it cannot be graded CRITICAL and NO CONFIDENCE IS
        # REPORTED AT ALL -- confidence stays None rather than being given some
        # plausible-looking number. Section 14 of the brief requires that a
        # guess is never dressed as a fact, and "I am 90% sure" computed from a
        # standard deviation that does not exist would be exactly that.
        result["verdict"] = WARNING
        result["confidence"] = None
        direction = "above" if absolute > 0 else "below"
        result["reason"] = (
            f"{current['mean']:.2f} is outside everything the baseline recorded "
            f"({baseline['minimum']:.2f} to {baseline['maximum']:.2f}), "
            f"{direction} a perfectly steady {baseline['mean']:.2f}. "
            f"With no variation in the baseline there is no spread to score the "
            f"size of this change against, so no confidence is claimed"
        )
    else:
        magnitude = abs(z_score)
        result["verdict"] = CRITICAL if magnitude >= config["z_critical"] else WARNING
        # Rounded to four places because the raw value approaches 1 without ever
        # reaching it: at z = 60 the bound is 0.99972, and printing that as
        # "100%" would claim a certainty Chebyshev never offers.
        result["confidence"] = round(_confidence(z_score), 4)
        direction = "above" if absolute > 0 else "below"
        shown_percent = f"{abs(percent):.0f}%" if percent is not None else "from zero"
        result["reason"] = (
            f"{current['mean']:.2f} is {magnitude:.1f} standard deviations "
            f"{direction} this machine's baseline of {baseline['mean']:.2f} "
            f"({shown_percent} change), and {movement['direction']}"
        )

    # EVIDENCE IS SEPARATE FROM THE CONCLUSION -- section 14 of the brief. Every
    # line below is a number read out of the database; none of them is an
    # interpretation. A reader can recompute the verdict from this list.
    result["evidence"] = [
        f"baseline: {baseline['samples']} readings over "
        f"{config['baseline_seconds']}s ending {config['recent_seconds']}s ago",
        f"baseline mean {baseline['mean']:.4f}, "
        f"stddev {baseline['stddev']:.4f}" if baseline["stddev"] is not None
        else f"baseline mean {baseline['mean']:.4f}, stddev undefined",
        f"baseline range {baseline['minimum']:.4f} to {baseline['maximum']:.4f}",
        f"current: {current['samples']} readings, mean {current['mean']:.4f}",
        f"trend over the last {config['recent_seconds']}s: {movement['direction']}"
        + (
            f", {movement['slope_per_minute']:+.4f} per minute"
            if movement["slope_per_minute"] is not None
            else ""
        ),
    ]
    return result


# ===========================================================================
#  5. SCANNING EVERYTHING
# ===========================================================================
def scan(connection=None, now=None):
    """Run analyse() over every metric and return the ones worth looking at.

    THE DEFAULT IS EVERY METRIC, NOT A CURATED LIST. A configured list would be
    a list of things somebody already thought to worry about, and the entire
    reason for having a baseline is to catch what nobody predicted. Scanning all
    thirty costs one query each against an index that is already in memory.
    """
    config = settings()
    owned = connection is None
    connection = connection or store.connect()

    try:
        names = config["metrics"] or [
            row["metric"] for row in store.metrics_known(connection=connection)
        ]

        findings = []
        skipped = []
        for name in names:
            try:
                findings.append(analyse(name, connection=connection, now=now, config=config))
            except (AnomalyError, store.StoreError) as error:
                # One unreadable metric must not stop the scan. It is recorded
                # as skipped rather than dropped, so a metric that quietly
                # stopped being analysable is visible instead of just absent.
                skipped.append({"metric": name, "message": str(error)})
    finally:
        if owned:
            connection.close()

    # Worst first, then by how far out it is: the order a human should read them
    # in. LEARNING sorts below NORMAL because "not enough data" is a state of the
    # detector, not of the machine, and it must not push a real finding down the
    # page.
    rank = {CRITICAL: 0, WARNING: 1, NORMAL: 2, LEARNING: 3}
    findings.sort(
        key=lambda f: (rank[f["verdict"]], -abs(f["deviation"]["z_score"] or 0))
    )

    counts = {verdict: 0 for verdict in (CRITICAL, WARNING, NORMAL, LEARNING)}
    for finding in findings:
        counts[finding["verdict"]] += 1

    return {
        "checked": len(findings),
        "summary": counts,
        "anomalies": [f for f in findings if f["verdict"] in (WARNING, CRITICAL)],
        "findings": findings,
        "skipped": skipped,
    }


# ===========================================================================
#  6. COMMAND LINE
# ===========================================================================
_USAGE = "scan | check <metric> | trend <metric> | settings"


def _emit(payload, exit_code=0):
    """Print one JSON object and exit. The single exit point of the CLI."""
    print(json.dumps(payload, indent=2, default=float))
    sys.exit(exit_code)


def main(argv):
    """Dispatch one subcommand, matched against a fixed set of literals."""
    if not argv:
        _emit({"module": "anomaly", "status": "error", "message": f"usage: {_USAGE}"}, 2)

    command, arguments = argv[0], argv[1:]
    try:
        if command == "scan":
            # The full findings list is dropped from the CLI's output on
            # purpose: thirty complete analyses is pages of JSON, and the
            # question `scan` answers is "is anything wrong". `check` gives the
            # detail for one metric.
            result = scan()
            result["findings"] = [
                {
                    "metric": f["metric"],
                    "verdict": f["verdict"],
                    "z_score": f["deviation"]["z_score"],
                    "reason": f["reason"],
                }
                for f in result["findings"]
            ]
        elif command == "settings":
            result = settings()
        elif command in ("check", "trend"):
            if not arguments:
                raise AnomalyError(f"{command} needs a metric name")
            result = (
                analyse(arguments[0])
                if command == "check"
                else {"metric": arguments[0], "trend": trend(arguments[0], store.connect())}
            )
        else:
            raise AnomalyError(f"unknown command {command!r} -- usage: {_USAGE}")
    except (AnomalyError, store.StoreError) as error:
        _emit({"module": "anomaly", "status": "error", "message": str(error)}, 1)
    except OSError as error:
        _emit(
            {
                "module": "anomaly",
                "status": "error",
                "message": f"{type(error).__name__}: {error}",
            },
            1,
        )

    result["module"] = "anomaly"
    result["status"] = "ok"
    _emit(result)


if __name__ == "__main__":
    main(sys.argv[1:])
