#!/usr/bin/env python3
"""
Linux Guardian -- guardian_risk.py                          (Phase 8, step 1)

HOW BAD IS IT, AND HOW MUCH DOES IT MATTER? -- two different questions.

    SEVERITY  how serious this thing is in itself.        INFO..CRITICAL
    RISK      how much attention it deserves right now,   0..100 -> LOW..CRITICAL
              given how confident we are, how long it has
              been going on, and what it is happening to.

They are separated because they disagree, constantly, and the disagreement is
the useful part. A CRITICAL-severity finding seen once, with 60% confidence, on
a component nothing depends on, is not where anyone should look first. A
MEDIUM-severity finding that has recurred every hour for a week, at 99%
confidence, on the disk, is.

Section 12 of the brief puts it in one line: **do not make every event
critical**. A severity scale on which everything is CRITICAL carries exactly as
much information as no severity scale at all, and it trains the person reading
it to ignore the colour red. Everything in this file is built to resist that
drift, and three rules do most of the work:

  1. LOW CONFIDENCE CANNOT PRODUCE HIGH SEVERITY. A finding the detector is
     unsure of is capped, no matter how alarming it looks.
  2. A FIRST SIGHTING IS NOT AN EMERGENCY. Escalation needs persistence -- the
     thing has to still be true a few samples later.
  3. EVERY ADJUSTMENT IS RECORDED. The output carries the list of steps that
     produced the answer, so a severity can be argued with rather than merely
     disbelieved.

NOTHING IN THIS FILE READS THE DATABASE, RUNS A COMMAND, OR HAS A SIDE EFFECT.
It is arithmetic over values the caller supplies, which is what makes it
testable against hand-worked examples -- see test_incidents.py section 1.
"""

from guardian_config import read_config

# ---------------------------------------------------------------------------
# THE SEVERITY LADDER, lowest first. The index in this tuple IS the severity
# level, which is what lets an adjustment be written as "+1 step" instead of a
# table of every from/to pair.
# ---------------------------------------------------------------------------
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

INFO, LOW, MEDIUM, HIGH, CRITICAL = SEVERITIES

# The risk bands. A score is turned into a word here and nowhere else, so the
# dashboard, the log and the API can never disagree about what "62" means.
RISK_BANDS = (
    (25, "LOW"),
    (50, "MEDIUM"),
    (75, "HIGH"),
    (101, "CRITICAL"),
)


class RiskError(Exception):
    """A refusal by this layer: an unknown severity name, an impossible weight."""


# ===========================================================================
#  1. CONFIGURATION
# ===========================================================================
def _number(key, default, minimum=0.0):
    """Read one numeric setting, falling back when absent or unusable."""
    raw = read_config().get(key, "")
    try:
        value = float(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


def settings():
    """Every weight and rule this module uses, resolved in one place.

    Returned rather than read at the point of use so that a score can carry the
    weights that produced it. A risk number without its weights cannot be
    checked by the person it is shown to, and an unfalsifiable number is not
    evidence -- it is decoration.
    """
    return {
        # The six factors risk is built from. They are weights, not
        # percentages: only their RATIO matters, because the total is divided
        # by their sum. That means a weight can be changed without every other
        # one having to be re-tuned to keep them adding to 100.
        "weight_severity": _number("RISK_WEIGHT_SEVERITY", 3.0),
        "weight_confidence": _number("RISK_WEIGHT_CONFIDENCE", 2.0),
        "weight_impact": _number("RISK_WEIGHT_IMPACT", 2.0),
        "weight_persistence": _number("RISK_WEIGHT_PERSISTENCE", 1.5),
        "weight_recurrence": _number("RISK_WEIGHT_RECURRENCE", 1.0),
        "weight_security": _number("RISK_WEIGHT_SECURITY", 1.5),
        # How many consecutive sightings count as "fully persistent", and how
        # many previous occurrences count as "fully recurrent". Both are the
        # point at which the factor reaches 1.0 and stops growing -- a problem
        # seen 500 times is not five times more urgent than one seen 100 times.
        "persistence_full": _number("RISK_PERSISTENCE_FULL", 10.0, minimum=1.0),
        "recurrence_full": _number("RISK_RECURRENCE_FULL", 5.0, minimum=1.0),
        # Severity rules.
        "escalate_after": _number("SEVERITY_ESCALATE_AFTER", 5.0, minimum=1.0),
        "min_confidence_for_high": _number("SEVERITY_MIN_CONFIDENCE_FOR_HIGH", 0.85),
        # What confidence to assume when the detector could not compute one.
        # See the zero-variance case in guardian_anomaly: sometimes there is
        # genuinely no confidence figure, and something has to be used. It is
        # deliberately BELOW min_confidence_for_high, so an unquantifiable
        # finding can never be escalated to HIGH on the strength of a number
        # this file invented for it.
        "unknown_confidence": _number("RISK_UNKNOWN_CONFIDENCE", 0.5),
    }


# ===========================================================================
#  2. SEVERITY
# ===========================================================================
def severity_index(name):
    """Turn a severity name into its position on the ladder."""
    try:
        return SEVERITIES.index(name)
    except ValueError:
        raise RiskError(f"unknown severity {name!r} -- expected one of {SEVERITIES}") from None


def assess_severity(base, verdict=None, confidence=None, occurrences=1,
                    security_relevant=False, config=None):
    """Work out a severity, and show the working.

    Starts from the base severity declared for this incident type in
    incidents.json -- a human's judgement about how serious this KIND of thing
    is -- and then moves it up or down for what was actually observed.

    THE ADJUSTMENTS, IN THE ORDER THEY APPLY (order matters: the confidence cap
    is applied LAST, so it can undo an escalation rather than being undone by
    one -- the whole point of a cap is that nothing gets past it):

      +1  the detector called it CRITICAL rather than WARNING
      +1  it has persisted for escalate_after sightings or more
      +1  it is security-relevant, per the registry
      cap at MEDIUM if confidence is below min_confidence_for_high

    WHY THE CAP EXISTS AT ALL. Without it the arithmetic happily produces a
    CRITICAL from a finding the detector explicitly said it was unsure about --
    and a CRITICAL that turns out to be noise costs more than a missed MEDIUM,
    because it is what teaches people to stop reading the alerts.
    """
    config = config or settings()
    steps = []

    index = severity_index(base)
    steps.append(f"base severity for this incident type: {base}")

    if verdict == "CRITICAL":
        index += 1
        steps.append("+1: the detector's verdict was CRITICAL, not WARNING")

    if occurrences >= config["escalate_after"]:
        index += 1
        steps.append(
            f"+1: seen {occurrences} times, at or past the "
            f"{int(config['escalate_after'])} needed to count as persistent"
        )
    else:
        steps.append(
            f"no escalation: seen {occurrences} time(s), "
            f"{int(config['escalate_after'])} needed to count as persistent"
        )

    if security_relevant:
        index += 1
        steps.append("+1: this incident type is marked security-relevant")

    # Clamp BEFORE the cap, so "CRITICAL + 1" does not fall off the end of the
    # ladder and raise an IndexError on the most alarming input in the system.
    index = max(0, min(index, len(SEVERITIES) - 1))

    effective_confidence = (
        config["unknown_confidence"] if confidence is None else confidence
    )
    ceiling = severity_index(MEDIUM)
    if effective_confidence < config["min_confidence_for_high"] and index > ceiling:
        note = (
            f"capped at {MEDIUM}: confidence "
            f"{effective_confidence:.0%} is below the "
            f"{config['min_confidence_for_high']:.0%} needed for {HIGH} or above"
        )
        if confidence is None:
            note += " (the detector could not compute a confidence, so the configured default was used)"
        index = ceiling
        steps.append(note)

    return {"severity": SEVERITIES[index], "steps": steps}


# ===========================================================================
#  3. RISK
# ===========================================================================
def _clamp01(value):
    """Force a factor into 0..1. Every factor below must be on the same scale.

    A factor that escaped its range would silently reweight every other one:
    the total is divided by the sum of the WEIGHTS, so a factor of 3.0 would
    contribute three times its declared share and the score could exceed 100.
    """
    return max(0.0, min(1.0, float(value)))


def assess_risk(severity, confidence=None, impact=0.5, occurrences=1,
                previous_occurrences=0, security_relevant=False, config=None):
    """Score 0..100 and band it LOW / MEDIUM / HIGH / CRITICAL.

    THE FORMULA
        risk = 100 * sum(weight_i * factor_i) / sum(weight_i)

    A weighted average of six factors, each normalised to 0..1. It is a weighted
    average and NOT a sum of penalties for one specific reason: an average
    cannot exceed 100 and cannot be gamed by adding more factors. Every new
    consideration dilutes the others rather than pushing the total up, so the
    scale keeps meaning the same thing as the model grows.

    THE SIX FACTORS
        severity     position on the ladder, 0..1
        confidence   how sure the detector is
        impact       how much depends on the affected component, from the
                     registry -- a human's judgement, written down once
        persistence  consecutive sightings, saturating at persistence_full
        recurrence   how many times this has happened BEFORE and been resolved;
                     a problem that keeps coming back is worse than one of the
                     same size that does not
        security     1 if this type is security-relevant, else 0

    WHY WEIGHTS AND NOT A LEARNED MODEL: there is no labelled data on this
    machine to learn from, and inventing coefficients that look learned would be
    the same fabrication this project refuses everywhere else. These are
    declared judgements in a config file, and they can be argued with.
    """
    config = config or settings()

    effective_confidence = (
        config["unknown_confidence"] if confidence is None else confidence
    )

    factors = {
        "severity": severity_index(severity) / (len(SEVERITIES) - 1),
        "confidence": _clamp01(effective_confidence),
        "impact": _clamp01(impact),
        "persistence": _clamp01(occurrences / config["persistence_full"]),
        "recurrence": _clamp01(previous_occurrences / config["recurrence_full"]),
        "security": 1.0 if security_relevant else 0.0,
    }
    weights = {
        "severity": config["weight_severity"],
        "confidence": config["weight_confidence"],
        "impact": config["weight_impact"],
        "persistence": config["weight_persistence"],
        "recurrence": config["weight_recurrence"],
        "security": config["weight_security"],
    }

    total_weight = sum(weights.values())
    if total_weight <= 0:
        raise RiskError("every risk weight is zero -- check RISK_WEIGHT_* in guardian.conf")

    score = 100.0 * sum(weights[name] * factors[name] for name in factors) / total_weight
    score = int(round(score))

    for ceiling, band in RISK_BANDS:
        if score < ceiling:
            level = band
            break

    return {
        "score": score,
        "level": level,
        "confidence_assumed": confidence is None,
        # The contribution each factor made, in points out of 100. This is what
        # turns "risk 62" into "risk 62, of which 21 is severity and 14 is that
        # it has happened four times before" -- a number that can be understood
        # instead of merely obeyed.
        "contributions": {
            name: round(100.0 * weights[name] * factors[name] / total_weight, 1)
            for name in factors
        },
        "factors": {name: round(value, 4) for name, value in factors.items()},
        "weights": weights,
    }
