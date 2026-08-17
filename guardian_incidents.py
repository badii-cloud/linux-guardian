#!/usr/bin/env python3
"""
Linux Guardian -- guardian_incidents.py                     (Phase 8, step 1)

FROM "FOUR METRICS LOOK ODD" TO "ONE THING IS HAPPENING".

Phase 7 ended with a demonstration and a complaint. Two of four cores were
loaded on purpose and the detector correctly reported:

    CRITICAL  load_1min        z=8.4
    CRITICAL  load_per_core    z=8.0
    CRITICAL  load_5min        z=6.3
    CRITICAL  cpu_idle_ticks   z=4.2

Four alarms. One event. Section 12 of the brief is explicit that this is a
failure mode -- an alert list where one cause fills four rows is an alert list
people stop reading. This module turns those four into:

    INC-20260816-0001   CPU saturation   HIGH   risk 68   4 symptoms

and keeps it as ONE row for as long as the condition lasts, instead of raising
a fresh incident every thirty seconds.

    guardian_anomaly.scan()  ->  correlate  ->  fingerprint  ->  open or update
                                                                       |
                                                                       v
                                                        incidents + incident_timeline

THE THREE JOBS
--------------
 1. CORRELATE. linux/incidents.json declares which metrics are symptoms of the
    same condition. Several abnormal symptoms of one type become one incident.

 2. DEDUPLICATE. An incident has a FINGERPRINT -- its type and component. If an
    open incident already carries that fingerprint, the new observation updates
    it and increments its occurrence count. This is what makes an hour-long
    problem one row instead of 120.

 3. REMEMBER. Every state change appends to an append-only timeline, so the
    question "why did Guardian do that?" has an answer months later.

WHAT THIS MODULE MAY NOT DO
---------------------------
It cannot execute anything. `recommended_actions` are ids copied out of
actions.json and checked against it at load time, so an incident can only ever
SUGGEST something the action registry has already approved -- and suggesting is
where this module's authority ends. Phase 3's validation, allow-lists and
confirm step all still stand between a recommendation and a running command.
That is the same relationship Phase 6 gave the language model: propose freely,
execute never.
"""

import json
import sys
import time

import guardian_risk as risk
import guardian_store as store
from guardian_actions import ACTIONS, LINUX_DIR, _strip_docs

REGISTRY_FILE = LINUX_DIR / "incidents.json"

# ---------------------------------------------------------------------------
# THE LIFECYCLE  (brief section 11)
#
# A status is not a label, it is a position in a machine with declared edges.
# Writing the legal transitions down means an impossible one -- RESOLVED going
# back to DETECTED, or a REMEDIATING incident jumping straight to RESOLVED
# without ever being VERIFIED -- is refused by this module rather than quietly
# stored and puzzled over later.
#
# WHY VERIFYING CANNOT BE SKIPPED: section 25 of the brief requires that an
# action's exit code is never taken as proof it worked. Making VERIFYING the
# only route from REMEDIATING to RESOLVED puts that rule in the state machine
# instead of in a comment somebody may forget to read.
# ---------------------------------------------------------------------------
DETECTED = "DETECTED"
INVESTIGATING = "INVESTIGATING"
WAITING_APPROVAL = "WAITING_APPROVAL"
REMEDIATING = "REMEDIATING"
VERIFYING = "VERIFYING"
RESOLVED = "RESOLVED"
FAILED = "FAILED"
IGNORED = "IGNORED"

STATUSES = (
    DETECTED, INVESTIGATING, WAITING_APPROVAL, REMEDIATING,
    VERIFYING, RESOLVED, FAILED, IGNORED,
)

# An incident in one of these is still happening, and is what deduplication
# looks for. The other three are endings.
OPEN_STATUSES = (DETECTED, INVESTIGATING, WAITING_APPROVAL, REMEDIATING, VERIFYING, FAILED)

TRANSITIONS = {
    DETECTED:         (INVESTIGATING, WAITING_APPROVAL, RESOLVED, IGNORED),
    INVESTIGATING:    (WAITING_APPROVAL, REMEDIATING, RESOLVED, IGNORED, FAILED),
    # INVESTIGATING is in this list because a human saying "no, not that fix"
    # has to lead somewhere. Without it, rejecting a proposal was impossible --
    # the Reject button raised, and the only ways out of WAITING_APPROVAL were
    # to approve, to resolve or to ignore. That is a state machine that pressures
    # the operator into agreeing, which is the opposite of what an approval step
    # is for. Found by test_remediate.py, not by reading the table.
    WAITING_APPROVAL: (INVESTIGATING, REMEDIATING, RESOLVED, IGNORED, FAILED),
    REMEDIATING:      (VERIFYING, FAILED),
    VERIFYING:        (RESOLVED, FAILED),
    # FAILED is not an ending in the way RESOLVED is. Section 26 of the brief
    # requires a failed remediation to leave the incident OPEN with its evidence
    # intact, so a human can pick it up -- hence the routes back out of it.
    FAILED:           (INVESTIGATING, WAITING_APPROVAL, RESOLVED, IGNORED),
    RESOLVED:         (),
    IGNORED:          (),
}

# Timeline entry kinds. Fixed set, so the UI can render each one differently
# and a typo cannot invent a category nothing knows how to draw.
TIMELINE_STATUS = "STATUS"
TIMELINE_EVIDENCE = "EVIDENCE"
TIMELINE_ACTION = "ACTION"
TIMELINE_VERIFY = "VERIFY"
TIMELINE_NOTE = "NOTE"
TIMELINE_KINDS = (
    TIMELINE_STATUS, TIMELINE_EVIDENCE, TIMELINE_ACTION, TIMELINE_VERIFY, TIMELINE_NOTE,
)

CATEGORIES = ("SYSTEM", "PERFORMANCE", "NETWORK", "SERVICE", "PROCESS", "SECURITY")

FALLBACK_TYPE = "metric_anomaly"


class IncidentError(Exception):
    """A refusal by this layer: unknown type, illegal transition, bad registry."""


# ===========================================================================
#  1. THE REGISTRY
# ===========================================================================
def load_registry():
    """Parse incidents.json into {type_id: definition}.

    Documentation keys are stripped with the SAME helper actions.json uses, so
    the two registries cannot drift in how they treat '_comment'. Reusing it is
    the point: one convention, defined once.
    """
    raw = json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
    clean = _strip_docs(raw)
    return {entry["id"]: entry for entry in clean["incidents"]}


TYPES = load_registry()


def _symptom_index():
    """Build {metric_name: type_id} once, at import.

    Correlation happens for every metric on every scan, so the lookup has to be
    a dictionary rather than a walk over every type's symptom list. Built here
    rather than cached lazily because the registry does not change at runtime.
    """
    index = {}
    for type_id, definition in TYPES.items():
        for metric in definition.get("symptoms") or ():
            index[metric] = type_id
    return index


SYMPTOM_OF = _symptom_index()


def check_registry():
    """Report anything structurally wrong with incidents.json.

    THE THIRD CHECK IS THE IMPORTANT ONE. Every id in `recommended_actions` must
    already exist in actions.json. That is what makes it impossible for this
    module to recommend something the action registry has never heard of -- a
    typo, a renamed action, or a hopeful invention would all be caught here, at
    the bench, rather than producing a dead button during a demonstration.

    Run from test_incidents.py, so the registry is verified on every test run.
    """
    problems = []
    known_actions = set(ACTIONS)

    for type_id, definition in TYPES.items():
        for field in ("title", "category", "component", "base_severity", "description"):
            if not definition.get(field):
                problems.append(f"{type_id}: missing {field}")

        if definition.get("category") not in CATEGORIES:
            problems.append(
                f"{type_id}: category {definition.get('category')!r} is not one of {CATEGORIES}"
            )

        try:
            risk.severity_index(definition.get("base_severity"))
        except risk.RiskError as error:
            problems.append(f"{type_id}: {error}")

        impact = definition.get("impact")
        if not isinstance(impact, (int, float)) or not 0 <= impact <= 1:
            problems.append(f"{type_id}: impact must be a number from 0 to 1, got {impact!r}")

        if not isinstance(definition.get("security_relevant"), bool):
            problems.append(f"{type_id}: security_relevant must be true or false")

        for action_id in definition.get("recommended_actions") or ():
            if action_id not in known_actions:
                problems.append(
                    f"{type_id}: recommends {action_id!r}, which is not in actions.json"
                )

        investigate = definition.get("investigate")
        if investigate and investigate not in known_actions:
            problems.append(
                f"{type_id}: investigate names {investigate!r}, which is not in actions.json"
            )
        if investigate and ACTIONS.get(investigate, {}).get("danger") != "read":
            problems.append(
                f"{type_id}: investigate names {investigate!r}, which is not a read-only action"
            )

        primary = definition.get("primary")
        symptoms = definition.get("symptoms") or []
        if symptoms and primary not in symptoms:
            problems.append(f"{type_id}: primary {primary!r} is not in its own symptom list")

    # One metric may only belong to one incident type. If two types claimed the
    # same symptom, which incident a given anomaly joined would depend on
    # dictionary ordering -- a bug that would appear to be random.
    seen = {}
    for type_id, definition in TYPES.items():
        for metric in definition.get("symptoms") or ():
            if metric in seen:
                problems.append(
                    f"metric {metric!r} is claimed by both {seen[metric]} and {type_id}"
                )
            seen[metric] = type_id

    if FALLBACK_TYPE not in TYPES:
        problems.append(f"the fallback type {FALLBACK_TYPE!r} is missing from the registry")

    return problems


# ===========================================================================
#  2. CORRELATION -- four anomalies into one incident
# ===========================================================================
def correlate(findings):
    """Group abnormal findings by the incident type their metric belongs to.

    Takes the `findings` list from guardian_anomaly.scan() and returns one
    candidate per incident type, each carrying every symptom that fired.

    NORMAL AND LEARNING FINDINGS ARE DROPPED HERE, not earlier: the detector's
    job is to describe every metric, and choosing which descriptions amount to
    an incident is this module's job. Keeping the split means the detector can
    be read and tested without knowing incidents exist.

    A metric belonging to no declared type still produces a candidate, under the
    fallback type, named after itself. Nothing is silently discarded -- the
    consequence of an unmapped metric is a low-severity line in the list, which
    is visible, rather than silence, which is not.
    """
    candidates = {}

    for finding in findings:
        if finding.get("verdict") not in ("WARNING", "CRITICAL"):
            continue

        metric = finding["metric"]
        type_id = SYMPTOM_OF.get(metric, FALLBACK_TYPE)
        definition = TYPES[type_id]

        # The fallback groups PER METRIC, not all together: two unrelated
        # unmapped metrics are two unknown things, and merging them into one
        # "unclassified" incident would invent a relationship nobody declared.
        key = type_id if type_id != FALLBACK_TYPE else f"{FALLBACK_TYPE}:{metric}"

        candidate = candidates.setdefault(
            key,
            {
                "type": type_id,
                "component": definition["component"],
                "metric_scope": None if type_id != FALLBACK_TYPE else metric,
                "symptoms": [],
            },
        )
        candidate["symptoms"].append(finding)

    for candidate in candidates.values():
        _summarise(candidate)
    return list(candidates.values())


def _summarise(candidate):
    """Fill in the fields derived from a candidate's symptoms.

    THE WORST SYMPTOM DRIVES THE INCIDENT. Verdict first, then how far out the
    reading was. A CPU incident whose symptoms are one CRITICAL and three
    WARNINGs is a CRITICAL incident, because the machine only has to be broken
    in one way to be broken.

    CONFIDENCE IS THE HIGHEST AMONG THE SYMPTOMS, NOT THE AVERAGE. Averaging
    would let three quiet symptoms talk down one the detector was certain
    about, which is precisely backwards: confidence here means "how sure are we
    that SOMETHING is abnormal", and the surest symptom answers that.
    Symptoms with no confidence at all (the zero-variance case) are skipped
    rather than counted as zero.
    """
    definition = TYPES[candidate["type"]]

    rank = {"CRITICAL": 0, "WARNING": 1}
    candidate["symptoms"].sort(
        key=lambda f: (rank.get(f["verdict"], 2), -abs(f["deviation"]["z_score"] or 0))
    )
    worst = candidate["symptoms"][0]

    confidences = [
        f["confidence"] for f in candidate["symptoms"] if f.get("confidence") is not None
    ]

    candidate["verdict"] = worst["verdict"]
    candidate["primary_metric"] = worst["metric"]
    candidate["confidence"] = max(confidences) if confidences else None
    candidate["title"] = definition["title"]
    if candidate["metric_scope"]:
        candidate["title"] = f"{definition['title']}: {candidate['metric_scope']}"

    candidate["description"] = definition["description"]
    candidate["evidence"] = _evidence(candidate)


def _evidence(candidate):
    """The observed facts, as lines a human can read and a marker can re-check.

    Section 14 of the brief again: this list contains only numbers that came out
    of the database. The interpretation lives in the incident's severity, risk
    and description, never in here.
    """
    lines = []
    for finding in candidate["symptoms"]:
        deviation = finding["deviation"]
        z_score = deviation.get("z_score")
        percent = deviation.get("percent")
        piece = f"{finding['metric']}: {finding['verdict']}"
        if finding["current"]["mean"] is not None:
            piece += f", now {finding['current']['mean']:.2f}"
        if finding["baseline"]["mean"] is not None:
            piece += f" vs baseline {finding['baseline']['mean']:.2f}"
        if z_score is not None:
            piece += f" (z={z_score:+.1f}"
            piece += f", {percent:+.0f}%)" if percent is not None else ")"
        elif percent is not None:
            piece += f" ({percent:+.0f}%)"
        piece += f", trend {finding['trend']['direction']}"
        lines.append(piece)
    return lines


def fingerprint(candidate):
    """The identity used to recognise the same condition on a later scan.

    TYPE PLUS COMPONENT, AND DELIBERATELY NOT THE SYMPTOM LIST. A CPU problem
    that starts with three abnormal metrics and grows to five is still the same
    CPU problem; including the symptoms would make it a different fingerprint
    and open a second incident halfway through the first one.

    It also excludes severity, risk and confidence, for the same reason: those
    all move while an incident is running, and an identity that changes is not
    an identity.
    """
    scope = candidate.get("metric_scope")
    base = f"{candidate['type']}:{candidate['component']}"
    return f"{base}:{scope}" if scope else base


# ===========================================================================
#  3. IDENTIFIERS
# ===========================================================================
def _next_id(connection, now):
    """Allocate INC-YYYYMMDD-NNNN, counting within the day.

    WHY NOT A UUID: this identifier is read aloud, typed into a search box and
    written in a report. "INC-20260816-0003" tells a human when it happened and
    that it was the third that day; a UUID tells them nothing and cannot be
    transcribed reliably.

    The count comes from the table rather than a counter variable, so it
    survives a restart. It is computed inside the caller's transaction, which is
    what stops two incidents opened in the same instant claiming one number.
    """
    day = time.strftime("%Y%m%d", time.localtime(now))
    prefix = f"INC-{day}-"
    row = connection.execute(
        "SELECT COUNT(*) AS n FROM incidents WHERE id LIKE ?", (prefix + "%",)
    ).fetchone()
    return f"{prefix}{row['n'] + 1:04d}"


# ===========================================================================
#  4. THE TIMELINE
# ===========================================================================
def add_timeline(connection, incident_id, kind, message, status=None, detail=None, now=None):
    """Append one entry. Nothing in this project ever updates or deletes one."""
    if kind not in TIMELINE_KINDS:
        raise IncidentError(f"unknown timeline kind {kind!r} -- expected one of {TIMELINE_KINDS}")
    connection.execute(
        """
        INSERT INTO incident_timeline (incident_id, ts, kind, status, message, detail)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            incident_id,
            int(time.time()) if now is None else int(now),
            kind,
            status,
            message,
            json.dumps(detail) if detail is not None else None,
        ),
    )


def timeline(incident_id, connection=None):
    """Every recorded event for one incident, oldest first."""
    owned = connection is None
    connection = connection or store.connect()
    try:
        rows = connection.execute(
            """
            SELECT ts, kind, status, message, detail
              FROM incident_timeline
             WHERE incident_id = ?
             ORDER BY ts ASC, id ASC
            """,
            (incident_id,),
        ).fetchall()
    finally:
        if owned:
            connection.close()

    entries = []
    for row in rows:
        entry = dict(row)
        entry["detail"] = json.loads(row["detail"]) if row["detail"] else None
        entry["ts_human"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["ts"]))
        entries.append(entry)
    return entries


# ===========================================================================
#  5. OPENING AND UPDATING
# ===========================================================================
def _score(candidate, occurrences, previous_occurrences, config=None):
    """Run the risk engine for one candidate. Returns (severity, risk, steps)."""
    definition = TYPES[candidate["type"]]
    severity = risk.assess_severity(
        base=definition["base_severity"],
        verdict=candidate["verdict"],
        confidence=candidate["confidence"],
        occurrences=occurrences,
        security_relevant=definition["security_relevant"],
        config=config,
    )
    scored = risk.assess_risk(
        severity=severity["severity"],
        confidence=candidate["confidence"],
        impact=definition["impact"],
        occurrences=occurrences,
        previous_occurrences=previous_occurrences,
        security_relevant=definition["security_relevant"],
        config=config,
    )
    return severity, scored


def _find_open(connection, print_):
    """The open incident carrying this fingerprint, or None.

    Newest first, though there should only ever be one: the whole point of the
    fingerprint is that a second cannot be opened while the first is open. The
    ORDER BY is there so that if a bug ever did produce two, the behaviour is
    defined rather than arbitrary.
    """
    placeholders = ",".join("?" for _ in OPEN_STATUSES)
    return connection.execute(
        f"""
        SELECT * FROM incidents
         WHERE fingerprint = ? AND status IN ({placeholders})
         ORDER BY created_at DESC
         LIMIT 1
        """,
        (print_, *OPEN_STATUSES),
    ).fetchone()


def _count_resolved(connection, print_):
    """How many times this exact condition has happened before and ended.

    This is the `recurrence` factor in the risk score. A problem that has been
    resolved four times and is back for a fifth is a different situation from
    one that has never been seen, even though the two look identical right now.
    """
    row = connection.execute(
        "SELECT COUNT(*) AS n FROM incidents WHERE fingerprint = ? AND status = ?",
        (print_, RESOLVED),
    ).fetchone()
    return row["n"]


def record(candidate, connection=None, now=None, config=None):
    """Open a new incident for this candidate, or update the open one.

    THE WHOLE OF DEDUPLICATION IS THE `if existing` BELOW, and it is what makes
    the difference between a usable incident list and a scrolling wall. Without
    it, a CPU problem lasting an hour produces 120 rows at DAEMON_INTERVAL=30.

    An update is not a no-op. Each one:
      - increments the occurrence count, which feeds persistence, which is what
        escalates a nuisance into something worth waking up for;
      - re-scores severity and risk from scratch rather than adjusting the old
        values, so the numbers always describe the evidence as it stands now;
      - replaces the evidence with the current readings;
      - appends to the timeline ONLY when something a human would notice has
        actually changed. An unchanged incident ticking every thirty seconds
        must not write 120 identical timeline entries -- that would make the
        timeline as unreadable as the list this deduplication exists to fix.
    """
    print_ = fingerprint(candidate)
    owned = connection is None
    connection = connection or store.connect()
    now = int(time.time()) if now is None else int(now)

    try:
        with connection:
            existing = _find_open(connection, print_)
            previous = _count_resolved(connection, print_)

            occurrences = (existing["occurrences"] + 1) if existing else 1
            severity, scored = _score(candidate, occurrences, previous, config=config)

            detail = {
                "symptoms": [
                    {
                        "metric": f["metric"],
                        "verdict": f["verdict"],
                        "z_score": f["deviation"]["z_score"],
                        "percent": f["deviation"]["percent"],
                        "current": f["current"]["mean"],
                        "baseline": f["baseline"]["mean"],
                        "trend": f["trend"]["direction"],
                        "confidence": f.get("confidence"),
                    }
                    for f in candidate["symptoms"]
                ],
                "severity_steps": severity["steps"],
                "risk": scored,
                "recommended_actions": TYPES[candidate["type"]].get("recommended_actions") or [],
                "investigate": TYPES[candidate["type"]].get("investigate"),
            }
            symptom_names = [f["metric"] for f in candidate["symptoms"]]

            if existing is None:
                incident_id = _next_id(connection, now)
                connection.execute(
                    """
                    INSERT INTO incidents
                        (id, fingerprint, type, title, category, component, status,
                         severity, risk_score, risk_level, confidence, occurrences,
                         created_at, updated_at, description, symptoms, evidence, detail)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id, print_, candidate["type"], candidate["title"],
                        TYPES[candidate["type"]]["category"], candidate["component"],
                        DETECTED, severity["severity"], scored["score"], scored["level"],
                        candidate["confidence"], 1, now, now,
                        candidate["description"], json.dumps(symptom_names),
                        json.dumps(candidate["evidence"]), json.dumps(detail),
                    ),
                )
                add_timeline(
                    connection, incident_id, TIMELINE_STATUS,
                    f"{candidate['title']} detected: "
                    f"{len(symptom_names)} abnormal metric(s) -- "
                    f"{', '.join(symptom_names)}",
                    status=DETECTED, now=now,
                )
                add_timeline(
                    connection, incident_id, TIMELINE_EVIDENCE,
                    f"severity {severity['severity']}, risk {scored['score']} "
                    f"({scored['level']})",
                    detail={"evidence": candidate["evidence"], "severity_steps": severity["steps"]},
                    now=now,
                )
                return {"incident_id": incident_id, "created": True, "occurrences": 1,
                        "severity": severity["severity"], "risk": scored}

            incident_id = existing["id"]

            # THE SYMPTOM LIST IS CUMULATIVE, NOT A SNAPSHOT -- and getting this
            # wrong produced a genuinely misleading record in the first live run
            # of Phase 8. A CPU incident opened on cpu_idle_ticks and
            # processes_running, ran for six observations, and finished with
            # `symptoms: load_5min` -- because each update overwrote the list
            # with whatever was still abnormal at that instant, and the last
            # instant of a recovering incident is the least informative one
            # there is. Anyone reading the closed incident would have been told
            # the wrong story about what had happened.
            #
            # So the stored list is the UNION over the incident's whole life:
            # every metric that was ever part of this condition. `evidence` and
            # `detail` still hold the CURRENT readings, so nothing is lost --
            # the two fields now answer two different questions, "what has this
            # involved" and "what does it look like right now".
            #
            # sorted(set(...)) because the order symptoms arrive in is the
            # detector's ranking at one moment, which would reshuffle on every
            # tick and make the `changed` test below fire constantly.
            previous_symptoms = json.loads(existing["symptoms"] or "[]")
            all_symptoms = sorted(set(previous_symptoms) | set(symptom_names))

            # THE SAME MISTAKE, ONE FIELD ACROSS -- and this one cost the user
            # the analysis they had just asked for. `detail` above is built
            # fresh from THIS observation, and writing it whole discarded every
            # key an observation does not produce. guardian_rootcause.analyse()
            # stores its findings at detail["root_cause"]; the next tick, thirty
            # seconds later, deleted them. The symptom that reached a person was
            # "I pressed Investigate, read the analysis, and by the time I
            # looked again the panel was empty".
            #
            # An observation OWNS the keys it recomputes -- the current symptom
            # readings, the severity working, the risk breakdown, the registry's
            # recommendations -- and those are refreshed. Everything else on the
            # record was put there by something that knew more than a periodic
            # sample does, and is kept. Merging in this direction (start from
            # what is stored, overlay what is fresh) is the safe one: a new key
            # added by a future phase survives without anybody remembering to
            # list it here.
            stored_detail = json.loads(existing["detail"] or "{}")
            detail = {**stored_detail, **detail}

            # What a human would call a change. Occurrence count is deliberately
            # excluded: it moves every single tick and would defeat the check.
            # A symptom being ADDED is news; one going quiet is not, because a
            # condition shedding symptoms as it recovers is the normal path to
            # resolution and does not need a line of its own.
            changed = (
                existing["severity"] != severity["severity"]
                or existing["risk_level"] != scored["level"]
                or set(all_symptoms) != set(previous_symptoms)
            )
            connection.execute(
                """
                UPDATE incidents
                   SET severity = ?, risk_score = ?, risk_level = ?, confidence = ?,
                       occurrences = ?, updated_at = ?, symptoms = ?, evidence = ?, detail = ?
                 WHERE id = ?
                """,
                (
                    severity["severity"], scored["score"], scored["level"],
                    candidate["confidence"], occurrences, now,
                    json.dumps(all_symptoms), json.dumps(candidate["evidence"]),
                    json.dumps(detail), incident_id,
                ),
            )
            if changed:
                appeared = sorted(set(all_symptoms) - set(previous_symptoms))
                note = (
                    f"still present after {occurrences} observations; "
                    f"severity {existing['severity']} -> {severity['severity']}, "
                    f"risk {existing['risk_score']} -> {scored['score']} ({scored['level']})"
                )
                if appeared:
                    note += f"; spread to {', '.join(appeared)}"
                add_timeline(
                    connection, incident_id, TIMELINE_EVIDENCE, note,
                    detail={"evidence": candidate["evidence"],
                            "severity_steps": severity["steps"],
                            "currently_abnormal": symptom_names},
                    now=now,
                )
            return {"incident_id": incident_id, "created": False, "occurrences": occurrences,
                    "severity": severity["severity"], "risk": scored, "changed": changed}
    finally:
        if owned:
            connection.close()


# ===========================================================================
#  6. THE STATE MACHINE
# ===========================================================================
def transition(incident_id, to_status, message, kind=TIMELINE_STATUS,
               detail=None, connection=None, now=None):
    """Move an incident to a new status, refusing any illegal move.

    THE REFUSAL IS THE FEATURE. Every route through the lifecycle is declared in
    TRANSITIONS, and a move that is not there raises instead of being stored.
    In particular REMEDIATING can only reach RESOLVED through VERIFYING, which
    puts section 25 of the brief -- never trust an exit code as proof of success
    -- into the data model rather than into a comment.
    """
    if to_status not in STATUSES:
        raise IncidentError(f"unknown status {to_status!r} -- expected one of {STATUSES}")

    owned = connection is None
    connection = connection or store.connect()
    now = int(time.time()) if now is None else int(now)
    try:
        with connection:
            row = connection.execute(
                "SELECT status FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if row is None:
                raise IncidentError(f"no such incident: {incident_id}")

            current = row["status"]
            if to_status == current:
                raise IncidentError(f"{incident_id} is already {current}")
            if to_status not in TRANSITIONS[current]:
                raise IncidentError(
                    f"{incident_id}: {current} -> {to_status} is not a legal transition "
                    f"(from {current} you may go to {', '.join(TRANSITIONS[current]) or 'nowhere'})"
                )

            resolved_at = now if to_status in (RESOLVED, IGNORED) else None
            connection.execute(
                "UPDATE incidents SET status = ?, updated_at = ?, resolved_at = ? WHERE id = ?",
                (to_status, now, resolved_at, incident_id),
            )
            add_timeline(connection, incident_id, kind, message,
                         status=to_status, detail=detail, now=now)
    finally:
        if owned:
            connection.close()

    return {"incident_id": incident_id, "from": current, "to": to_status}


# ===========================================================================
#  7. AUTOMATIC RESOLUTION
# ===========================================================================
def close_recovered(active_fingerprints, connection=None, now=None):
    """Resolve open incidents whose condition is no longer being observed.

    An incident that opened because CPU went abnormal must close when CPU comes
    back to normal, or the list only ever grows and every demo ends with forty
    stale rows.

    IT ONLY CLOSES INCIDENTS THAT NOTHING TOUCHED. An incident that reached
    WAITING_APPROVAL, REMEDIATING, VERIFYING or FAILED has a human or an action
    involved in it, and quietly resolving one of those from underneath them
    would destroy the record of what was being done. Only DETECTED and
    INVESTIGATING -- the states nobody has acted on yet -- resolve themselves,
    and the timeline says plainly that the metric recovered on its own rather
    than that anything fixed it.
    """
    owned = connection is None
    connection = connection or store.connect()
    now = int(time.time()) if now is None else int(now)
    closed = []
    try:
        rows = connection.execute(
            "SELECT id, fingerprint, title, occurrences FROM incidents WHERE status IN (?, ?)",
            (DETECTED, INVESTIGATING),
        ).fetchall()
        for row in rows:
            if row["fingerprint"] in active_fingerprints:
                continue
            transition(
                row["id"], RESOLVED,
                f"the metrics returned to their normal range on their own after "
                f"{row['occurrences']} observation(s); no action was taken",
                connection=connection, now=now,
            )
            closed.append(row["id"])
    finally:
        if owned:
            connection.close()
    return closed


# ===========================================================================
#  8. THE ONE CALL THE DAEMON MAKES
# ===========================================================================
def process(report, connection=None, now=None, config=None):
    """Turn one anomaly scan into incidents: open, update and auto-resolve.

    This is the whole Phase 8 pipeline in one function, and the order matters:
    incidents are recorded FIRST and recovered ones closed SECOND, using the
    fingerprints just recorded. Closing first would resolve an incident and then
    immediately reopen it under a new id every time a metric wobbled across the
    threshold -- the same duplication problem, wearing a different hat.
    """
    owned = connection is None
    connection = connection or store.connect()
    now = int(time.time()) if now is None else int(now)
    try:
        candidates = correlate(report.get("findings") or [])
        results = [record(c, connection=connection, now=now, config=config) for c in candidates]
        active = {fingerprint(c) for c in candidates}
        closed = close_recovered(active, connection=connection, now=now)
    finally:
        if owned:
            connection.close()

    return {
        "opened": [r["incident_id"] for r in results if r["created"]],
        "updated": [r["incident_id"] for r in results if not r["created"]],
        "resolved": closed,
        "active_incidents": len(results),
    }


# ===========================================================================
#  9. READING
# ===========================================================================
def _inflate(row):
    """Turn one database row into the shape the API and templates expect."""
    incident = dict(row)
    for field in ("symptoms", "evidence", "detail"):
        incident[field] = json.loads(row[field]) if row[field] else None
    for field, label in (("created_at", "created_human"), ("updated_at", "updated_human")):
        incident[label] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[field]))
    incident["open"] = row["status"] in OPEN_STATUSES
    return incident


def get(incident_id, connection=None):
    """One incident, with its full timeline attached."""
    owned = connection is None
    connection = connection or store.connect()
    try:
        row = connection.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            raise IncidentError(f"no such incident: {incident_id}")
        incident = _inflate(row)
        incident["timeline"] = timeline(incident_id, connection=connection)
    finally:
        if owned:
            connection.close()
    return incident


def listing(status=None, limit=50, connection=None):
    """Recent incidents, newest first, optionally filtered by status.

    `status` accepts the literal word "open", which expands to the open states.
    Anything else is checked against STATUSES before it goes near the query --
    not because a bound parameter could inject anything, but because a typo
    silently returning zero rows is a worse outcome than an error that names it.
    """
    owned = connection is None
    connection = connection or store.connect()
    try:
        limit = max(1, min(int(limit), 500))
        if status is None:
            rows = connection.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        elif status == "open":
            placeholders = ",".join("?" for _ in OPEN_STATUSES)
            rows = connection.execute(
                f"SELECT * FROM incidents WHERE status IN ({placeholders}) "
                f"ORDER BY created_at DESC LIMIT ?",
                (*OPEN_STATUSES, limit),
            ).fetchall()
        else:
            if status not in STATUSES:
                raise IncidentError(
                    f"unknown status {status!r} -- expected 'open' or one of {STATUSES}"
                )
            rows = connection.execute(
                "SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
    finally:
        if owned:
            connection.close()
    return [_inflate(row) for row in rows]


def summary(connection=None):
    """Counts by status and severity, for the dashboard's headline numbers."""
    owned = connection is None
    connection = connection or store.connect()
    try:
        by_status = {
            row["status"]: row["n"]
            for row in connection.execute(
                "SELECT status, COUNT(*) AS n FROM incidents GROUP BY status"
            )
        }
        placeholders = ",".join("?" for _ in OPEN_STATUSES)
        by_severity = {
            row["severity"]: row["n"]
            for row in connection.execute(
                f"SELECT severity, COUNT(*) AS n FROM incidents "
                f"WHERE status IN ({placeholders}) GROUP BY severity",
                OPEN_STATUSES,
            )
        }
        worst = connection.execute(
            f"SELECT MAX(risk_score) AS r FROM incidents WHERE status IN ({placeholders})",
            OPEN_STATUSES,
        ).fetchone()["r"]
    finally:
        if owned:
            connection.close()

    return {
        "by_status": {status: by_status.get(status, 0) for status in STATUSES},
        "open_by_severity": {name: by_severity.get(name, 0) for name in risk.SEVERITIES},
        "open": sum(by_status.get(status, 0) for status in OPEN_STATUSES),
        "highest_open_risk": worst,
    }


# ===========================================================================
#  10. COMMAND LINE
# ===========================================================================
_USAGE = ("scan | list [open|STATUS] | show <id> | summary | "
          "transition <id> <STATUS> <message> | registry")


def _emit(payload, exit_code=0):
    print(json.dumps(payload, indent=2, default=float))
    sys.exit(exit_code)


def main(argv):
    """Dispatch one subcommand, matched against a fixed set of literals."""
    if not argv:
        _emit({"module": "incidents", "status": "error", "message": f"usage: {_USAGE}"}, 2)

    command, arguments = argv[0], argv[1:]
    try:
        if command == "scan":
            # Imported here rather than at the top of the file so that the
            # incident engine can be used -- and tested -- without pulling in
            # the detector. The two are separable on purpose.
            import guardian_anomaly

            result = process(guardian_anomaly.scan())
        elif command == "list":
            result = {"incidents": listing(arguments[0] if arguments else None)}
        elif command == "summary":
            result = summary()
        elif command == "registry":
            problems = check_registry()
            result = {"types": sorted(TYPES), "problems": problems}
        elif command == "show":
            if not arguments:
                raise IncidentError("show needs an incident id")
            result = get(arguments[0])
        elif command == "transition":
            if len(arguments) < 3:
                raise IncidentError("transition needs <id> <STATUS> <message>")
            result = transition(arguments[0], arguments[1], " ".join(arguments[2:]))
        else:
            raise IncidentError(f"unknown command {command!r} -- usage: {_USAGE}")
    except (IncidentError, risk.RiskError, store.StoreError) as error:
        _emit({"module": "incidents", "status": "error", "message": str(error)}, 1)
    except (OSError, json.JSONDecodeError) as error:
        _emit(
            {
                "module": "incidents",
                "status": "error",
                "message": f"{type(error).__name__}: {error}",
            },
            1,
        )

    result["module"] = "incidents"
    result["status"] = "ok"
    _emit(result)


if __name__ == "__main__":
    main(sys.argv[1:])
