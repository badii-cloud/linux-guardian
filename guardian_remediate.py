#!/usr/bin/env python3
"""
Linux Guardian -- guardian_remediate.py                     (Phase 8, step 2)

FROM A RECOMMENDATION TO A VERIFIED FIX -- with a human in the middle.

An incident can now say what is wrong and why. This is the module that lets
something be done about it, and every line of it is about making sure that
"something" is small, chosen in advance, approved by a person, and checked
afterwards.

    incident  ->  propose()   what could be done, and what it would cost
                      |            (the incident becomes WAITING_APPROVAL)
                      v
                  a human presses APPROVE
                      |
                      v
                  approve()   re-validate EVERYTHING from scratch
                      |            -> REMEDIATING -> execute
                      v
                  verify()    re-measure, independently
                      |            -> VERIFYING -> RESOLVED or FAILED
                      v
                  before / after

WHERE THE AUTHORITY ACTUALLY LIVES  (and it is not here)
--------------------------------------------------------
This module chooses NOTHING. Three separate registries decide what is possible
and it merely walks between them:

  linux/incidents.json   which actions this incident type may recommend
  linux/actions.json     what those actions are, and what parameters are legal
  guardian.conf          which services healing.sh will touch at all

THE REQUEST BODY CANNOT INTRODUCE AN ACTION OR A PARAMETER. approve() accepts an
action id, checks it against the incident's OWN recommended list, and then
derives every parameter server-side from the incident record. A forged POST can
therefore pick between "restart apache2" and "restart apache2" -- there is no
third option to smuggle in, because there is no path from the request to a
parameter value.

That is the same shape Phase 6 used for the language model, and for the same
reason: the thing making the suggestion is never the thing granting permission.

SECTION 25 -- NEVER TRUST AN EXIT CODE
--------------------------------------
`systemctl start` returns as soon as systemd considers the unit activated. A
service can fail a moment later while parsing its own configuration, and the
exit code will still be 0. So execution and verification are two separate steps
with the state machine between them: REMEDIATING can only reach RESOLVED through
VERIFYING, and verify() re-measures rather than re-reading what execute() said.
"""

import json
import sys
import time

import guardian_actions as actions
import guardian_incidents as incidents
import guardian_risk as risk
import guardian_store as store

# How long to wait after an action before verifying it. `systemctl start`
# returns early, so measuring immediately would measure the moment before the
# service had a chance to fail. healing.sh already retries internally; this is
# the extra pause before the INDEPENDENT check.
VERIFY_DELAY_SECONDS = 2


class RemediationError(Exception):
    """A refusal by this layer: nothing to do, wrong state, action not permitted."""


# ===========================================================================
#  1. WHAT COULD BE DONE
# ===========================================================================
def _writable_recommendations(incident):
    """The recommended actions for this incident that actually change something.

    An incident type recommends a mix of read and write actions -- "look at the
    processes" alongside "restart the service". Only the write ones are
    remediation; the read ones are investigation and have already happened.
    """
    definition = incidents.TYPES.get(incident["type"]) or {}
    return [
        action_id
        for action_id in (definition.get("recommended_actions") or [])
        if actions.ACTIONS.get(action_id, {}).get("danger") == "write"
    ]


def _parameters_for(incident, action_id):
    """Derive an action's parameters from the incident. Never from a request.

    THIS FUNCTION IS THE REASON A FORGED POST GAINS NOTHING. The caller supplies
    an action id and nothing else; every value that will reach a command line is
    worked out here, from the incident record and the config.

    For heal_service the service name comes from the root-cause analysis --
    which unit was found to be down -- intersected with HEALABLE_SERVICES. If
    the analysis has not run, or the down unit is not on the allow-list, the
    answer is "no parameters can be derived", and the remediation is refused
    rather than being run against a guess.
    """
    specification = actions.ACTIONS[action_id]["params"]
    if not specification:
        return {}

    names = {spec["name"] for spec in specification}
    if names == {"service"}:
        cause = ((incident.get("detail") or {}).get("root_cause") or {}).get("primary_cause") or {}
        units = cause.get("units") or []
        healable = set(actions.config_words("HEALABLE_SERVICES"))
        candidates = [unit for unit in units if unit in healable]
        if not candidates:
            raise RemediationError(
                "no healable service was identified -- run the investigation first, "
                "and note that Guardian may only restart services in HEALABLE_SERVICES"
            )
        # One at a time, deliberately. A button that restarts three services is a
        # button whose consequences a person cannot picture before pressing it.
        return {"service": candidates[0]}

    raise RemediationError(
        f"{action_id} needs parameters that cannot be derived from this incident"
    )


def propose(incident_id, connection=None, now=None):
    """Work out what could be done and put the incident in front of a human.

    Returns a PREVIEW -- section 24 of the brief -- and the preview is not
    authorisation. It moves the incident to WAITING_APPROVAL and stops. Nothing
    has run when this returns.
    """
    owned = connection is None
    connection = connection or store.connect()
    now = int(time.time()) if now is None else int(now)
    try:
        incident = incidents.get(incident_id, connection=connection)

        if incident["status"] not in (incidents.DETECTED, incidents.INVESTIGATING,
                                      incidents.FAILED):
            raise RemediationError(
                f"{incident_id} is {incident['status']}; a remediation can only be "
                f"proposed for an incident that is detected, under investigation, or failed"
            )

        candidates = _writable_recommendations(incident)
        if not candidates:
            raise RemediationError(
                f"{incident['type']} has no remediation Guardian is permitted to "
                f"perform -- this incident needs a human"
            )

        action_id = candidates[0]
        parameters = _parameters_for(incident, action_id)
        validation = actions.validate(action_id, parameters)
        if not validation.ok:
            raise RemediationError(f"the registry refused {action_id}: {validation.message}")

        # The action's own risk, which is NOT the incident's risk. Restarting
        # apache2 is a MEDIUM-risk act whether the incident that prompted it is
        # a nuisance or a disaster, and conflating the two would let a scary
        # incident talk a person into a scarier action than they agreed to.
        action_risk = _action_risk(validation)

        preview = {
            "incident_id": incident_id,
            "action": action_id,
            "description": validation.action["description"],
            "parameters": parameters,
            "effect": actions.describe_effect(validation),
            "risk": action_risk,
            "reason": incident["title"] + " -- " + (incident["description"] or ""),
            "expected": _expected_result(action_id, parameters),
            "alternatives": candidates[1:],
        }

        if incident["status"] != incidents.WAITING_APPROVAL:
            incidents.transition(
                incident_id, incidents.WAITING_APPROVAL,
                f"remediation proposed: {action_id} "
                f"{json.dumps(parameters) if parameters else ''} "
                f"(risk {action_risk['level']}) -- waiting for a human",
                detail=preview, connection=connection, now=now,
            )
        return preview
    finally:
        if owned:
            connection.close()


def _action_risk(validation):
    """Score the ACT, not the incident.

    Read actions are LOW by construction: they cannot change anything. A write
    action's severity comes from what it touches, and a service restart is a
    visible interruption, so it is graded MEDIUM rather than LOW even though it
    is the safest write this project has.
    """
    if validation.action["danger"] == "read":
        return risk.assess_risk(severity="INFO", confidence=1.0, impact=0.0)
    return risk.assess_risk(
        severity=risk.MEDIUM,
        confidence=1.0,
        impact=0.6,
        occurrences=1,
    )


def _expected_result(action_id, parameters):
    """One sentence saying what success will look like, written BEFORE the act.

    Writing the expectation down first is what makes verification meaningful.
    An expectation invented afterwards is just a description of whatever
    happened, and it can never fail.
    """
    if action_id == "heal_service":
        return f"{parameters.get('service')} is active and running"
    return "the action completes and the incident's condition clears"


# ===========================================================================
#  2. APPROVAL AND EXECUTION
# ===========================================================================
def approve(incident_id, action_id, connection=None, now=None, operator="web"):
    """Execute an approved remediation, then verify it independently.

    EVERYTHING IS RE-VALIDATED FROM SCRATCH. The preview produced by propose()
    is not carried forward and is not trusted -- it was a description shown to a
    human, not a token granting permission. This function re-reads the incident,
    re-derives the parameters, re-checks the action against the incident's
    recommended list and re-runs the registry validator. Forging the approval
    POST therefore gains nothing that pressing the button would not.
    """
    owned = connection is None
    connection = connection or store.connect()
    now = int(time.time()) if now is None else int(now)
    try:
        incident = incidents.get(incident_id, connection=connection)
        if incident["status"] != incidents.WAITING_APPROVAL:
            raise RemediationError(
                f"{incident_id} is {incident['status']}, not {incidents.WAITING_APPROVAL}; "
                f"an approval must follow a proposal"
            )

        # CHECK 1: the action must be one THIS incident type recommends. An id
        # from another incident's list, or one invented entirely, stops here.
        permitted = _writable_recommendations(incident)
        if action_id not in permitted:
            _refuse(connection, incident_id,
                    f"refused {action_id}: not a permitted remediation for "
                    f"{incident['type']} (permitted: {', '.join(permitted) or 'none'})", now)
            raise RemediationError(
                f"{action_id} is not a permitted remediation for {incident['type']}"
            )

        # CHECK 2: parameters are derived here, never accepted.
        parameters = _parameters_for(incident, action_id)

        # CHECK 3: the registry validator, the same one the console uses.
        validation = actions.validate(action_id, parameters)
        if not validation.ok:
            _refuse(connection, incident_id,
                    f"refused {action_id}: {validation.message}", now)
            raise RemediationError(f"the registry refused {action_id}: {validation.message}")

        before = _snapshot(incident, connection)

        incidents.transition(
            incident_id, incidents.REMEDIATING,
            f"approved by {operator}: running {action_id} "
            f"{json.dumps(parameters) if parameters else ''}",
            kind=incidents.TIMELINE_ACTION,
            detail={"action": action_id, "parameters": parameters, "operator": operator},
            connection=connection, now=now,
        )

        # CHECK 4, and it is not ours: healing.sh re-applies PROTECTED_SERVICES,
        # HEALABLE_SERVICES and its own character allow-list before it touches
        # anything. Four independent checks, none of which trusts the others.
        outcome = actions.execute(validation)

        incidents.add_timeline(
            connection, incident_id, incidents.TIMELINE_ACTION,
            f"{action_id} finished: {outcome.get('status')}",
            detail=outcome, now=now,
        )
        connection.commit()

        return verify(incident_id, action_id, parameters, before, outcome,
                      connection=connection, now=now)
    finally:
        if owned:
            connection.close()


def _refuse(connection, incident_id, message, now):
    """Record a refusal on the incident's timeline.

    A REFUSAL IS EVIDENCE, not an error to discard -- the same principle the
    project applies to healing.sh and to the console. Someone attempting an
    action that is not permitted is exactly the event a security-minded operator
    wants to find later, so it is written down before the exception is raised.
    """
    incidents.add_timeline(
        connection, incident_id, incidents.TIMELINE_ACTION, message, now=now
    )
    connection.commit()


# ===========================================================================
#  3. VERIFICATION -- section 25
# ===========================================================================
def _snapshot(incident, connection):
    """The state worth comparing before and after. Section 28 of the brief.

    Deliberately small and cheap: the overall health score, and the current
    value of each of the incident's symptoms. A full diagnosis sweep costs 3.25
    seconds and would be run twice, adding seven seconds to every remediation
    for numbers nobody reads.
    """
    values = {}
    for symptom in (incident.get("symptoms") or []):
        try:
            latest = store.latest(symptom, connection=connection)
        except store.StoreError:
            continue
        if latest:
            values[symptom] = latest["value"]
    return {
        "at": int(time.time()),
        "status": incident["status"],
        "severity": incident["severity"],
        "risk_score": incident["risk_score"],
        "metrics": values,
    }


def verify(incident_id, action_id, parameters, before, outcome,
           connection=None, now=None):
    """Re-measure, and decide whether the remediation actually worked.

    IT DOES NOT LOOK AT THE EXIT CODE. `outcome` is recorded for the audit
    trail, but the decision below comes from a fresh reading taken through the
    registry's own read-only action. An action that reported success and left
    the service dead must fail here, and that is the entire point of the step.
    """
    owned = connection is None
    connection = connection or store.connect()
    now = int(time.time()) if now is None else int(now)
    try:
        incidents.transition(
            incident_id, incidents.VERIFYING,
            f"re-measuring to confirm {action_id} actually worked",
            kind=incidents.TIMELINE_VERIFY, connection=connection, now=now,
        )

        # The pause is the honest part: systemctl returns before a service has
        # finished proving it can stay up.
        time.sleep(VERIFY_DELAY_SECONDS)

        checks, succeeded = _run_checks(action_id, parameters)
        incident = incidents.get(incident_id, connection=connection)
        after = _snapshot(incident, connection)

        comparison = {
            "before": before,
            "after": after,
            "checks": checks,
            "action": action_id,
            "parameters": parameters,
            "exit_status": outcome.get("status"),
        }

        if succeeded:
            incidents.transition(
                incident_id, incidents.RESOLVED,
                "verified: " + "; ".join(c["message"] for c in checks if c["ok"]),
                kind=incidents.TIMELINE_VERIFY, detail=comparison,
                connection=connection, now=now,
            )
        else:
            # SECTION 26: the incident stays OPEN and no retry is attempted.
            # Automatically repeating a remediation that has just failed is how
            # a monitoring system turns one broken service into a restart loop.
            incidents.transition(
                incident_id, incidents.FAILED,
                "verification FAILED: "
                + "; ".join(c["message"] for c in checks if not c["ok"])
                + " -- the incident stays open and no retry will be attempted",
                kind=incidents.TIMELINE_VERIFY, detail=comparison,
                connection=connection, now=now,
            )

        with connection:
            detail = incident.get("detail") or {}
            detail["remediation"] = comparison
            connection.execute(
                "UPDATE incidents SET detail = ?, updated_at = ? WHERE id = ?",
                (json.dumps(detail), now, incident_id),
            )

        comparison["incident_id"] = incident_id
        comparison["verified"] = succeeded
        return comparison
    finally:
        if owned:
            connection.close()


def _run_checks(action_id, parameters):
    """The independent measurements. Returns (checks, all_passed).

    Each check is a fresh read through the action registry -- not a re-read of
    what the remediation reported. For a service restart the question is simply
    "is it running now", asked of systemd rather than of the script that claimed
    to have started it.
    """
    checks = []

    if action_id == "heal_service":
        service = parameters.get("service")
        validation = actions.validate("check_service", {"service": service})
        if not validation.ok:
            checks.append({"ok": False, "message": f"could not re-check {service}"})
            return checks, False

        result = actions.execute(validation)
        data = result.get("data")
        if isinstance(data, list):
            data = data[0] if data else {}
        data = data or {}

        running = bool(data.get("running"))
        checks.append({
            "ok": running,
            "message": (f"{service} is {data.get('active_state')}/{data.get('sub_state')}"
                        if data else f"{service} could not be read"),
        })
        checks.append({
            "ok": data.get("main_pid") is not None,
            "message": (f"{service} has a running process (pid {data.get('main_pid')})"
                        if data.get("main_pid") else f"{service} has no main process"),
        })
        return checks, all(c["ok"] for c in checks)

    checks.append({
        "ok": False,
        "message": f"no verification is written for {action_id}, so success cannot be confirmed",
    })
    return checks, False


def reject(incident_id, reason="rejected by the operator", connection=None, now=None):
    """Decline a proposed remediation and hand the incident back for investigation."""
    return incidents.transition(
        incident_id, incidents.INVESTIGATING,
        f"remediation rejected: {reason}",
        kind=incidents.TIMELINE_ACTION, connection=connection, now=now,
    )


# ===========================================================================
#  4. COMMAND LINE
# ===========================================================================
_USAGE = "propose <id> | approve <id> <action> | reject <id> [reason]"


def _emit(payload, exit_code=0):
    print(json.dumps(payload, indent=2, default=float))
    sys.exit(exit_code)


def main(argv):
    if not argv:
        _emit({"module": "remediate", "status": "error", "message": f"usage: {_USAGE}"}, 2)

    command, arguments = argv[0], argv[1:]
    try:
        if command == "propose":
            if not arguments:
                raise RemediationError("propose needs an incident id")
            result = propose(arguments[0])
        elif command == "approve":
            if len(arguments) < 2:
                raise RemediationError("approve needs <incident-id> <action-id>")
            result = approve(arguments[0], arguments[1], operator="cli")
        elif command == "reject":
            if not arguments:
                raise RemediationError("reject needs an incident id")
            result = reject(arguments[0], " ".join(arguments[1:]) or "rejected from the cli")
        else:
            raise RemediationError(f"unknown command {command!r} -- usage: {_USAGE}")
    except (RemediationError, incidents.IncidentError, store.StoreError) as error:
        _emit({"module": "remediate", "status": "error", "message": str(error)}, 1)

    result["module"] = "remediate"
    result["status"] = "ok"
    _emit(result)


if __name__ == "__main__":
    main(sys.argv[1:])
