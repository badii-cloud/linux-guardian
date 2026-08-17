#!/usr/bin/env python3
"""
Linux Guardian -- guardian_rootcause.py                     (Phase 8, step 2)

WHY IS THIS HAPPENING? -- the question an incident cannot answer on its own.

Phase 8 step 1 can say:

    CPU saturation, HIGH, risk 65, six symptoms, rising

which is a complete and accurate description of a problem, and tells nobody
what to do about it. Section 14 of the brief asks for the next sentence:

    the dominant contributor is PID 2134 (stress-ng), using 79% of one core;
    it accounts for most of the change, and it is the thing to look at.

THE THREE KINDS OF STATEMENT, KEPT APART  (brief sections 14 and 39)
--------------------------------------------------------------------
This is the rule the whole file is built around, and mixing them is the failure
this project is trying hardest to avoid:

    FACT            a number that was measured. "PID 2134 is at 79% of a core."
    INFERENCE       what we think it means, with a stated confidence.
                    "PID 2134 is the dominant contributor."
    RECOMMENDATION  what a human might do. "Investigate PID 2134."

They are three separate lists in the output, never one paragraph. A reader must
always be able to see which parts were measured and which parts were reasoned,
because the reasoning is the part that can be wrong.

NOTHING HERE EXECUTES ANYTHING NEW
-----------------------------------
Evidence is gathered by running the `investigate` action named in
linux/incidents.json -- through guardian_actions.validate() and execute(), the
exact path the web console uses. check_registry() already guarantees that
action exists and is `danger: "read"`, so investigation cannot change the
machine even if this file wanted it to.

There is no subprocess call in this module. There is no command string. The
only thing this file contributes is the interpretation.
"""

import json
import sys
import time

import guardian_actions as actions
import guardian_incidents as incidents
import guardian_store as store

# How much of the observed total one process must account for before it is
# called dominant rather than merely the largest. Below this, the honest answer
# is "no single process explains it", which is a real and common finding: a
# machine can be busy because forty things are each a little busy.
DOMINANCE_SHARE = 0.5

# Confidence is capped here, and the cap is the point. A root cause is an
# INFERENCE drawn from one reading taken after the fact -- never a proof. A
# module that reported 100% confidence in a cause would be claiming something no
# amount of evidence in this project can support.
MAX_CONFIDENCE = 0.95


class RootCauseError(Exception):
    """A refusal by this layer: unknown incident, no investigation available."""


# ===========================================================================
#  1. GATHERING EVIDENCE
# ===========================================================================
def _investigation_parameters(action_id, incident):
    """What to pass to the investigation action, if it needs anything.

    Most read actions take nothing. `check_service` is the exception: it names
    ONE service, because services.sh reports on all of them and the registry
    filters the answer down. The name comes from MONITORED_SERVICES in
    guardian.conf, never from the incident text -- an incident about
    `failed_units` knows a count, not a unit name, and inventing one from a
    metric would be exactly the kind of guess this module exists to avoid.

    Returns a list of parameter dicts, because one investigation may legitimately
    need to be run several times -- once per monitored service here.
    """
    specification = actions.ACTIONS[action_id]["params"]
    if not specification:
        return [{}]

    names = {spec["name"] for spec in specification}
    if names == {"service"}:
        monitored = actions.config_words("MONITORED_SERVICES")
        return [{"service": name} for name in monitored] or [{}]

    # An action needing parameters this function does not know how to supply is
    # reported rather than guessed at. An investigation run with made-up
    # arguments would produce evidence about the wrong thing.
    return []


def gather(incident):
    """Run the incident type's declared read-only investigation.

    Returns {"action": id, "status": ..., "data": ...}. A failure here is
    reported, never raised: an incident whose evidence could not be collected is
    still an incident, and losing it because `ps` hiccuped would be absurd.
    """
    action_id = (incidents.TYPES.get(incident["type"]) or {}).get("investigate")
    if not action_id:
        return {"action": None, "status": "error",
                "message": f"no investigation is declared for {incident['type']}"}

    parameter_sets = _investigation_parameters(action_id, incident)
    if not parameter_sets:
        return {"action": action_id, "status": "error",
                "message": f"{action_id} needs parameters that cannot be derived "
                           f"from this incident; not guessing at them"}

    # Several runs are collected into a list; a single run returns its own data
    # unchanged, so the common case keeps the shape the interpreters expect.
    if len(parameter_sets) > 1:
        collected = []
        for parameters in parameter_sets:
            one = _run_one(action_id, parameters)
            if one.get("status") != "ok":
                return one
            collected.append(one["data"])
        return {"action": action_id, "status": "ok", "data": collected}

    return _run_one(action_id, parameter_sets[0])


def _run_one(action_id, parameters):
    """Validate and run one read-only action. The only execution in this file."""
    # THE SAME VALIDATOR THE WEB CONSOLE USES. Passing through it here rather
    # than calling the script directly is what keeps one execution path in the
    # project: if the registry is edited, this changes with it, and there is no
    # second place where a command gets built.
    validation = actions.validate(action_id, parameters)
    if not validation.ok:
        return {"action": action_id, "status": "error",
                "message": f"the registry refused {action_id}: {validation.message}"}

    # Belt and braces. check_registry() already refuses a non-read action in
    # `investigate`, so this can only fire if the registry changed underneath a
    # running process. Investigation must never be able to change the machine,
    # and that promise is worth two lines to re-check at the moment of use.
    if validation.action["danger"] != "read":
        return {"action": action_id, "status": "error",
                "message": f"{action_id} is not read-only; refusing to investigate with it"}

    result = actions.execute(validation)
    result["action"] = action_id
    return result


# ===========================================================================
#  2. INTERPRETERS -- one per component
# ===========================================================================
#
# Each returns (facts, inferences, recommendations, confidence, primary_cause).
# They are deliberately small and specific. A single clever generic interpreter
# would have to describe a runaway process and a full disk in the same words,
# and the words that fit both are the words that help with neither.
# ---------------------------------------------------------------------------
def _interpret_cpu(incident, evidence):
    """A CPU or process incident: which process is responsible, if any?"""
    facts, inferences, recommendations = [], [], []

    # THE REGISTRY HAS ALREADY NARROWED THIS. `list_processes` declares
    # "select": "processes", so execute() returns the ARRAY, not the whole
    # process.sh document. Both shapes are accepted here because the registry is
    # a file a human edits, and an interpreter that crashes when someone removes
    # a `select` is a brittle interpreter.
    data = evidence.get("data")
    processes = data if isinstance(data, list) else (data or {}).get("processes") or []

    if not processes:
        return facts, ["no process listing was available, so no contributor could be named"], \
               ["run the process listing by hand: ./linux/process.sh"], 0.0, None

    top = processes[0]
    # process.sh reports CPU as a percentage of ONE core, the same scale top
    # uses, so a 4-core machine can legitimately total more than 100.
    total = sum(p.get("cpu_percent") or 0 for p in processes)
    share = (top["cpu_percent"] / total) if total > 0 else 0.0

    facts.append(
        f"the busiest process is {top['name']} (pid {top['pid']}) at "
        f"{top['cpu_percent']}% of one core"
    )
    facts.append(
        f"the {len(processes)} busiest processes together account for "
        f"{total:.1f}% of one core"
    )
    if len(processes) > 1:
        second = processes[1]
        facts.append(
            f"the next busiest is {second['name']} (pid {second['pid']}) at "
            f"{second['cpu_percent']}%"
        )

    if share >= DOMINANCE_SHARE:
        inferences.append(
            f"{top['name']} (pid {top['pid']}) accounts for {share:.0%} of the "
            f"measured CPU use and is the dominant contributor"
        )
        recommendations.append(
            f"investigate pid {top['pid']} ({top['name']}) before changing anything else"
        )
        # Confidence rises with dominance and is capped: 100% share still only
        # earns MAX_CONFIDENCE, because "this process is using the CPU" is not
        # the same statement as "this process is the reason the CPU is busy".
        confidence = min(MAX_CONFIDENCE, share)
        return facts, inferences, recommendations, confidence, {
            "kind": "process", "pid": top["pid"], "name": top["name"],
            "cpu_percent": top["cpu_percent"], "share": round(share, 3),
        }

    inferences.append(
        f"no single process dominates -- the busiest accounts for only "
        f"{share:.0%} of the measured total, so the load is spread across many"
    )
    recommendations.append(
        "look for a pattern across processes rather than a single culprit; "
        "a burst of short-lived processes will not show in one snapshot"
    )
    return facts, inferences, recommendations, min(0.5, 1 - share), None


def _interpret_memory(incident, evidence):
    """A memory incident: how full, and is it paging?"""
    facts, inferences, recommendations = [], [], []
    data = evidence.get("data") or {}
    used = data.get("usage_percent")

    if used is None:
        return facts, ["no memory reading was available"], [], 0.0, None

    facts.append(f"memory is {used}% used ({data.get('used_mb')} MB of {data.get('total_mb')} MB)")
    facts.append(f"{data.get('available_mb')} MB is still available to a new program")

    # The swap symptom is read from the incident's own evidence rather than
    # re-measured: it is already there, and re-reading it a second later would
    # invite the two numbers to disagree on the page.
    swap = next(
        (s for s in (incident.get("detail") or {}).get("symptoms") or []
         if s["metric"] == "swap_used_percent"),
        None,
    )
    if swap and swap.get("current"):
        facts.append(f"swap is {swap['current']:.1f}% used")
        inferences.append(
            "swap is in use as well as RAM, which means the machine is paging -- "
            "the symptom that makes a machine feel slow rather than merely full"
        )
        recommendations.append("identify the largest memory consumers before freeing anything")
        return facts, inferences, recommendations, 0.8, {"kind": "paging"}

    inferences.append(
        "memory is elevated but the machine is not paging, so this is pressure rather than exhaustion"
    )
    recommendations.append("watch it; no action is warranted while swap stays unused")
    return facts, inferences, recommendations, 0.6, None


def _interpret_service(incident, evidence):
    """A service incident: which unit is down, and is it one we may touch?"""
    facts, inferences, recommendations = [], [], []

    # check_service is run once per monitored service, so `data` is a list of
    # single-service objects. A one-service run returns the object on its own,
    # and a registry without the `select` would return the whole document --
    # all three are unwrapped here rather than assumed.
    data = evidence.get("data")
    if isinstance(data, list):
        services = data
    elif isinstance(data, dict) and "services" in data:
        services = data["services"]
    elif isinstance(data, dict):
        services = [data]
    else:
        services = []
    services = [s for s in services if isinstance(s, dict) and s.get("name")]

    broken = [s for s in services if s.get("installed") and not s.get("running")]
    for service in services:
        facts.append(
            f"{service['name']}: {service.get('active_state')}/{service.get('sub_state')}, "
            f"{'enabled' if service.get('enabled') else 'disabled'} at boot"
        )

    if not broken:
        inferences.append(
            "every monitored service is running now, so the failure has already cleared"
        )
        return facts, inferences, ["no action needed"], 0.7, None

    names = ", ".join(s["name"] for s in broken)
    inferences.append(f"{names} is not running, which is what raised this incident")

    # HEALABLE_SERVICES is read from the config rather than assumed, so the
    # recommendation can never suggest something healing.sh would refuse. The
    # allow-list decides what may be recommended, not this module's opinion.
    healable = set(actions.config_words("HEALABLE_SERVICES"))
    for service in broken:
        if service["name"] in healable:
            recommendations.append(
                f"{service['name']} is on the healing allow-list; a restart can be "
                f"requested, and it will still need approval and verification"
            )
        else:
            recommendations.append(
                f"{service['name']} is NOT on the healing allow-list, so Guardian "
                f"cannot restart it -- this one is for a human"
            )
    return facts, inferences, recommendations, 0.9, {
        "kind": "service", "units": [s["name"] for s in broken],
    }


def _interpret_network(incident, evidence):
    """A network incident: is the link healthy, and what changed?"""
    facts, inferences, recommendations = [], [], []
    data = evidence.get("data") or {}
    interface = data.get("interface") or {}
    connectivity = data.get("connectivity") or {}

    if interface:
        facts.append(
            f"interface {interface.get('name')} is {interface.get('state')} "
            f"with address {interface.get('ip_address')}/{interface.get('prefix_length')}"
        )
    if connectivity:
        facts.append(
            f"gateway {connectivity.get('target')} is "
            f"{'reachable' if connectivity.get('reachable') else 'UNREACHABLE'}"
            + (f" with {connectivity.get('packet_loss_percent')}% packet loss"
               if connectivity.get("reachable") else "")
        )

    if connectivity and not connectivity.get("reachable"):
        inferences.append("the gateway does not answer, so this is a connectivity failure")
        recommendations.append("check the VM's network adapter and the host's virtual network")
        return facts, inferences, recommendations, 0.9, {"kind": "link_down"}

    if incident["type"] == "exposure_change":
        inferences.append(
            "the number of listening sockets changed while the link stayed healthy, "
            "so a service started or stopped rather than anything failing"
        )
        recommendations.append(
            "confirm which service opened or closed the port, and that it was expected"
        )
        return facts, inferences, recommendations, 0.7, {"kind": "exposure"}

    inferences.append(
        "the link is up and the gateway answers, so this is a change in traffic "
        "volume rather than a fault"
    )
    recommendations.append("identify what is transferring before treating it as a problem")
    return facts, inferences, recommendations, 0.6, None


def _interpret_disk(incident, evidence):
    """A disk incident: is it filling, or merely busy?"""
    facts, inferences, recommendations = [], [], []
    data = evidence.get("data") or {}
    used = data.get("usage_percent")

    if used is None:
        return facts, ["no disk reading was available"], [], 0.0, None

    facts.append(
        f"{data.get('mount_point')} is {used}% full "
        f"({data.get('used_gb')} GB of {data.get('total_gb')} GB, "
        f"{data.get('free_gb')} GB free)"
    )

    busy = [s["metric"] for s in (incident.get("detail") or {}).get("symptoms") or []
            if s["metric"] in ("disk_read_sectors", "disk_write_sectors", "disk_io_ms")]

    # CAPACITY AND THROUGHPUT ARE DIFFERENT PROBLEMS and the recommendation
    # differs completely, so the interpretation says which one it is looking at.
    if busy and used < 80:
        inferences.append(
            f"the disk is only {used}% full, so this is throughput rather than capacity: "
            f"{', '.join(busy)} moved, not the free space"
        )
        recommendations.append(
            "find what is reading or writing; a backup or an update finishing looks exactly like this"
        )
        return facts, inferences, recommendations, 0.7, {"kind": "throughput"}

    inferences.append(f"the filesystem is {used}% full and the trend is what matters here")
    recommendations.append("check the largest directories before anything is deleted")
    return facts, inferences, recommendations, 0.7, {"kind": "capacity"}


def _interpret_generic(incident, evidence):
    """Anything with no specific interpreter: report, do not speculate.

    THE HONEST FALLBACK. It would be easy to emit a confident-sounding sentence
    for every incident type by templating the metric name into a paragraph. That
    would be a guess wearing the costume of an analysis, which section 14 of the
    brief forbids specifically. Saying "no interpreter exists for this" is less
    impressive and considerably more useful.
    """
    symptoms = (incident.get("detail") or {}).get("symptoms") or []
    facts = [
        f"{s['metric']}: now {s['current']:.2f} against a baseline of {s['baseline']:.2f}"
        for s in symptoms if s.get("current") is not None and s.get("baseline") is not None
    ]
    return (
        facts,
        [f"no root-cause interpreter is written for {incident['component']} incidents, "
         f"so the readings above are reported without one"],
        ["read the evidence and the trend on the incident page"],
        0.0,
        None,
    )


INTERPRETERS = {
    "cpu": _interpret_cpu,
    "processes": _interpret_cpu,
    "memory": _interpret_memory,
    "services": _interpret_service,
    "network": _interpret_network,
    "disk": _interpret_disk,
}


# ===========================================================================
#  3. THE ANALYSIS
# ===========================================================================
def analyse(incident_id, connection=None, now=None):
    """Investigate one incident and record what was found.

    Moves the incident DETECTED -> INVESTIGATING the first time, appends the
    findings to its timeline, and stores the analysis on the incident so the
    page can show it without investigating again.

    IT DOES NOT DECIDE ANYTHING. The output ends with recommendations and stops.
    Turning a recommendation into an action is a separate, explicit request that
    goes through the registry and the approval step, exactly as it did in Phase 6.
    """
    owned = connection is None
    connection = connection or store.connect()
    now = int(time.time()) if now is None else int(now)

    try:
        incident = incidents.get(incident_id, connection=connection)
        if incident["status"] in (incidents.RESOLVED, incidents.IGNORED):
            raise RootCauseError(
                f"{incident_id} is {incident['status']}; investigating a closed "
                f"incident would append to a finished record"
            )

        evidence = gather(incident)
        interpreter = INTERPRETERS.get(incident["component"], _interpret_generic)

        if evidence.get("status") != "ok":
            facts, inferences = [], [
                f"evidence could not be collected: {evidence.get('message')}"
            ]
            recommendations, confidence, cause = [], 0.0, None
        else:
            facts, inferences, recommendations, confidence, cause = interpreter(
                incident, evidence
            )

        analysis = {
            "investigated_at": now,
            "action": evidence.get("action"),
            "facts": facts,
            "inferences": inferences,
            "recommendations": recommendations,
            "confidence": round(confidence, 3),
            "primary_cause": cause,
            "raw": evidence.get("data") if evidence.get("status") == "ok" else None,
        }

        summary = (
            inferences[0] if inferences else "no conclusion could be drawn from the evidence"
        )

        with connection:
            # The analysis is stored INSIDE the incident's detail blob rather
            # than in a column, because nothing queries it -- see the schema
            # comment in guardian_store: queryable state gets a column, a
            # document a human reads once gets JSON.
            detail = incident.get("detail") or {}
            detail["root_cause"] = analysis
            connection.execute(
                "UPDATE incidents SET detail = ?, updated_at = ? WHERE id = ?",
                (json.dumps(detail), now, incident_id),
            )
            incidents.add_timeline(
                connection, incident_id, incidents.TIMELINE_EVIDENCE,
                f"investigated with {evidence.get('action')}: {summary}",
                detail=analysis, now=now,
            )

        # DETECTED -> INVESTIGATING happens after the evidence is stored, so an
        # incident is never left claiming to be under investigation with nothing
        # to show for it.
        if incident["status"] == incidents.DETECTED:
            incidents.transition(
                incident_id, incidents.INVESTIGATING,
                f"root-cause analysis run ({analysis['confidence']:.0%} confidence)",
                connection=connection, now=now,
            )

        analysis["incident_id"] = incident_id
        analysis["summary"] = summary
        return analysis
    finally:
        if owned:
            connection.close()


# ===========================================================================
#  4. COMMAND LINE
# ===========================================================================
_USAGE = "analyse <incident-id>"


def main(argv):
    if not argv:
        print(json.dumps(
            {"module": "rootcause", "status": "error", "message": f"usage: {_USAGE}"}, indent=2))
        sys.exit(2)

    try:
        if argv[0] == "analyse":
            if len(argv) < 2:
                raise RootCauseError("analyse needs an incident id")
            result = analyse(argv[1])
        else:
            raise RootCauseError(f"unknown command {argv[0]!r} -- usage: {_USAGE}")
    except (RootCauseError, incidents.IncidentError, store.StoreError) as error:
        print(json.dumps(
            {"module": "rootcause", "status": "error", "message": str(error)}, indent=2))
        sys.exit(1)

    result["module"] = "rootcause"
    result["status"] = "ok"
    print(json.dumps(result, indent=2, default=float))


if __name__ == "__main__":
    main(sys.argv[1:])
