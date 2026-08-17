#!/usr/bin/env python3
"""
Linux Guardian -- guardian_explain.py                              (Phase 9)

THE PLAIN-ENGLISH LAYER FOR INCIDENTS.

Phases 7 and 8 built something that is correct and, to anybody who has not read
the source, largely unreadable. A user is shown:

    INC-20260816-0003  cpu_saturation  CRITICAL  risk 74  HIGH
    load_per_core  z=+8.0  +220%  confidence 0.98

Every one of those numbers is honest and hard-won. None of them tells a person
what happened, whether it matters, or what to do next. That is not a data
problem -- the data is all there -- it is a TRANSLATION problem, and this file
is the translator.

    what the machine measured   ->   what a person needs to know

FOUR QUESTIONS, ALWAYS IN THE SAME ORDER
----------------------------------------
    1. What happened?          one sentence, no jargon
    2. Why did Guardian say so? the comparison it actually made
    3. What does it mean for me? the consequence, from the incident registry
    4. What should I do now?     exactly one next step, matched to the status

Answering them in a fixed order matters as much as answering them at all. A
reader who learns that the third paragraph is always "what it means" stops
having to search for it.

WHAT THIS FILE IS AND IS NOT
----------------------------
It is a PRESENTER. It reads an incident record and returns sentences. It never
measures anything, never changes an incident, and imports neither `subprocess`
nor `os` -- test_explain.py asserts that against the parsed syntax tree.

It also invents no facts. Every number it puts in a sentence came out of the
incident record; where a value is missing it says so rather than guessing,
which is why `confidence is None` prints "could not be calculated" and never
0%. The zero-variance case in guardian_anomaly.py is exactly that situation,
and printing 0% there would claim certainty that the finding was meaningless --
the opposite of what happened.

WHY IT IS NOT IN THE TEMPLATE
-----------------------------
Jinja could do most of this with enough {% if %}. It would then be untestable,
duplicated across incidents.html and incident.html, and impossible to check
from a terminal. Keeping the wording here means test_explain.py can prove that
every status produces a next step and that no sentence is left empty.
"""

import guardian_incidents as gi


# ===========================================================================
#  1. METRIC NAMES IN ENGLISH
# ===========================================================================
#
# The identifiers come from metrics.sh, where they are correct and terse:
# `load_per_core`, `cpu_idle_ticks`, `net_rx_bytes`. Terse is right for a
# database column and wrong for a sentence.
#
# Each entry is (short label, what it actually measures). The second half is
# what makes the page teach rather than merely rename: 'cpu_idle_ticks' as
# "CPU idle time" is still a mystery until you are told it is a counter that
# FALLS as the machine gets busier.
METRIC_NAMES = {
    "load_1min":      ("Load average (1 min)", "how many processes were waiting to run, averaged over the last minute"),
    "load_5min":      ("Load average (5 min)", "the same figure over five minutes, so a brief spike does not dominate it"),
    "load_15min":     ("Load average (15 min)", "the same figure over fifteen minutes -- the slowest to move"),
    "load_per_core":  ("Load per CPU core", "the load average divided by the number of cores, so 1.0 means 'exactly as much work as this machine can do'"),
    "cpu_idle_ticks": ("CPU idle time", "a counter of how much time the CPU spent doing nothing; it RISES on an idle machine and stalls on a busy one"),
    "cpu_total_ticks": ("Total CPU time", "a counter of all CPU time, used as the denominator for the idle figure"),
    "context_switches": ("Context switches", "how often the kernel swapped one process off the CPU for another"),
    "processes_running": ("Processes running", "how many processes were actually on a CPU at the moment of the reading"),
    "processes_blocked": ("Processes blocked", "processes stuck waiting for the disk or the network rather than for the CPU"),
    "processes_total": ("Processes", "every process on the machine"),
    "processes_zombie": ("Zombie processes", "finished processes whose parent has not collected them; a handful is normal, a growing number is a leak"),
    "processes_forked": ("Processes started", "a counter of every process created since boot"),
    "memory_used_percent": ("Memory used", "the percentage of RAM in use, excluding cache the kernel can reclaim"),
    "swap_used_percent": ("Swap used", "how much of the swap file is in use; steady swapping means RAM ran out"),
    "swap_total_mb":  ("Swap size", "how much swap exists at all"),
    "disk_used_percent": ("Disk used", "how full the root filesystem is"),
    "disk_read_sectors": ("Disk reads", "a counter of sectors read from the disk"),
    "disk_write_sectors": ("Disk writes", "a counter of sectors written to the disk"),
    "disk_io_ms":     ("Disk busy time", "milliseconds the disk spent working; if this rises as fast as the clock, the disk is saturated"),
    "net_rx_bytes":   ("Network received", "a counter of bytes arriving on the interface"),
    "net_tx_bytes":   ("Network sent", "a counter of bytes leaving the interface"),
    "net_rx_packets": ("Packets received", "a counter of packets arriving"),
    "net_tx_packets": ("Packets sent", "a counter of packets leaving"),
    "net_rx_errors":  ("Receive errors", "packets the interface could not accept -- almost always a cable, driver or duplex problem"),
    "net_tx_errors":  ("Send errors", "packets the interface could not transmit"),
    "listening_sockets": ("Listening ports", "how many ports on this machine are accepting connections; a change means something started or stopped serving"),
    "established_connections": ("Open connections", "how many network conversations are currently in progress"),
    "open_file_descriptors": ("Open files", "files, sockets and pipes held open across the whole machine; a number that only ever rises is a leak"),
    "failed_units":   ("Failed services", "systemd units in the failed state"),
    "login_sessions": ("Login sessions", "how many people or services are logged in"),
}


def metric_label(metric):
    """The human name for a metric, or a tidied version of the identifier.

    The fallback matters: a metric added to metrics.sh tomorrow gets
    "Net rx dropped" rather than vanishing or crashing the page. It reads
    slightly worse than a written label, which is the correct incentive.
    """
    if metric in METRIC_NAMES:
        return METRIC_NAMES[metric][0]
    return metric.replace("_", " ").capitalize()


def metric_meaning(metric):
    """What the metric actually measures, in one clause. May be empty."""
    return METRIC_NAMES.get(metric, ("", ""))[1]


# ===========================================================================
#  2. SIZE OF A CHANGE, IN WORDS
# ===========================================================================
def magnitude(percent):
    """Turn a percentage change into the phrase a person would actually use.

    Nobody says "220% above baseline" out loud; they say "about three times
    higher". Both are printed -- the phrase leads, the number follows in
    brackets -- because the phrase is what gets understood and the number is
    what gets defended.

    Written as an explicit ladder rather than a formula because the boundaries
    are judgements about ENGLISH, not about arithmetic: 'roughly double' is a
    fair description of anything from about 1.8x to 2.5x, and no formula
    expresses that better than saying so.
    """
    if percent is None:
        return "changed"

    size = abs(percent)
    direction = "higher" if percent > 0 else "lower"

    if size < 15:
        return f"slightly {direction}"
    if size < 60:
        return f"noticeably {direction}"
    if size < 130:
        return f"roughly double" if percent > 0 else "roughly half"
    if size < 400:
        multiple = 1 + size / 100
        return f"about {multiple:.0f} times {direction}"
    return f"far {direction} -- more than five times"


def number(value):
    """Format a measurement the way it would be said aloud.

    The store keeps full precision, which is right for arithmetic and wrong for
    a sentence: "1.18519" invites a reader to believe five decimal places were
    meaningful, when the figure is an average over a handful of samples. The
    ladder below keeps roughly three significant figures and drops trailing
    zeros, so 1.18519 reads as 1.19 and 5.0 reads as 5.

    Formatting only. The precise value is still in the chart, the evidence list
    and the raw JSON -- this is the version for prose.
    """
    if value is None:
        return "unknown"
    size = abs(value)
    if size >= 100:
        return f"{value:,.0f}"
    if size >= 10:
        text = f"{value:.1f}"
    else:
        text = f"{value:.2f}"
    # "5.00" -> "5" and "5.50" -> "5.5". A trailing ".0" on a count of ports
    # makes it look like a measurement that could be fractional.
    return text.rstrip("0").rstrip(".") if "." in text else text


def symptom_sentence(symptom):
    """One measured symptom, as a sentence with the numbers still in it."""
    label = metric_label(symptom["metric"])
    current = symptom.get("current")
    baseline = symptom.get("baseline")
    percent = symptom.get("percent")

    if current is None or baseline is None:
        return f"{label} was flagged, but the reading behind it is no longer available."

    trend = symptom.get("trend") or ""
    # The trend is only worth a clause when it says something. "steady" on an
    # incident that is currently abnormal is genuinely useful ("it is not
    # getting worse"), so it is kept; an empty trend is not.
    tail = {
        "rising":  " It is still climbing.",
        "falling": " It is now coming back down.",
        "steady":  " It has settled at that level.",
    }.get(trend, "")

    # A BASELINE OF ZERO HAS NO PERCENTAGE, and this is not an edge case worth
    # papering over -- it is the most striking finding the detector produces.
    # A counter whose rate was flat at zero and is now moving means something
    # started happening that had never happened before. "changed by None%" said
    # nothing; this says the actual news.
    if percent is None or baseline == 0:
        return (f"{label} is now {number(current)}. Before this, it had never "
                f"been anything other than {number(baseline)} on this "
                f"machine.{tail}")

    return (f"{label} measured {number(current)}, against {number(baseline)} "
            f"normally for this machine -- {magnitude(percent)} "
            f"({percent:+.0f}%).{tail}")


# ===========================================================================
#  3. THE FOUR QUESTIONS
# ===========================================================================

# How urgent, in words, from the risk band. The band already exists; what did
# not exist was a sentence telling somebody what to do with it.
URGENCY = {
    "CRITICAL": ("Look at this now", "This is the most serious thing open."),
    "HIGH":     ("Worth looking at soon", "It is not an emergency, but it should not sit all day."),
    "MEDIUM":   ("Worth a look", "Nothing is on fire. Have a look when convenient."),
    "LOW":      ("For information", "Guardian noticed it and is keeping an eye on it."),
    "INFO":     ("For information", "Recorded so there is a history, not because it needs action."),
}


def urgency(incident):
    """The two-line 'how much should I care' answer."""
    title, detail = URGENCY.get(incident.get("risk_level"), URGENCY["INFO"])
    return {"title": title, "detail": detail}


def what_happened(incident):
    """Question 1. What happened, with when and how long."""
    occurrences = incident.get("occurrences") or 1
    started = incident.get("created_human") or "recently"
    label = incident.get("component") or "this machine"

    if incident.get("open"):
        seen = ("It has been abnormal on every check since"
                if occurrences > 1 else "It has been seen once so far")
        return (f"Guardian noticed something unusual about {label} at "
                f"{started}. {seen} -- {occurrences} observation"
                f"{'' if occurrences == 1 else 's'} in total.")

    ended = incident.get("updated_human") or "later"
    return (f"Guardian noticed something unusual about {label} at {started}, "
            f"observed it {occurrences} time{'' if occurrences == 1 else 's'}, "
            f"and closed it at {ended}.")


def why_noticed(incident):
    """Question 2. The comparison Guardian actually made.

    This is the sentence that stops the whole system looking like magic. It is
    NOT a threshold: no number here was written by anybody in advance. The
    machine's own recent history is the yardstick.
    """
    symptoms = (incident.get("detail") or {}).get("symptoms") or []
    count = len(symptoms) or len(incident.get("symptoms") or [])

    base = ("Guardian compared this machine against its own recent history -- "
            "not against a fixed limit somebody typed in. ")

    if not count:
        return base + "The readings that triggered it are recorded below."

    if count == 1:
        return base + ("One measurement moved far enough outside its usual "
                       "range to count as abnormal.")

    return base + (f"{count} measurements moved outside their usual range at "
                   f"the same time, and they are all known symptoms of the "
                   f"same condition -- so they are shown as ONE incident "
                   f"rather than {count} separate alerts.")


def what_it_means(incident):
    """Question 3. The consequence, taken from the incident registry.

    The wording comes from linux/incidents.json rather than from here, so the
    person who adds a new incident type writes its explanation next to its
    definition and cannot forget to.
    """
    described = incident.get("description")
    if described:
        return described
    definition = gi.TYPES.get(incident.get("type")) or {}
    return definition.get("description") or (
        "Guardian has no written explanation for this condition -- it is an "
        "unclassified metric anomaly, recorded so it is not lost.")


# ===========================================================================
#  3b. STATUS NAMES A PERSON WOULD SAY
# ===========================================================================
#
# The status VALUES stay exactly as they are -- they are database contents, a
# CSS class and part of the state machine, and renaming them would be renaming
# a key. Only the label changes. WAITING_APPROVAL is a perfectly good constant
# and a poor thing to print on a page.
STATUS_LABELS = {
    gi.DETECTED:         "Noticed",
    gi.INVESTIGATING:    "Being investigated",
    gi.WAITING_APPROVAL: "Waiting for you",
    gi.REMEDIATING:      "Fix running",
    gi.VERIFYING:        "Checking the fix",
    gi.RESOLVED:         "Resolved",
    gi.FAILED:           "Fix failed",
    gi.IGNORED:          "Ignored",
}


def status_label(status):
    """The printable name of a status. Falls back to the raw value.

    The fallback is not politeness -- a status added to the state machine and
    forgotten here should show up as SHOUTING_SNAKE_CASE on the page, which is
    ugly enough that somebody fixes it. Silently prettifying it with .title()
    would hide the omission.
    """
    return STATUS_LABELS.get(status, status)


# ===========================================================================
#  4. THE ONE NEXT STEP
# ===========================================================================
#
# EXACTLY ONE next step per status, never a menu. An interface that offers
# four equally-weighted buttons has not decided anything on the user's behalf,
# and deciding is most of what a monitoring tool is for. The other buttons
# still exist on the page; this says which one to press.
NEXT_STEP = {
    gi.DETECTED: {
        "label": "Investigate",
        "text": "Press Investigate. It runs a read-only check -- it collects "
                "evidence and cannot start, stop, delete or edit anything.",
        "who": "you",
    },
    gi.INVESTIGATING: {
        "label": "Read the analysis",
        "text": "Guardian has collected evidence. Read the root-cause panel "
                "below: it separates what was MEASURED from what was REASONED, "
                "so you can see which is which before deciding anything.",
        "who": "you",
    },
    gi.WAITING_APPROVAL: {
        "label": "Approve or Reject",
        "text": "Guardian is waiting for you and nothing has run. Read the "
                "action request, then Approve to run it or Reject to hand the "
                "incident back untouched.",
        "who": "you",
    },
    gi.REMEDIATING: {
        "label": "Wait",
        "text": "The approved action is running. Nothing is needed from you "
                "until it finishes.",
        "who": "guardian",
    },
    gi.VERIFYING: {
        "label": "Wait",
        "text": "The action has finished and Guardian is re-measuring the "
                "machine to see whether it actually worked. It deliberately "
                "does not trust the action's exit code as proof.",
        "who": "guardian",
    },
    gi.RESOLVED: {
        "label": "Nothing",
        "text": "This incident is closed. The timeline below is kept as the "
                "record of what happened and what, if anything, was done.",
        "who": "nobody",
    },
    gi.FAILED: {
        "label": "Human needed",
        "text": "An action ran but the machine did not improve, so Guardian "
                "stopped. It will NOT retry on its own, and the incident stays "
                "open on purpose -- a failed repair is not a closed problem.",
        "who": "you",
    },
    gi.IGNORED: {
        "label": "Nothing",
        "text": "A person closed this as understood and not worth acting on. "
                "It is kept so the decision is on the record.",
        "who": "nobody",
    },
}


def next_step(incident):
    """Question 4. What to do now, matched to the status.

    INVESTIGATING is the one status whose answer depends on more than the
    status itself: before the investigation has produced anything there is
    nothing to read, so the advice stays "press Investigate".
    """
    status = incident.get("status")
    step = dict(NEXT_STEP.get(status, NEXT_STEP[gi.DETECTED]))

    if status == gi.INVESTIGATING:
        detail = incident.get("detail") or {}
        if not detail.get("root_cause"):
            step = dict(NEXT_STEP[gi.DETECTED])

    return step


# ===========================================================================
#  4B. WHAT A HUMAN CAN DO WHEN GUARDIAN CANNOT
# ===========================================================================
#
# THE GAP THIS FILLS. Guardian detects a CPU saturation, groups it, scores it,
# investigates it, and names the process responsible -- and then the page says
# "there is no remediation Guardian is permitted to perform; it needs a human"
# and stops. Every word of that is true and none of it is useful. The reader is
# told a human is needed without being told what the human should do.
#
# The reason there is no fix is worth stating plainly, because it is a design
# decision and not an oversight: the registry contains exactly one action that
# changes the state of the machine, `heal_service`, and it may only start
# apache2. NOTHING IN THIS PROJECT CAN REDUCE CPU LOAD. Adding a kill action
# would mean giving a web process the power to end arbitrary programs, which is
# a far larger grant of privilege than "start one named web server" and would
# need its own deny-list, allow-list, approval and verification.
#
# So the honest answer is to hand the work to the person: print the commands
# they would run, with the pid the investigation already found, and execute
# none of them.
#
# THE ONE RULE THAT MAKES THIS SAFE. A suggestion that gets followed is an
# action with extra steps. On this desktop VM the busiest process is routinely
# Xorg or the browser, and a page that mechanically printed "kill <busiest pid>"
# would eventually tell a student to destroy their own session during a
# demonstration. NEVER_SUGGEST_KILLING in guardian.conf is therefore consulted
# before any stop command is offered, and a protected process gets an
# explanation instead of a command.
#
# It returns DATA, never a rendered string: {"command", "why", "caution"}. The
# template decides what a command looks like; this file decides what is true.

# Ordered gentlest-first, which is also the order they are shown. Reversible
# before destructive is a habit worth teaching, not just a safety measure.
_LOOK = "look"
_SOFTEN = "soften"
_STOP = "stop"


def _never_kill():
    """Process names that must never appear in a stop suggestion.

    Read from guardian.conf at call time rather than import time, so editing
    the list does not need the web process restarted -- the same treatment
    HEALABLE_SERVICES gets.
    """
    from guardian_config import config_words
    return {name.lower() for name in config_words("NEVER_SUGGEST_KILLING")}


def _process_steps(cause):
    """Steps for an incident the investigation blamed on one process."""
    pid, name = cause.get("pid"), cause.get("name") or "the process"
    share = cause.get("share")

    # A process whose name is on the protected list gets a sentence, not a
    # command. Naming it is still useful -- "your browser is the busiest thing
    # on this machine" is a real finding -- but the reader is told to close it
    # the way it is meant to be closed.
    if str(name).lower() in _never_kill():
        return [{
            "kind": _LOOK,
            "command": f"ps -p {pid} -o pid,ppid,user,%cpu,%mem,etime,comm",
            "why": f"{name} (pid {pid}) is the busiest process, but it is part of "
                   f"your desktop session or of Guardian itself. Look at it rather "
                   f"than stopping it.",
            "caution": f"Do not kill {name}: stopping it would take down the "
                       f"session you are demonstrating in. Close the application "
                       f"normally instead, or leave it alone.",
        }]

    dominance = f" It accounts for {share:.0%} of the measured CPU use." if share else ""
    return [
        {
            "kind": _LOOK,
            "command": f"ps -p {pid} -o pid,ppid,user,%cpu,%mem,etime,comm",
            "why": f"Confirm {name} (pid {pid}) is still running and still busy "
                   f"before doing anything to it.{dominance}",
            "caution": "",
        },
        {
            "kind": _SOFTEN,
            "command": f"renice -n 19 -p {pid}",
            "why": "Make it yield to everything else without stopping it. This is "
                   "reversible, needs no root for your own processes, and is the "
                   "right first move when the process is doing useful work.",
            "caution": "",
        },
        {
            "kind": _STOP,
            "command": f"kill {pid}",
            "why": f"Ask {name} to shut down cleanly. Plain `kill` sends SIGTERM, "
                   f"which lets the program save and exit.",
            "caution": "Unsaved work in that program is lost. Use `kill -9` only "
                       "if SIGTERM is ignored -- it gives the program no chance "
                       "to clean up.",
        },
    ]


def _spread_load_steps():
    """Steps when no single process was to blame -- the harder, commoner case."""
    return [
        {
            "kind": _LOOK,
            "command": "top -o %CPU",
            "why": "No single process dominated the one snapshot Guardian took. "
                   "Watch the machine live for a few seconds: a burst of "
                   "short-lived processes never shows up in a single reading.",
            "caution": "",
        },
        {
            "kind": _LOOK,
            "command": "./linux/process.sh | jq '.processes[0:10]'",
            "why": "Take another snapshot yourself and compare it with the one in "
                   "the analysis above. Two readings distinguish a spike from a "
                   "steady load.",
            "caution": "",
        },
        {
            "kind": _LOOK,
            "command": "uptime",
            "why": "The three load averages are 1, 5 and 15 minutes. If the first "
                   "is far above the third the load is arriving now; if they are "
                   "level it has been there a while.",
            "caution": "",
        },
    ]


# What to suggest when the investigation reached no structured cause. Keyed by
# the incident's component so the advice is at least about the right subsystem.
_BY_COMPONENT = {
    "memory": ("free -h",
               "Show memory and swap in human units. Guardian's percentage is "
               "the same number this prints, so the two can be compared directly."),
    "disk": ("df -h /",
             "Show what is actually using the filesystem Guardian measured. "
             "A percentage does not say which directory grew."),
    "network": ("ip -br addr; ping -c 3 192.168.138.2",
                "Confirm the interface still has its address and the gateway "
                "still answers."),
    "services": ("systemctl status apache2 ssh --no-pager",
                 "Read the unit state and the last log lines systemd kept."),
    "processes": ("ps -eo pid,user,%cpu,%mem,etime,comm --sort=-%cpu | head -15",
                  "List the busiest processes yourself, sorted by CPU."),
}


def manual_steps(incident):
    """Commands a person can run when Guardian has no permitted remediation.

    Returns a possibly-empty list of {"kind", "command", "why", "caution"}.
    An empty list means "nothing honest to suggest", which is a real answer:
    it is better than filling the panel with generic advice that fits every
    incident and helps with none.

    NOTHING HERE RUNS. This module imports neither subprocess nor os, and
    test_explain.py asserts that against the parsed syntax tree -- so "the page
    only prints these" is a property of the file rather than a promise in a
    docstring.
    """
    detail = incident.get("detail") or {}
    analysis = detail.get("root_cause") or {}
    cause = analysis.get("primary_cause") or {}

    if not analysis:
        # Nothing has been investigated yet, so there is no pid to name and no
        # honest command to print. The next step is already "press Investigate".
        return []

    if cause.get("kind") == "process":
        return _process_steps(cause)

    component = incident.get("component")
    if component in ("cpu", "processes") and not cause:
        return _spread_load_steps()

    fallback = _BY_COMPONENT.get(component)
    if fallback:
        command, why = fallback
        return [{"kind": _LOOK, "command": command, "why": why, "caution": ""}]

    return []


# ===========================================================================
#  5. THE LIFECYCLE, DRAWN AS A LINE
# ===========================================================================
#
# The state machine in guardian_incidents.py is correct and invisible. Showing
# it as five labelled steps with "you are here" marked is the single change
# that makes the incident page legible: a user can see that approval comes
# before anything runs, and that verification comes after.
#
# The labels are verbs in plain English, not the status names. NOTICED rather
# than DETECTED, CHECKED rather than VERIFYING.
STAGES = (
    ("noticed",     "Noticed",      "A measurement left this machine's normal range.", (gi.DETECTED,)),
    ("investigated", "Investigated", "A read-only check collected evidence.",           (gi.INVESTIGATING,)),
    ("approved",    "Approved",     "A person decided whether a fix may run.",          (gi.WAITING_APPROVAL,)),
    ("fixed",       "Fixed",        "The approved action ran.",                          (gi.REMEDIATING,)),
    ("checked",     "Checked",      "Guardian re-measured to see if it worked.",         (gi.VERIFYING,)),
    ("closed",      "Closed",       "The incident is finished.",  (gi.RESOLVED, gi.IGNORED, gi.FAILED)),
)

# How far along each status is. Used to decide which stages are behind the
# current one -- a lookup rather than an index() call, so a status that is not
# in STAGES cannot raise on a page load.
_STAGE_INDEX = {}
for _position, (_key, _label, _note, _statuses) in enumerate(STAGES):
    for _status in _statuses:
        _STAGE_INDEX[_status] = _position


def pipeline(incident):
    """The lifecycle with the current position marked.

    Each stage is 'done', 'current' or 'todo'. FAILED is the one case that is
    not a simple position on a line: the incident got all the way to the end
    and came back out, so its last stage is marked 'failed' rather than
    'current', and the page can colour it accordingly.
    """
    status = incident.get("status")
    here = _STAGE_INDEX.get(status, 0)
    stages = []

    for position, (key, label, note, _statuses) in enumerate(STAGES):
        if position < here:
            state = "done"
        elif position == here:
            state = "failed" if status == gi.FAILED else "current"
        else:
            state = "todo"
        stages.append({"key": key, "label": label, "note": note,
                       "state": state})

    # An incident that resolved on its own never went through approval or
    # remediation, and marking those stages 'done' would claim a fix ran. They
    # are marked 'skipped', and the page says so.
    if status == gi.RESOLVED and not (incident.get("detail") or {}).get("remediation"):
        for stage in stages:
            if stage["key"] in ("approved", "fixed", "checked"):
                stage["state"] = "skipped"
                stage["note"] = "Not needed -- the machine recovered on its own."

    return stages


# ===========================================================================
#  6. THE NUMBERS, EXPLAINED WHERE THEY APPEAR
# ===========================================================================
def severity_sentence(incident):
    """What the severity badge means, and that it is capped."""
    steps = (incident.get("detail") or {}).get("severity_steps") or []
    if not steps:
        return (f"{incident.get('severity')} is the base severity written in "
                f"the incident registry for this type of condition.")
    return ("Severity answers 'how bad is this if it is real'. It started at "
            "the level written in the registry for this type of condition, "
            "and each line below either raised it or held it back.")


def risk_sentence(incident):
    """What the risk score means, and how it differs from severity.

    THESE TWO NUMBERS DISAGREE ON PURPOSE, and that disagreement is the useful
    part -- a CRITICAL finding Guardian is unsure about is a smaller problem
    than a HIGH one it is certain of. Saying so where both numbers appear is
    the difference between a page that looks arbitrary and one that reads.
    """
    return (f"Risk is {incident.get('risk_score')} out of 100. It is a "
            f"weighted average of six things -- how bad it would be, how sure "
            f"Guardian is, how much of the machine it affects, how long it has "
            f"lasted, whether it keeps coming back, and whether it is "
            f"security-related. Severity asks 'how bad', risk asks 'how much "
            f"should I care right now', and they are allowed to differ.")


def confidence_sentence(incident):
    """How sure Guardian is -- and the honest answer when it cannot say.

    A null confidence is the zero-variance case: the baseline never varied at
    all, so there is no spread to measure a deviation against. The finding is
    still real (the value was outside everything ever seen) but no percentage
    can be attached to it, and inventing one would be the single most
    misleading thing this page could do.
    """
    confidence = incident.get("confidence")
    if confidence is None:
        return ("Guardian cannot put a number on how sure it is. This "
                "measurement had never varied at all before, so there is no "
                "spread to compare against -- the reading is genuinely outside "
                "everything ever recorded, but no percentage would be honest.")

    percent = confidence * 100
    return (f"Guardian is {percent:.0f}% sure this is a real anomaly rather "
            f"than normal variation. That figure is a Chebyshev bound, which "
            f"holds for any shape of data -- at most {100 - percent:.0f}% of "
            f"normal readings could be this far from the average. A bell-curve "
            f"figure would look more impressive and would be made up: CPU "
            f"usage is not bell-shaped.")


# ===========================================================================
#  7. THE GLOSSARY
# ===========================================================================
#
# Shown on the incident pages behind a <details>, so it is one click away from
# every jargon word instead of in documentation nobody opens. Ordered by how
# early a reader meets the word, not alphabetically.
GLOSSARY = (
    ("Incident",
     "One real problem, not one reading. If a single cause moves six "
     "measurements, that is one incident with six symptoms -- never six alerts."),
    ("Symptom",
     "One measurement that is behaving abnormally. An incident collects every "
     "symptom it has EVER involved, not just the ones abnormal right now."),
    ("Baseline",
     "What this measurement normally looks like on THIS machine, worked out "
     "from its own recent history. Nobody types a baseline in; it is measured."),
    ("Anomaly",
     "A reading far enough from the baseline to be worth mentioning. It has to "
     "pass two tests: statistically unusual AND a big enough change in "
     "absolute terms -- so a value flat at 3.00 moving to 3.05 is ignored."),
    ("Severity",
     "How bad this would be if it is real: INFO, LOW, MEDIUM, HIGH, CRITICAL."),
    ("Risk",
     "How much you should care right now, out of 100. Combines severity with "
     "confidence, impact, how long it has lasted, whether it recurs, and "
     "whether it is security-related."),
    ("Confidence",
     "How sure Guardian is that the reading is genuinely unusual. Occasionally "
     "'n/a', which is honest: see the note on the confidence card."),
    ("Observations",
     "How many times Guardian has checked and still found this abnormal. It "
     "rises every 30 seconds while the condition lasts."),
    ("Investigate",
     "A read-only action declared in the registry for this type of incident. "
     "It cannot start, stop, delete or edit anything -- that is enforced by "
     "the registry, not by good intentions."),
    ("Propose a fix",
     "Produces a description of what WOULD happen. Nothing runs. The incident "
     "moves to 'waiting for approval' so a person has to decide."),
    ("Verification",
     "Re-measuring the machine after an action, instead of believing the "
     "action's exit code. An action that reports success while the service is "
     "still dead is caught here."),
    ("LEARNING",
     "Not enough history yet to judge this measurement. A distinct word "
     "on purpose -- it means 'I do not know', not 'everything is fine'."),
)


# ===========================================================================
#  8. ONE CALL FOR A TEMPLATE
# ===========================================================================
def explain(incident):
    """Everything a template needs, in one dictionary.

    One call rather than eight, so a page cannot accidentally show the
    'what happened' of one incident beside the 'what to do' of another, and so
    adding a sentence later means changing one function and no templates.
    """
    return {
        "urgency": urgency(incident),
        "happened": what_happened(incident),
        "noticed": why_noticed(incident),
        "means": what_it_means(incident),
        "next": next_step(incident),
        "pipeline": pipeline(incident),
        "severity": severity_sentence(incident),
        "risk": risk_sentence(incident),
        "confidence": confidence_sentence(incident),
        "symptoms": [
            {**symptom,
             "label": metric_label(symptom["metric"]),
             "meaning": metric_meaning(symptom["metric"]),
             "sentence": symptom_sentence(symptom)}
            for symptom in ((incident.get("detail") or {}).get("symptoms") or [])
        ],
    }


def summarise(incident):
    """The short version, for a row in the incident LIST.

    A list has room for one sentence per incident, so it gets the one that
    answers 'should I click this?' -- the consequence and the next step, not
    the measurement. The measurement is what the detail page is for.
    """
    step = next_step(incident)
    return {
        "urgency": urgency(incident),
        "means": what_it_means(incident),
        "next_label": step["label"],
        "next_who": step["who"],
        "symptoms": [metric_label(metric)
                     for metric in (incident.get("symptoms") or [])],
    }


# ===========================================================================
#  9. INTEGRITY
# ===========================================================================
def check_explain():
    """Report any status or incident type this file cannot describe.

    The failure being guarded against is a new status or a new incident type
    arriving and producing a blank panel -- which reads as "nothing is wrong"
    at exactly the moment something is.
    """
    problems = []

    for status in gi.STATUSES:
        if status not in NEXT_STEP:
            problems.append(f"status {status}: no next step written")
        if status not in _STAGE_INDEX:
            problems.append(f"status {status}: does not map to a lifecycle stage")
        if status not in STATUS_LABELS:
            problems.append(f"status {status}: no printable label")

    for type_id, definition in gi.TYPES.items():
        if not definition.get("description"):
            problems.append(f"incident type {type_id}: no plain description")

    for level in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        if level not in URGENCY:
            problems.append(f"risk level {level}: no urgency sentence")

    return problems
