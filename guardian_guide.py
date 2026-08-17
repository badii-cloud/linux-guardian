#!/usr/bin/env python3
"""
Linux Guardian -- guardian_guide.py                                (Phase 9)

THE TEACHING LAYER FOR THE ASSISTANT.

Phase 6 gave the console a matcher and a registry. Both work, and neither
explains itself: a user faced with an empty text box has no way to discover
that "how full is my disk" works and "disk pls" does not. This module turns the
registry and the trigger dictionary into GUIDANCE -- for every action, the
words that trigger it, an example sentence, the parameters it needs, and the
exact Bash command the sentence becomes.

    "create a file called notes"     <- what a person types
              |
              v
    linux/workspace.sh create notes  <- what Linux actually runs

Showing both, side by side, is the whole point. This is a Linux course: the
English is the interface, the argv is the lesson.

THE PROPERTY THAT MAKES THE EXAMPLES TRUSTWORTHY
------------------------------------------------
Every example sentence in EXAMPLES is fed back through guardian_nlp.match() by
test_guide.py, and must resolve to the action it is filed under, above the
confidence threshold. An example that stops working therefore fails the test
suite instead of embarrassing somebody in a demonstration. The examples are not
a second, hand-maintained copy of the matcher's vocabulary -- they are claims
about it that are checked.

WHAT THIS MODULE IS NOT ALLOWED TO DO
-------------------------------------
It never executes anything. It imports neither `subprocess` nor `os`; the only
thing it calls that touches the disk is guardian_actions.describe_effect(),
which reads whether a file already exists so a preview can honestly say
"replace" rather than "create". Running an action stays where it has been since
Phase 6: guardian_actions.execute(), reached only through the console routes.
"""

import re
import shlex

import guardian_actions as ga
import guardian_nlp as nlp
from guardian_config import config_words


# ===========================================================================
#  1. THE CANONICAL SENTENCE FOR EACH ACTION
# ===========================================================================
#
# A TEMPLATE, not a fixed string, because the builder has to rewrite the
# sentence live as the user fills the fields in. Two pieces of syntax:
#
#   {name}          replaced by the value of that parameter
#   [ ... {x} ... ] a segment that DISAPPEARS ENTIRELY when {x} is empty
#
# The square brackets exist for optional parameters. "create a file called
# notes containing" with a trailing "containing" and nothing after it is not a
# sentence anybody would type, and showing it would teach the user a phrasing
# that reads as broken. The whole clause goes, or none of it does.
#
# Every template below is built out of words that are ALREADY trigger phrases
# in guardian_nlp.TRIGGERS. That is checked by test_guide.py rather than
# promised here.
TEMPLATES = {
    "check_disk":      "how full is my disk",
    "check_memory":    "how much free memory is there",
    "check_cpu":       "how busy is the cpu",
    "check_network":   "check the network connection",
    "check_service":   "is {service} running",
    "list_processes":  "show the top processes",
    "run_diagnosis":   "run a full health check",
    "show_logs":       "show the logs",
    "list_files":      "list my files",
    "list_schedules":  "show my schedules",
    "create_file":     "create a file called {name}[ containing {content}]",
    "heal_service":    "restart {service}",
    "schedule_file":   "create a file called {name} every {day} at {time}",
    "cancel_schedule": "cancel the schedule called {name}",
}

# Sample values used to render an example when the user has typed nothing yet.
# Deliberately boring and obviously fake: 'notes' and 'report' cannot be
# mistaken for a real file somebody cares about, and a demonstration that
# creates 'notes.txt' is one nobody has to think twice about.
SAMPLES = {
    "name": "notes",
    "content": "hello",
    "day": "Thursday",
    "time": "09:00",
    "service": "apache2",
}

# The example is a SEPARATE string from the template for the three actions
# where the sample values would read oddly inside the template. 'schedule_file'
# is the clear case: its template is deliberately identical to create_file's
# opening, because that is exactly the sentence a user types -- but as a
# standalone example it needs the day and time present to be worth reading.
EXAMPLE_OVERRIDES = {
    "schedule_file": "create a file called report every thursday at 9am",
    "cancel_schedule": "cancel the schedule called report",
}

# One plain sentence per action, answering "why would I press this?" rather
# than "what does it do?", which the registry's own description already covers.
WHEN_TO_USE = {
    "check_disk":      "The machine says it is out of space, or you want to know before it is.",
    "check_memory":    "Things feel slow and you want to know whether RAM is the reason.",
    "check_cpu":       "The fan is loud, or the desktop is sluggish.",
    "check_network":   "A page will not load and you need to know whether the machine is even on the network.",
    "check_service":   "You want to know whether one particular service is up, without reading the dashboard.",
    "list_processes":  "Something is using the CPU and you want to know what.",
    "run_diagnosis":   "You want one number for the whole machine -- the same sweep the dashboard runs.",
    "show_logs":       "You want to see what Guardian has been asked to do, and what it refused.",
    "list_files":      "You want to know what is in the sandbox Guardian is allowed to write to.",
    "list_schedules":  "You want to check a repeating task really was created.",
    "create_file":     "You want a note written into the sandbox, to prove a write action works end to end.",
    "heal_service":    "A service on the healable list is down and you want it started.",
    "schedule_file":   "You want a file written automatically, every week, by a systemd user timer.",
    "cancel_schedule": "You are finished with a repeating task and want the timer removed.",
}

# Human labels for the registry's categories, used to group the catalogue.
# Ordered, because the order is a claim about what a first-time user should
# read first: the read-only questions, then the things that change something.
CATEGORY_ORDER = (
    ("system",   "Ask about this machine"),
    ("network",  "Ask about the network"),
    ("services", "Ask about services"),
    ("files",    "Files and schedules"),
    ("logs",     "History and audit"),
)


# ===========================================================================
#  2. RENDERING A SENTENCE FROM A TEMPLATE
# ===========================================================================

# One optional segment: a '[' ... ']' pair with no nested brackets inside it.
# Non-greedy is not needed because the class excludes ']' outright, which is a
# cheaper and more obvious way to stop the match running to the last bracket on
# the line.
_OPTIONAL = re.compile(r"\[([^\]]*)\]")

# A placeholder: {name}. The character class is deliberately narrow -- these
# names come from actions.json, and anything that is not a plain parameter name
# is a mistake in the registry rather than something to be clever about.
_SLOT = re.compile(r"\{([a-z_]+)\}")


def render(template, values):
    """Fill a sentence template. Returns the sentence a user could type.

    A missing or empty value does two different things depending on where the
    slot is:

        inside [ ... ]   the whole segment disappears
        outside          the slot becomes <name>, a visible placeholder

    The second half is what makes the live preview useful while a form is still
    half-filled: "restart <service>" says plainly which word is still missing,
    where "restart " with a trailing space says nothing at all.
    """
    def fill_optional(match):
        segment = match.group(1)
        # A segment survives only if EVERY slot inside it has a value. A
        # segment with two slots and one value would otherwise render half a
        # clause.
        for slot in _SLOT.findall(segment):
            if not str(values.get(slot, "")).strip():
                return ""
        return segment

    text = _OPTIONAL.sub(fill_optional, template)

    def fill_slot(match):
        name = match.group(1)
        value = str(values.get(name, "")).strip()
        return value if value else f"<{name}>"

    return _SLOT.sub(fill_slot, text).strip()


def example_sentence(action_id):
    """The example shown before the user has typed anything."""
    if action_id in EXAMPLE_OVERRIDES:
        return EXAMPLE_OVERRIDES[action_id]
    return render(TEMPLATES.get(action_id, action_id.replace("_", " ")), SAMPLES)


def sentence_for(action_id, params):
    """The sentence that corresponds to the parameters currently filled in."""
    return render(TEMPLATES.get(action_id, action_id.replace("_", " ")), params or {})


# ===========================================================================
#  3. DESCRIBING ONE PARAMETER TO A HUMAN
# ===========================================================================

# What each parameter TYPE accepts, in words rather than in a regular
# expression. guardian_actions._explain() says the same thing when a value has
# already been refused; this says it BEFORE the user types, which is the
# cheaper moment for everybody.
TYPE_HINTS = {
    "name": "1-40 characters: letters, digits, underscore or hyphen. "
            "No dots and no slashes, so a name can never climb out of the "
            "workspace. It cannot start with a hyphen either -- a value "
            "starting with '-' is a flag to most Unix commands, not a filename.",
    "text": "Any text. It is passed as its own argv entry, so a semicolon in "
            "it is just a semicolon -- there is no shell to interpret it.",
    "day":  "A day of the week. 'thursday', 'THU' and 'Thu' all normalise to "
            "the 'Thu' that systemd's OnCalendar= expects.",
    "time": "A 24-hour time. '9am', '9 am', '09:00' and 'noon' all normalise "
            "to HH:MM. 25:00 is refused by the pattern, not by the parser.",
    "enum": "One of the names in guardian.conf. The list is policy, and policy "
            "lives in the config file -- not in this page and not in the URL.",
}

PLACEHOLDERS = {
    "name": "notes",
    "content": "text to put in the file",
    "day": "thursday",
    "time": "9am",
    "service": "apache2",
}


def describe_param(spec):
    """Turn one registry parameter spec into something a form can render."""
    choices_key = spec.get("choices_from")
    return {
        "name": spec["name"],
        "type": spec["type"],
        "required": bool(spec["required"]),
        "hint": TYPE_HINTS.get(spec["type"], f"must match {spec['pattern']}"),
        "placeholder": PLACEHOLDERS.get(spec["name"], ""),
        "pattern": spec["pattern"],
        # Only enum parameters have a fixed list, and that list is read from
        # guardian.conf at request time rather than baked into the page, so
        # editing HEALABLE_SERVICES changes the dropdown with no code change.
        "choices": config_words(choices_key) if choices_key else None,
        "choices_from": choices_key,
        # A parameter that is never passed to a script cannot be an injection.
        # Saying so on the page is worth more than saying it in a comment only
        # the marker will read.
        "passed_to_script": bool(spec.get("pass_to_script")),
    }


# ===========================================================================
#  4. THE SHAPE OF THE COMMAND, BEFORE ANY VALUES EXIST
# ===========================================================================
def command_shape(action):
    """Show what the argv will look like, with <slots> where values will go.

    This is the answer to "what does my English turn into?" for an action the
    user has not filled in yet. It is built from the SAME fields
    guardian_actions.build_command() uses -- the script name, the fixed args,
    then the parameters in registry order -- so the shape shown and the command
    run cannot disagree about the order of anything.
    """
    if action["script"] is None:
        return f"(no command -- served inside Python by {action.get('native')})"

    parts = [f"linux/{action['script']}", *action["args"]]
    for spec in action["params"]:
        if not spec.get("pass_to_script"):
            continue
        slot = f"<{spec['name']}>"
        parts.append(slot if spec["required"] else f"[{slot}]")
    return " ".join(parts)


def shell_preview(argv):
    """Render an argv list the way a user would have to type it in a terminal.

    shlex.join quotes only what genuinely needs quoting, so 'notes' stays bare
    and 'hello world' gains quotes. THIS IS FOR READING, NOT FOR RUNNING:
    nothing in this project ever passes a string to a shell. The quoting is
    here so that a user copying the line into their own terminal gets the same
    result Guardian got -- and so that a value containing a space is visibly
    ONE argument on screen, which is the point being taught.
    """
    return shlex.join(argv) if argv else ""


# ===========================================================================
#  5. THE CATALOGUE -- every action, ready to render
# ===========================================================================
def action_guide(action_id):
    """Everything the console needs in order to teach one action."""
    action = ga.ACTIONS[action_id]
    return {
        "id": action_id,
        "description": action["description"],
        "danger": action["danger"],
        "category": action.get("category", "other"),
        "when": WHEN_TO_USE.get(action_id, ""),
        # The trigger phrases are read straight out of the matcher. There is no
        # second list to keep in step, so a phrase shown on the page is by
        # construction a phrase that works.
        "phrases": nlp.TRIGGERS.get(action_id, []),
        "example": example_sentence(action_id),
        # The sentence with nothing filled in: "create a file called <name>".
        # This is what the builder shows before the user has typed anything, so
        # the empty form already says which words are its own and which are the
        # user's -- and it is what the page falls back to with scripting off.
        "blank": sentence_for(action_id, {}),
        "template": TEMPLATES.get(action_id, ""),
        "shape": command_shape(action),
        "params": [describe_param(spec) for spec in action["params"]],
        "script": action["script"],
        "native": action.get("native"),
        "select": action.get("select"),
    }


def catalogue():
    """Every action, grouped for display. Read actions first inside each group.

    Sorting read before write inside a group is a small thing that matters: the
    first row of every group is something that cannot change the machine, so a
    nervous first-time user can always try the top one.
    """
    guides = [action_guide(action_id) for action_id in ga.ACTIONS]
    groups = []
    for key, label in CATEGORY_ORDER:
        members = [g for g in guides if g["category"] == key]
        if members:
            members.sort(key=lambda g: (g["danger"] == "write", g["id"]))
            groups.append({"key": key, "label": label, "actions": members})

    # Anything whose category is not in CATEGORY_ORDER still appears. A new
    # action added to the registry must never vanish from the page just because
    # nobody remembered to add its category here.
    placed = {g["id"] for group in groups for g in group["actions"]}
    leftover = [g for g in guides if g["id"] not in placed]
    if leftover:
        groups.append({"key": "other", "label": "Other", "actions": leftover})
    return groups


# ===========================================================================
#  6. THE TRANSLATOR -- English in, argv out, nothing executed
# ===========================================================================
def translate(action_id, params=None):
    """Answer "what would this do?" without doing it.

    Returns the sentence, the command, the plain-English effect and any
    validation errors. It is the read-only half of console_run(): the same
    validate() call, the same build_command() call, and then it STOPS.

    Everything it reports comes from the registry, so the preview cannot
    describe one thing while the confirm route runs another.
    """
    params = {key: value for key, value in (params or {}).items()
              if str(value).strip() != ""}

    action = ga.ACTIONS.get(action_id)
    if action is None:
        return {"ok": False, "action_id": action_id,
                "errors": [f"unknown action: {action_id!r} is not in the registry"],
                "sentence": "", "command": "", "argv": [], "effect": [],
                "danger": None}

    sentence = sentence_for(action_id, params)
    validation = ga.validate(action_id, params)

    if not validation.ok:
        # A half-filled form is the NORMAL state of a builder, not an error to
        # shout about -- so the errors come back as data and the caller decides
        # whether to show them. The sentence and the command shape are still
        # returned, because they are exactly what a user needs to see while
        # they work out what is missing.
        return {"ok": False, "action_id": action_id, "errors": validation.errors,
                "sentence": sentence, "command": command_shape(action),
                "argv": [], "effect": [], "danger": action["danger"],
                "description": action["description"]}

    argv = ga.build_command(validation)

    # describe_effect only covers write actions -- a read action's "effect" is
    # simply the answer it returns, and inventing a sentence for that would be
    # padding.
    try:
        effect = ga.describe_effect(validation)
    except ga.SandboxError as error:
        # Reachable only if the registry pattern and the sandbox rule ever
        # disagree, which is exactly the pair test_actions.py compares. Report
        # it rather than raising: a builder that 500s while somebody types is
        # worse than one that says why it refused.
        return {"ok": False, "action_id": action_id, "errors": [str(error)],
                "sentence": sentence, "command": command_shape(action),
                "argv": [], "effect": [], "danger": action["danger"],
                "description": action["description"]}

    return {
        "ok": True,
        "action_id": action_id,
        "description": action["description"],
        "danger": action["danger"],
        "sentence": sentence,
        "argv": argv or [],
        "command": shell_preview(argv) if argv else
                   f"(served inside Python by {action.get('native')})",
        "effect": effect,
        "params": validation.params,
        "errors": [],
    }


def understand(text):
    """Dry-run the matcher on a sentence: what WOULD the console do with this?

    Used by the live "as you type" line under the ask box. It runs exactly the
    cascade console_run() runs -- keyword dictionary, then the optional model --
    and then stops before validate() would have been followed by execute().

    Returning `will_run` as a separate boolean from `ok` keeps the two
    questions apart on the page:
        ok        Guardian understood the sentence
        will_run  and it is a read action, so pressing Run acts immediately
    A write action understood perfectly still answers will_run=False, because
    pressing Run gives a preview.
    """
    text = (text or "").strip()
    if not text:
        return {"state": "empty", "sentence": "", "candidates": []}

    candidates, matched_by = nlp.resolve(text)
    threshold = nlp.min_confidence()

    if not candidates:
        return {"state": "no_match", "matched_by": matched_by, "candidates": [],
                "threshold": threshold}

    listed = [{
        "action_id": c.action_id,
        "confidence": c.raw_confidence,
        "phrase": c.phrase,
        "danger": ga.ACTIONS[c.action_id]["danger"],
        "description": ga.ACTIONS[c.action_id]["description"],
    } for c in sorted(candidates, key=lambda c: -c.raw_confidence)]

    top = candidates[0]
    if top.confidence < threshold:
        return {"state": "ambiguous", "matched_by": matched_by,
                "candidates": listed, "threshold": threshold}

    preview = translate(top.action_id, top.params)
    return {
        "state": "ok",
        "matched_by": matched_by,
        "threshold": threshold,
        "action_id": top.action_id,
        "confidence": top.confidence,
        "phrase": top.phrase,
        "danger": preview["danger"],
        "description": preview.get("description", ""),
        "command": preview["command"],
        "will_run": preview["danger"] == "read",
        "params": top.params,
        "candidates": listed,
        "errors": preview["errors"],
    }


# ===========================================================================
#  7. INTEGRITY -- the same idea as check_registry()
# ===========================================================================
def check_guide():
    """Report anything in this file that has fallen out of step with the registry.

    Run by test_guide.py. The failure this is really guarding against is an
    action being added to actions.json and silently getting no guidance, which
    would leave a blank card on the page rather than an error anybody notices.
    """
    problems = []

    for action_id in ga.ACTIONS:
        if action_id not in TEMPLATES:
            problems.append(f"{action_id}: no sentence template")
        if action_id not in WHEN_TO_USE:
            problems.append(f"{action_id}: no 'when to use' sentence")
        if not nlp.TRIGGERS.get(action_id):
            problems.append(f"{action_id}: no trigger phrases in guardian_nlp")

    for action_id in TEMPLATES:
        if action_id not in ga.ACTIONS:
            problems.append(f"{action_id}: template for an action that does not exist")

    # Every slot in a template must be a parameter the action really declares.
    # Without this check a renamed parameter would leave the builder writing
    # "<oldname>" into a sentence for ever.
    for action_id, template in TEMPLATES.items():
        action = ga.ACTIONS.get(action_id)
        if action is None:
            continue
        declared = {spec["name"] for spec in action["params"]}
        for slot in _SLOT.findall(template):
            if slot not in declared:
                problems.append(
                    f"{action_id}: template names {{{slot}}}, "
                    f"which is not a parameter of that action"
                )

    return problems
