#!/usr/bin/env python3
"""
Linux Guardian -- guardian_actions.py                              (Phase 6)

THE REGISTRY LOADER AND THE PARAMETER VALIDATOR.

This module is the wall between "some text a human typed" and "a process that
runs on this machine". Nothing else in Phase 6 is allowed to build a command.

    console text  ->  matcher  ->  action_id + params
                                        |
                                        v
                            THIS FILE: is that a real id?
                                       is every param the right shape?
                                       does the path stay in the sandbox?
                                        |
                                        v
                                 subprocess.run([list])

THE RULE THAT MAKES IT SAFE
---------------------------
A command is never assembled from text. It is assembled from:
  - a script filename that was written in actions.json by a human, and
  - parameters that have each been matched against an anchored regular
    expression declared next to that filename.

The language model can only choose an id. It cannot invent a flag, a path, a
pipe or a semicolon, because there is nowhere in this code that a string from
the model becomes part of a command.

ORDER OF OPERATIONS -- AND WHY IT IS THIS WAY ROUND
---------------------------------------------------
    normalise  ->  length cap  ->  regex  ->  allow-list  ->  path containment

Normalising FIRST is what lets a human type "thursday" or "12 pm" while the
validator still only ever approves the one exact spelling systemd understands.
Doing it the other way round -- validate then normalise -- would mean the value
that gets used is not the value that was checked, which is the classic way a
validator gets bypassed.
"""

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from guardian_config import (CONFIG_FILE, PROJECT_ROOT, config_path,
                             config_words, read_config, workspace_dir)

# ---------------------------------------------------------------------------
# WHERE THINGS ARE
#
# Same reasoning as app.py and as ${BASH_SOURCE[0]} in the shell scripts: every
# path is derived from the location of this file, so nothing breaks if the
# project is moved and no absolute /home/kali path is ever written down.
# ---------------------------------------------------------------------------
LINUX_DIR = PROJECT_ROOT / "linux"
REGISTRY_FILE = LINUX_DIR / "actions.json"
LOG_FILE = PROJECT_ROOT / "logs" / "guardian.log"

# Same generous timeout app.py uses, and for the same reason: system.sh and
# process.sh each sample the CPU for a second, and diagnosis.sh runs all four
# modules one after another. A timeout is still essential -- a hung script must
# produce an error card, never a page that spins for ever.
SCRIPT_TIMEOUT_SECONDS = 60


# ===========================================================================
#  1. READING config/guardian.conf
# ===========================================================================
def read_config():
    """Read guardian.conf into a plain dictionary of strings.

    guardian.conf is a Bash file, but it is deliberately written as nothing but
    KEY="value" lines so Python can read it WITHOUT executing it. That
    distinction is the whole point: `source guardian.conf` in Bash RUNS the
    file. A web process that ran its own config file would turn every edit to
    that file into code executed by the server. Here we only ever match text.

    The regular expression, piece by piece:
        ^\\s*                optional leading spaces
        ([A-Z_][A-Z0-9_]*)   the key: capitals, digits, underscores
        \\s*=\\s*            the '=', spaces tolerated around it
        "?([^"#]*)"?         the value, optional quotes, stopping at a comment
    """
    settings = {}
    pattern = re.compile(r'^\s*([A-Z_][A-Z0-9_]*)\s*=\s*"?([^"#]*)"?')
    try:
        for line in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("#"):
                continue
            match = pattern.match(line)
            if match:
                settings[match.group(1)] = match.group(2).strip()
    except OSError:
        pass
    return settings


def _expand(value):
    """Expand ONLY ${GUARDIAN_ROOT} and ${HOME} in a config value.

    WHY NOT os.path.expandvars: that function expands EVERY $NAME it finds,
    using this process's whole environment. A config value is trusted, but the
    environment a web server inherits is a much bigger surface than it needs to
    be, and expanding blindly is how a value picks up something nobody intended.
    Two named substitutions are all this project uses, so two is all that is
    implemented.
    """
    return (
        value
        .replace("${GUARDIAN_ROOT}", str(PROJECT_ROOT))
        .replace("${HOME}", str(Path.home()))
    )


def config_path(key, default):
    """Read one config key that holds a path, expanded and made absolute."""
    raw = read_config().get(key, default)
    return Path(_expand(raw))


def config_words(key):
    """Read one space-separated config list into a list of words.

    Used for MONITORED_SERVICES and HEALABLE_SERVICES, so that the service
    names live in guardian.conf exactly once (rule 3) instead of being copied
    into actions.json where they could silently drift apart.
    """
    return read_config().get(key, "").split()


def workspace_dir():
    """The one directory the console may write files into."""
    return config_path("WORKSPACE_DIR", str(PROJECT_ROOT / "workspace"))


# ===========================================================================
#  2. LOADING THE REGISTRY
# ===========================================================================
def _strip_docs(value):
    """Recursively drop every key beginning with '_'.

    JSON has no comment syntax, so actions.json documents itself in '_readme'
    and '_comment' keys. They are for the human reading the file and for the
    report; the program must not see them, or a '_comment' would look like a
    field with meaning.
    """
    if isinstance(value, dict):
        return {k: _strip_docs(v) for k, v in value.items() if not k.startswith("_")}
    if isinstance(value, list):
        return [_strip_docs(v) for v in value]
    return value


def load_registry():
    """Parse actions.json and return {action_id: action_dict}.

    Returns a dictionary rather than the raw list because every single lookup
    in this project is 'is this id known?', and a dict makes that lookup the
    natural thing to write -- an unknown id is a KeyError, not a subtle
    fall-through to some default.
    """
    raw = json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
    clean = _strip_docs(raw)
    return {a["id"]: a for a in clean["actions"]}


ACTIONS = load_registry()


def action_ids():
    """Every known id. This exact list is what the LLM is shown to choose from."""
    return list(ACTIONS.keys())


# ===========================================================================
#  3. NORMALISERS -- run BEFORE validation
# ===========================================================================

# Long-form and short-form day names -> the three-letter spelling systemd's
# OnCalendar= directive expects. Written out in full rather than computed with
# a date library because a professor can read this and confirm it is complete.
_DAYS = {
    "mon": "Mon", "monday": "Mon",
    "tue": "Tue", "tues": "Tue", "tuesday": "Tue",
    "wed": "Wed", "weds": "Wed", "wednesday": "Wed",
    "thu": "Thu", "thur": "Thu", "thurs": "Thu", "thursday": "Thu",
    "fri": "Fri", "friday": "Fri",
    "sat": "Sat", "saturday": "Sat",
    "sun": "Sun", "sunday": "Sun",
}


def normalise_day(value):
    """'thursday', 'THU', ' Thurs ' -> 'Thu'.

    An unrecognised word is returned UNCHANGED rather than corrected or
    guessed. That matters: 'funday' comes back as 'funday', fails the anchored
    pattern in actions.json, and the user gets told it is not a day. A
    normaliser that tried to guess would eventually guess wrong on a real word.
    """
    key = value.strip().lower()
    return _DAYS.get(key, value.strip())


# Accepts:  '12:00'  '12.00'  '12 pm'  '12pm'  '9am'  '9'  'noon'  'midnight'
_TIME_RE = re.compile(r"^(\d{1,2})(?:[:.](\d{2}))?\s*(am|pm)?$", re.IGNORECASE)


def normalise_time(value):
    """Turn everyday ways of writing a time into 24-hour HH:MM.

    THE NORMALISER DELIBERATELY DOES NOT JUDGE. If the user says '25:00' this
    returns '25:00', which then fails the pattern
    ^([01][0-9]|2[0-3]):[0-5][0-9]$ in actions.json and is reported as an
    invalid time. Keeping the judging in one place -- the declared pattern --
    means there is exactly one rule to read, not a rule plus a second opinion
    hidden in the parser.
    """
    text = value.strip().lower()

    # Two words worth special-casing because people really do type them.
    if text == "noon":
        return "12:00"
    if text == "midnight":
        return "00:00"

    match = _TIME_RE.match(text)
    if not match:
        return value.strip()

    hour = int(match.group(1))
    minute = int(match.group(2) or 0)
    suffix = match.group(3)

    # 12-hour clock conversion. Written as two explicit cases because the two
    # edge cases (12pm is noon, 12am is midnight) are exactly where a clever
    # one-line formula goes wrong.
    if suffix == "pm" and hour < 12:
        hour += 12
    elif suffix == "am" and hour == 12:
        hour = 0

    # %02d pads to two digits so '9:5' becomes '09:05' and the pattern matches.
    return f"{hour:02d}:{minute:02d}"


def normalise_name(value):
    """Tidy a file name without weakening the rule that judges it.

    One convenience: a trailing '.txt' is REMOVED, because a user who types
    'create notes.txt' plainly means the file called notes, and the extension
    is chosen by the script, not by them. Nothing else is stripped, so
    '../etc/passwd' stays '../etc/passwd' and is rejected a moment later, and
    'evil.sh' keeps its dot and is rejected too.
    """
    text = value.strip()
    if text.lower().endswith(".txt"):
        text = text[: -len(".txt")]
    return text


def normalise_service(value):
    """'Apache2', 'apache2.service' -> 'apache2'.

    systemd treats 'apache2' and 'apache2.service' as the same unit, and
    healing.sh already compares on the base name so that a rule written for
    'ssh' cannot be side-stepped by asking for 'ssh.service'. Stripping the
    suffix here keeps this validator agreeing with that one.
    """
    text = value.strip().lower()
    if text.endswith(".service"):
        text = text[: -len(".service")]
    return text


_NORMALISERS = {
    "day": normalise_day,
    "time": normalise_time,
    "name": normalise_name,
    "enum": normalise_service,
    "text": lambda v: v,          # content is kept exactly as typed
}


# ===========================================================================
#  4. THE VALIDATOR
# ===========================================================================
@dataclass
class Validation:
    """The result of checking one request. Never raises -- always reportable.

    ok      True only if the action exists AND every parameter passed.
    action  The registry entry, or None if the id was unknown.
    params  The NORMALISED, validated values. Safe to use. Empty if not ok.
    errors  Plain sentences suitable for showing to the user unmodified.
    """
    ok: bool
    action: dict = None
    params: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


def validate(action_id, raw_params=None):
    """Check an action id and its parameters. This is the only entry point.

    Returns a Validation. It never raises on bad input and never partially
    approves: if anything at all is wrong, ok is False and params is empty, so
    a caller that forgets to check `ok` still cannot run with a bad value.
    """
    raw_params = dict(raw_params or {})
    errors = []

    # --- 1. The id must be one we published. -------------------------------
    # This is the same check as app.py's ALLOWED_MODULES, and it is the one
    # that contains the language model: whatever it returns, if it is not a key
    # here, nothing runs.
    action = ACTIONS.get(action_id)
    if action is None:
        return Validation(
            ok=False,
            errors=[f"unknown action: {action_id!r} is not in the registry"],
        )

    declared = {p["name"]: p for p in action["params"]}

    # --- 2. Reject unknown parameter names outright. -----------------------
    # Silently ignoring an extra parameter is how a typo becomes a bug that
    # only shows up in a demo: the user asks for one thing, the typo is
    # dropped, and something subtly different runs. Refusing is louder and
    # safer.
    for supplied in raw_params:
        if supplied not in declared:
            errors.append(
                f"{action_id} does not take a parameter called {supplied!r}"
            )

    cleaned = {}
    for name, spec in declared.items():
        present = name in raw_params and str(raw_params[name]).strip() != ""

        # --- 3. Required parameters must actually be there. ----------------
        if not present:
            if spec["required"]:
                errors.append(f"{name} is required")
            continue

        value = str(raw_params[name])

        # --- 4. Cap the length BEFORE the regex. ---------------------------
        # A regular expression engine given a megabyte of text is a way to make
        # the server do a lot of work for one request. Checking a cheap
        # len() first means the expensive step only ever sees a bounded value.
        limit = spec.get("max_length", 200)
        if len(value) > limit:
            errors.append(
                f"{name} is too long: {len(value)} characters, the limit is {limit}"
            )
            continue

        # --- 5. Normalise, then validate the normalised value. -------------
        normalise = _NORMALISERS.get(spec["type"], lambda v: v.strip())
        value = normalise(value)

        # re.fullmatch, not re.match. re.match only anchors the START, so the
        # pattern ^[a-zA-Z0-9_-]{1,40}$ used with re.match would still accept
        # a value with a newline and a payload after it. fullmatch requires the
        # WHOLE string to match, which is what the anchors were written for.
        if not re.fullmatch(spec["pattern"], value, re.DOTALL):
            errors.append(_explain(action_id, name, spec, value))
            continue

        # --- 6. Allow-list, read from guardian.conf. -----------------------
        source = spec.get("choices_from")
        if source:
            allowed = config_words(source)
            if value not in allowed:
                errors.append(
                    f"{name}: {value!r} is not allowed. "
                    f"{source} permits: {', '.join(allowed) or '(nothing)'}"
                )
                continue

        cleaned[name] = value

    if errors:
        return Validation(ok=False, action=action, errors=errors)
    return Validation(ok=True, action=action, params=cleaned)


def _explain(action_id, name, spec, value):
    """Turn a failed pattern into a sentence a human can act on.

    'value does not match ^([01][0-9]|2[0-3]):[0-5][0-9]$' is true but useless
    to the person typing. Each type gets a sentence that says what IS accepted.
    """
    shown = value if len(value) <= 45 else value[:42] + "..."
    hints = {
        "name": "1 to 40 characters, letters digits underscore and hyphen only, "
                "starting with a letter, digit or underscore "
                "-- no dots, no slashes, and never a leading hyphen",
        "day":  "a day of the week, e.g. Monday, thu, Sat",
        "time": "a 24-hour time between 00:00 and 23:59, e.g. 14:30 or 2 pm",
        "enum": "letters, digits, @ . _ and - only",
        "text": "any text without a NUL byte",
    }
    hint = hints.get(spec["type"], f"must match {spec['pattern']}")
    return f"{action_id}.{name}: {shown!r} is not valid -- expected {hint}"


# ===========================================================================
#  5. THE SANDBOX
# ===========================================================================
class SandboxError(Exception):
    """Raised when a resolved path would land outside the workspace."""


# The file-name rule, written out again here on purpose.
#
# WHY NOT IMPORT IT FROM actions.json: this function is the LAST line of
# defence, and a last line of defence that reads its rule from the same file it
# is defending is not an independent check -- one bad edit to the registry
# would silently disarm both layers at once. Writing it out twice means an edit
# has to be made twice to be dangerous, and the test suite compares the two.
_SAFE_NAME = re.compile(r"^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,39}$")


def resolve_in_workspace(name, extension=".txt"):
    """Turn a name into an absolute path inside the workspace, or refuse.

    THREE CHECKS, EACH ANSWERING A DIFFERENT QUESTION:

      1. Is the name itself the right shape?  (a regex, on the text)
      2. Where would the filesystem REALLY put it?  (realpath, following every
         symbolic link and flattening every '..')
      3. Is that real destination still directly inside the workspace?

    Check 1 is done again here even though validate() already did it. That is
    not redundancy for its own sake: this function is importable and could be
    called by future code that forgot to validate first, and the cost of being
    sure is one regex. A name like '..' is exactly why -- with the extension
    appended it becomes '...txt', a perfectly legal filename that would pass a
    containment check on its own while being obvious nonsense.

    A regex reasons about the TEXT of a name. realpath reasons about WHERE the
    filesystem would put it. They are different questions, and a symlink
    planted inside the workspace is a case where only the second one is right.
    """
    if not _SAFE_NAME.fullmatch(name):
        raise SandboxError(
            f"refusing to build a path from {name!r}: "
            "a workspace name must be 1-40 characters of letters, digits, "
            "underscore or hyphen, and must not start with a hyphen"
        )

    root = workspace_dir().resolve()

    candidate = root / f"{name}{extension}"

    # strict=False: the file does not exist yet -- we are deciding whether we
    # are ALLOWED to create it. Any symlinks in the parts that DO exist are
    # still followed, which is the part that matters.
    resolved = candidate.resolve(strict=False)

    # Two checks, not one:
    #   is_relative_to  -- the path is somewhere under the workspace
    #   parent == root  -- and specifically directly in it, not in a subfolder
    if not resolved.is_relative_to(root) or resolved.parent != root:
        raise SandboxError(
            f"refusing to write outside the workspace: "
            f"{name!r} resolves to {resolved}, which is not directly inside {root}"
        )
    return resolved


# ===========================================================================
#  6. BUILDING THE COMMAND
# ===========================================================================
def build_command(validation):
    """Turn a PASSED validation into an argv list ready for subprocess.run().

    Returns a list, always. Never a string. Python hands a list straight to
    execve(), so each element arrives at the program as one argument no matter
    what is inside it -- a space, a semicolon and a quote are all just
    characters in an argument, because no shell ever sees them.

    Refuses to build anything from a validation that did not pass, so the
    unsafe path does not exist even if a caller forgets to check.
    """
    if not validation.ok:
        raise ValueError("build_command called on a validation that failed")

    action = validation.action
    if action["script"] is None:
        return None                      # served natively, see 'native'

    # The filename came from actions.json, written by a human. It is joined
    # with LINUX_DIR here and nowhere else, and no part of it came from a
    # request.
    command = [str(LINUX_DIR / action["script"])]

    # Fixed arguments first ('create', 'list', 'cancel'), also from the file.
    command.extend(action["args"])

    # Then the validated parameters, in the order the registry declares them.
    for spec in action["params"]:
        if spec.get("pass_to_script") and spec["name"] in validation.params:
            command.append(validation.params[spec["name"]])

    return command


# ===========================================================================
#  7. THE AUDIT TRAIL
# ===========================================================================
def log(level, message):
    """Append one line to logs/guardian.log in the EXISTING format.

    healing.sh and guardian-daemon.sh have written to this file since Phase 3
    as:
        2026-08-15 16:49:24 [SUCCESS] healing.sh: apache2 -- recovered ...

    Phase 6 writes the same shape with 'console' as the source, so the Logs
    page keeps working unchanged and one file still tells the whole story of
    what this machine was asked to do. Levels are the ones already in use:
    [ACTION] before, [SUCCESS] or [ERROR] after, [REFUSED] when a guard said no.

    A failure to log must never break the request that was being logged, so the
    write is wrapped: the user's action still completes if the disk is full.
    """
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp} [{level}] console: {message}\n")
    except OSError:
        pass


# ===========================================================================
#  8. RUNNING AN ACTION
# ===========================================================================
def _read_log_tail(limit=40):
    """The native handler for show_logs. Reads the file, newest line first."""
    try:
        lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    return {"lines": list(reversed(lines[-limit:])), "path": str(LOG_FILE)}


NATIVE_HANDLERS = {
    "read_log": _read_log_tail,
}


def execute(validation):
    """Run a PASSED validation and return the part of the answer that was asked for.

    Refuses to run a validation that failed, so there is no code path in this
    module that executes an unchecked value.

    Returns a dict shaped like the Bash modules' own output, so the template
    only ever deals with one shape:
        {"status": "ok",    "data": ...}
        {"status": "error", "message": "..."}
    """
    if not validation.ok:
        raise ValueError("execute called on a validation that failed")

    action = validation.action

    # --- Natively served actions (show_logs) ------------------------------
    if action["script"] is None:
        handler = NATIVE_HANDLERS.get(action.get("native", ""))
        if handler is None:
            return {"status": "error",
                    "message": f"no native handler for {action['id']}"}
        return {"status": "ok", "data": handler()}

    command = build_command(validation)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,   # collect stdout/stderr instead of letting
                                   # them escape to the terminal
            text=True,             # decode to str, so we get "..." not b"..."
            timeout=SCRIPT_TIMEOUT_SECONDS,
            check=False,           # a non-zero exit is a RESULT we display
                                   # (healing.sh exits 1 when it refuses), not
                                   # an exception to swallow
        )
    except subprocess.TimeoutExpired:
        return {"status": "error",
                "message": f"{action['script']} took longer than "
                           f"{SCRIPT_TIMEOUT_SECONDS}s and was stopped"}
    except OSError as exc:
        return {"status": "error",
                "message": f"could not run {action['script']}: {exc}"}

    # Every module prints exactly one JSON object on stdout, even when it
    # fails, so this is normally all that is needed.
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        first = detail[0] if detail else "no output at all"
        return {"status": "error",
                "message": f"{action['script']} did not return valid JSON: {first}"}

    # The Bash contract says failures still produce valid JSON. Parsing JSON is
    # therefore not proof that the action succeeded: forwarding an error
    # document into a root-cause interpreter made Investigate look as if it had
    # run while it had collected no evidence.
    if payload.get("status") != "ok":
        return {"status": "error",
                "message": payload.get("message") or
                           f"{action['script']} reported status {payload.get('status')!r}"}

    return {"status": "ok", "data": _narrow(action, validation.params, payload)}


def _narrow(action, params, payload):
    """Apply the registry's 'select' and 'filter_by' to a module's full output.

    This is what lets a read action reuse a Phase 1 module WITHOUT changing it.
    system.sh still reports CPU, RAM, disk and load every time; check_disk
    simply declares select="disk", so the console answers the question that was
    actually asked instead of dumping everything.
    """
    selected = payload
    key = action.get("select")
    if key:
        selected = payload.get(key, payload)

    # filter_by narrows a LIST down to the one entry the parameter named --
    # used by check_service, where services.sh reports every monitored service
    # and the user asked about one of them.
    rule = action.get("filter_by")
    if rule and isinstance(selected, list):
        wanted = params.get(rule["param"])
        if wanted is not None:
            matches = [row for row in selected
                       if isinstance(row, dict) and row.get(rule["field"]) == wanted]
            selected = matches[0] if len(matches) == 1 else matches

    return selected


# ===========================================================================
#  9. THE PREVIEW
# ===========================================================================
_FULL_DAY = {
    "Mon": "Monday", "Tue": "Tuesday", "Wed": "Wednesday", "Thu": "Thursday",
    "Fri": "Friday", "Sat": "Saturday", "Sun": "Sunday",
}


def describe_effect(validation):
    """Say, in plain English, what confirming this action WILL do.

    Returns a list of (label, value) pairs. This is the whole point of the
    confirmation step: a user should never have to read a command line to know
    what is about to happen to their machine. The command is shown too, but
    underneath the sentence, not instead of it.

    IMPORTANT: this function only DESCRIBES. It touches nothing. The one thing
    it reads from disk is whether a file already exists, so the preview can
    honestly say "replace" rather than "create".
    """
    action = validation.action
    params = validation.params
    rows = []

    if action["id"] == "create_file":
        target = resolve_in_workspace(params["name"])
        verb = "Will replace" if target.exists() else "Will create"
        rows.append((verb, str(target)))
        if target.exists():
            rows.append(("Replacing", f"{target.stat().st_size} bytes already there"))
        if params.get("content"):
            rows.append(("Content", params["content"]))

    elif action["id"] == "schedule_file":
        target = resolve_in_workspace(params["name"])
        day = _FULL_DAY.get(params["day"], params["day"])
        unit = f"{read_config().get('TIMER_PREFIX', 'guardian-')}{params['name']}.timer"
        rows.append(("Will create", str(target)))
        rows.append(("Scheduled", f"every {day} at {params['time']} "
                                  f"(systemd user timer)"))
        rows.append(("Calendar", f"OnCalendar={params['day']} {params['time']}"))
        rows.append(("Command", f"systemctl --user enable --now {unit}"))

    elif action["id"] == "cancel_schedule":
        unit = f"{read_config().get('TIMER_PREFIX', 'guardian-')}{params['name']}.timer"
        rows.append(("Will stop and remove", unit))
        rows.append(("Command", f"systemctl --user disable --now {unit}"))
        rows.append(("Keeps", "the file it produced, in the workspace"))

    elif action["id"] == "heal_service":
        rows.append(("Will start", f"{params['service']}.service"))
        rows.append(("Command", f"sudo -n systemctl start {params['service']}.service"))

    return rows


# ===========================================================================
#  10. REGISTRY INTEGRITY
# ===========================================================================
def check_registry():
    """Report anything structurally wrong with actions.json.

    Run as part of the test suite so a typo in the registry is caught at the
    bench rather than during a demo.
    """
    problems = []
    for action_id, action in ACTIONS.items():
        if action["danger"] not in ("read", "write"):
            problems.append(f"{action_id}: danger must be 'read' or 'write'")

        if action["script"] is None:
            if not action.get("native"):
                problems.append(f"{action_id}: script is null but no native handler named")
        elif not (LINUX_DIR / action["script"]).exists():
            problems.append(f"{action_id}: script not found: linux/{action['script']}")

        for spec in action["params"]:
            try:
                re.compile(spec["pattern"])
            except re.error as exc:
                problems.append(f"{action_id}.{spec['name']}: bad pattern ({exc})")
            if not (spec["pattern"].startswith("^") and spec["pattern"].endswith("$")):
                problems.append(
                    f"{action_id}.{spec['name']}: pattern is not anchored with ^...$"
                )
            if spec["type"] not in _NORMALISERS:
                problems.append(f"{action_id}.{spec['name']}: unknown type {spec['type']!r}")
    return problems
