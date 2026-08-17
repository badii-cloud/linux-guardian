#!/usr/bin/env python3
"""
Linux Guardian -- app.py                                        (Phase 5)

The web layer. It owns no logic of its own: every number on the page was
produced by a Bash script in linux/, and every action is carried out by one.
Flask's only jobs are to run those scripts, parse their JSON, and hand the
result to a Jinja2 template.

    Firefox (localhost:5000) -> Flask -> subprocess -> Bash modules -> Kali

THE SECURITY RULE THIS FILE IS BUILT AROUND
-------------------------------------------
An HTTP request never supplies a command, a path, or an argument. It supplies a
NAME, which is looked up in a dictionary defined here in the source. If the name
is not a key in that dictionary, the request is rejected before anything runs.

That is the difference between:

    BAD   subprocess.run(f"linux/{name}.sh", shell=True)
          A request for  ?name=x;rm -rf ~  runs two commands.

    GOOD  script = ALLOWED_MODULES[name]      # KeyError -> 404, nothing runs
          subprocess.run([script], shell=False)

Nothing in this file ever builds a command out of user input, and shell=False
(the default) is never overridden, so there is no shell to interpret a ";" even
if one somehow arrived.

Run with:  python3 app.py      then open http://127.0.0.1:5000
"""

from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, url_for

# Phase 6. These three modules hold ALL of the console's logic, and none of
# them import Flask -- which is what lets test_actions.py prove the validator
# and the matcher from the command line, with no web server running.
import guardian_actions as ga
import guardian_nlp as nlp
# Phase 9. Two presenters, and neither of them can act. guardian_guide turns the
# registry into guidance (which words work, what the Bash command will be);
# guardian_explain turns an incident record into plain English. Both are
# asserted against their own parsed syntax tree to import neither `subprocess`
# nor `os`, so no amount of editing a template can make one of them run
# something.
import guardian_explain as explain
import guardian_guide as guide
from guardian_config import read_config
from guardian_system import module_data as system_module_data
from guardian_system import run_script as system_run_script

# Phases 7 and 8. Same rule as above: none of them import Flask, so every one
# is testable from a terminal with no web server running. The web layer adds
# routes and templates on top of logic that already works without it.
import guardian_anomaly as anomaly
import guardian_incidents as gi
import guardian_remediate as remediate
import guardian_rootcause as rootcause
import guardian_store as gs
import guardian_preflight as preflight

# ---------------------------------------------------------------------------
# WHERE THINGS ARE
#
# Path(__file__).resolve() is the absolute path of THIS file, following any
# symlink. .parent is the directory holding it. Everything else is derived from
# that, so the project keeps working if it is moved or copied -- exactly the
# same reasoning as ${BASH_SOURCE[0]} in the shell scripts.
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
LINUX_DIR = PROJECT_ROOT / "linux"
CONFIG_FILE = PROJECT_ROOT / "config" / "guardian.conf"
LOG_FILE = PROJECT_ROOT / "logs" / "guardian.log"

# How long to wait for a Bash module before giving up. It has to be generous:
# system.sh and process.sh each sample the CPU for a second, and diagnosis.sh
# runs all four modules one after another. A timeout is still essential -- a
# hung script must produce an error card, never a browser tab that spins for
# ever.
SCRIPT_TIMEOUT_SECONDS = 60

# ---------------------------------------------------------------------------
# THE ALLOW LIST OF MODULES
#
# Keys are the only module names the application will ever accept from a URL.
# Values are plain filenames that appear nowhere in a request. Adding a module
# means editing this file; it can never be done by crafting a URL.
# ---------------------------------------------------------------------------
ALLOWED_MODULES = {
    "system": "system.sh",
    "network": "network.sh",
    "process": "process.sh",
    "services": "services.sh",
    "diagnosis": "diagnosis.sh",
}

app = Flask(__name__)

# PHASE 9. `status_label` turns WAITING_APPROVAL into "Waiting for you" for
# display. Registered as a Jinja global rather than passed by each route,
# because a status appears on four pages and the one that forgot to pass it
# would be the one showing SHOUTING_SNAKE_CASE to a marker.
#
# THE VALUE ITSELF IS NEVER CHANGED. The status stays WAITING_APPROVAL in the
# database, in the CSS class and in the state machine -- only the printed text
# differs. Renaming a key to make it read better is how a state machine
# acquires two spellings of the same state.
app.jinja_env.globals["status_label"] = explain.status_label


# ---------------------------------------------------------------------------
def read_guardian_conf():
    """Read config/guardian.conf into a dictionary.

    guardian.conf is a Bash file, but it is deliberately written as nothing
    more than KEY="value" lines so that Python can read it too without
    executing it. That distinction matters: `source guardian.conf` in Bash runs
    the file, and running a config file from a web process would mean any edit
    to it becomes code executed by the server. Here we only ever MATCH text.

    The regular expression, piece by piece:
        ^\\s*            optional leading spaces
        ([A-Z_][A-Z0-9_]*)   the key: capitals, digits and underscores
        \\s*=\\s*        the equals sign, spaces allowed around it
        "?([^"#]*)"?     the value, with optional quotes, stopping at a #
    Lines that do not match -- comments, blank lines -- are simply skipped.
    """
    return read_config()


def healable_services():
    """The set of services the Heal button may be offered for.

    Read from guardian.conf so that this list and the one healing.sh enforces
    can never drift apart. This is defence in depth, not the actual control:
    even if a request for another service were forged by hand, healing.sh
    checks PROTECTED_SERVICES and HEALABLE_SERVICES again before acting.
    """
    return set(read_guardian_conf().get("HEALABLE_SERVICES", "apache2").split())


def command_briefing(diagnosis=None):
    """Turn existing evidence into one safe, operator-controlled next step."""
    try:
        open_incidents = gi.listing(status="open", limit=1)
    except gs.StoreError:
        open_incidents = []

    if open_incidents:
        incident = open_incidents[0]
        return {
            "state": "ATTENTION", "title": incident["title"],
            "detail": (f"Open incident · risk {incident['risk_score']}/100 · "
                       f"{incident['severity']} severity"),
            "href": url_for("incident_page", incident_id=incident["id"]),
            "link": "Review evidence",
        }

    checks = (diagnosis or {}).get("checks") or []
    concerning = next((check for check in checks
                       if check.get("result") in ("WARNING", "FAIL")), None)
    if concerning:
        return {"state": "WATCH", "title": f"Watch {concerning['label']}",
                "detail": concerning.get("message") or "A threshold needs attention.",
                "href": url_for("dashboard"), "link": "View check details"}

    return {"state": "STEADY", "title": "System steady",
            "detail": "No open incidents. Guardian is collecting evidence in the background.",
            "href": url_for("automation_page"), "link": "View automation"}


# ---------------------------------------------------------------------------
def run_script(filename, arguments=None):
    """Run one Bash module and return its parsed JSON.

    Returns a dict. On any failure it returns a dict shaped like the modules'
    own error output, so the templates only ever deal with one shape and never
    have to guard against None.

    THE THREE THINGS THAT MAKE THIS SAFE:

      1. The command is a LIST, not a string: [script, arg]. Python passes the
         list straight to execve(), so the arguments arrive at the program
         exactly as written. A value containing a space, a semicolon or a quote
         is one argument, not a new command.

      2. shell=False -- the default, never overridden. There is no shell in the
         picture at all, so shell metacharacters have nothing to interpret them.

      3. `filename` comes from ALLOWED_MODULES, never from the request.
    """
    return system_run_script(filename, arguments)


def _error(message):
    """Build the same error shape the Bash modules produce themselves."""
    return {"status": "error", "message": message}


def module_data(name):
    """Look a module up in the allow list and run it. Unknown name -> 404."""
    if name not in ALLOWED_MODULES:
        abort(404, description=f"unknown module: {name}")
    return system_module_data(name)


# ---------------------------------------------------------------------------
#  ROUTES
# ---------------------------------------------------------------------------
@app.route("/")
def dashboard():
    """The main page: overall score, the individual checks, and live metrics.

    EVERY NUMBER IS RENDERED BY JINJA, INCLUDING THE ONES JAVASCRIPT LATER
    UPDATES. The first version of this page left the risk and history figures
    as "--" for the client script to fill in, which meant they stayed "--" for
    ever with JavaScript disabled, and flashed "--" on every page load with it
    enabled. The live refresh is an improvement on a correct page, never the
    thing that makes it correct.
    """
    try:
        incident_summary = gi.summary()
    except gs.StoreError:
        incident_summary = None
    try:
        store_stats = gs.stats()
    except gs.StoreError:
        store_stats = None
    diagnosis = module_data("diagnosis")

    return render_template(
        "index.html",
        diagnosis=diagnosis,
        system=module_data("system"),
        network=module_data("network"),
        services=module_data("services"),
        healable=healable_services(),
        incident_summary=incident_summary,
        store=store_stats,
        briefing=command_briefing(diagnosis),
    )


@app.route("/processes")
def processes():
    """The top-consumers table."""
    return render_template("processes.html", process=module_data("process"))


@app.route("/logs")
def logs():
    """The audit trail written by healing.sh and guardian-daemon.sh.

    Only the last lines are shown, newest first. The file is read here rather
    than shelled out to `tail`, because Python can do it without starting a
    process -- and because there is no user input involved, so there is nothing
    to sanitise.
    """
    try:
        lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    return render_template("logs.html", lines=list(reversed(lines[-200:])), log_path=LOG_FILE)


@app.route("/api/<module_name>")
def api(module_name):
    """Return a module's JSON unchanged, for testing with curl or jq.

    The <module_name> part of the URL is whatever the visitor typed, so it is
    passed to module_data(), which refuses anything not in ALLOWED_MODULES.
    """
    return module_data(module_name)


@app.route("/heal/<service_name>", methods=["POST"])
def heal(service_name):
    """Ask healing.sh to recover one service.

    METHOD=POST, NOT GET, AND THAT IS NOT A DETAIL. A GET is supposed to be
    safe to repeat: browsers pre-fetch them, and every crawler and "open all
    tabs" action would trigger a service restart. Anything that CHANGES the
    system must be a POST.

    TWO INDEPENDENT CHECKS GUARD THIS ROUTE:
      1. here      -- the name must be in the allow list read from guardian.conf
      2. in Bash   -- healing.sh re-checks PROTECTED_SERVICES and
                      HEALABLE_SERVICES and validates the characters again
    Neither trusts the other. Deleting either one still leaves the system safe.
    """
    if service_name not in healable_services():
        abort(403, description=f"{service_name} is not an allowed healing target")

    result = run_script("healing.sh", [service_name])
    return render_template("heal.html", result=result, service=service_name)


# ---------------------------------------------------------------------------
#  PHASE 6 -- THE NATURAL-LANGUAGE CONSOLE
# ---------------------------------------------------------------------------
#
# The history of what has been asked this session. It is a plain list in
# memory, NOT a database and NOT a cookie, because:
#   - the audit trail that actually matters is already logs/guardian.log, which
#     survives a restart and is what a marker should be shown;
#   - this list exists only so the page can show "what I just did", and losing
#     it when the server restarts is the correct behaviour for that.
# Capped so a long demo cannot grow it without limit.
CONSOLE_HISTORY = []
HISTORY_LIMIT = 20


def remember(entry):
    """Put one console interaction at the top of the history."""
    CONSOLE_HISTORY.insert(0, entry)
    del CONSOLE_HISTORY[HISTORY_LIMIT:]


@app.route("/console", methods=["GET"])
def console():
    """The console page, with nothing run yet."""
    return render_template(
        "console.html",
        actions=ga.ACTIONS,
        # PHASE 9. The catalogue is the guided builder: every action with the
        # words that trigger it, the parameters it takes, and the shape of the
        # Bash command it becomes. Built from the registry and the matcher's own
        # trigger dictionary, so a card cannot describe an action that does not
        # exist and an example cannot use a phrase that does not match.
        catalogue=guide.catalogue(),
        history=CONSOLE_HISTORY,
        threshold=nlp.min_confidence(),
        workspace=str(ga.workspace_dir()),
    )


@app.route("/console", methods=["POST"])
def console_run():
    """Understand one request and, if it is a READ action, run it.

    THE WHOLE SAFETY ARGUMENT IN ONE PLACE:
      1. The text is turned into an ACTION ID by the matcher. The matcher can
         only ever return an id that exists in TRIGGERS, and every one of those
         is a key in the registry.
      2. That id and its parameters go through ga.validate(), which re-checks
         the id against the registry and every parameter against its declared
         pattern. Nothing the matcher produced is trusted.
      3. Only then is a command built -- as a LIST, by the registry, from a
         script filename a human wrote.
      4. A 'write' action stops here and returns a preview instead of running.

    POST, not GET, because this can execute something. A GET is supposed to be
    safe to repeat, and browsers pre-fetch them.
    """
    text = (request.form.get("q") or "").strip()

    # The picker posts an explicit id when the user chose from the candidate
    # list. It is still just a NAME -- validate() decides whether it is real.
    chosen = (request.form.get("action_id") or "").strip()

    # PHASE 9. The guided builder posts its fields as console_param_<name>,
    # the same convention the confirm route has used since Phase 6, so the two
    # can never collide with the form's own fields (q, action_id).
    #
    # THIS IS NOT A NEW WAY IN. A parameter typed into a labelled box and a
    # parameter pulled out of a sentence by a regular expression arrive at
    # ga.validate() as exactly the same thing: a string, against an anchored
    # pattern declared in the registry. The builder is a nicer keyboard, not a
    # different door -- test_guide.py section 7 re-runs the whole Phase 6
    # hostile-input list through it to prove that.
    typed_params = {
        key[len("console_param_"):]: value
        for key, value in request.form.items()
        if key.startswith("console_param_") and value != ""
    }

    result = {"query": text, "chosen": chosen}

    if not text and not chosen:
        result["state"] = "empty"
        return _console_page(result)

    # --- 1. Work out WHICH action ----------------------------------------
    if chosen:
        # Two ways to arrive here, and they want different parameters:
        #   the guided builder  -> the user filled labelled fields, use those
        #   the "did you mean" picker -> re-extract from the sentence they typed
        # Explicit fields win, because a value somebody typed into a box marked
        # "name" is a better statement of intent than one a regex found.
        params = typed_params or (nlp.extract_params(text) if text else {})
        candidates = []
        action_id = chosen
        confidence = 1.0
        source = "chosen from the guide" if typed_params else "chosen by user"
    else:
        # THE THREE-ATTEMPT CASCADE: keyword dictionary, then Ollama only if
        # that found nothing, then give up. See guardian_nlp.resolve().
        candidates, matched_by = nlp.resolve(text)
        result["matched_by"] = matched_by

        if not candidates:
            result["state"] = "no_match"
            # Explain WHY nothing matched, including whether the optional model
            # was even available to be asked. "Ollama is not running" turns a
            # dead end into something the user can act on.
            result["ollama_ok"], result["ollama_detail"] = nlp.ollama_status()
            ga.log("REFUSED", f"could not understand: {text!r}")
            return _console_page(result)

        top = candidates[0]
        if top.confidence < nlp.min_confidence():
            # NEVER GUESS. Show the candidates and let the human decide.
            result["state"] = "ambiguous"
            # Sorted by the score each reading EARNED, so the list the user
            # picks from reads in a sensible order. c.confidence may have been
            # clamped by the ambiguity rule -- that governs whether anything
            # runs, not how the options are presented.
            result["candidates"] = [
                {"id": c.action_id,
                 "confidence": c.raw_confidence,
                 "description": ga.ACTIONS[c.action_id]["description"],
                 "danger": ga.ACTIONS[c.action_id]["danger"]}
                for c in sorted(candidates, key=lambda c: -c.raw_confidence)
            ]
            ga.log("REFUSED", f"not confident enough for {text!r} "
                              f"(best {top.action_id} at {top.confidence})")
            return _console_page(result)

        action_id = top.action_id
        params = top.params
        confidence = top.confidence
        if top.source == "ollama":
            source = f"classified by {nlp.ollama_model()}"
        else:
            source = f"keyword match on {top.phrase!r}"

    # --- 2. Validate the id and every parameter --------------------------
    validation = ga.validate(action_id, params)
    result["action_id"] = action_id
    result["confidence"] = confidence
    result["source"] = source

    if not validation.ok:
        result["state"] = "invalid"
        result["errors"] = validation.errors
        ga.log("REFUSED", f"{action_id} rejected: {validation.errors[0]}")
        return _console_page(result)

    action = validation.action
    result["description"] = action["description"]
    result["danger"] = action["danger"]
    result["params"] = validation.params

    # --- 3. A write action never runs on the first request ---------------
    #
    # THIS IS THE CONFIRMATION RULE. The user gets a description of what would
    # happen and has to ask again, deliberately, before anything changes. The
    # request that arrives here is treated as a QUESTION, never as an
    # instruction, no matter how confident the matcher was.
    if action["danger"] == "write":
        result["state"] = "preview"
        result["command"] = ga.build_command(validation)
        result["effect"] = ga.describe_effect(validation)
        ga.log("ACTION", f"{action_id} previewed, awaiting confirmation: "
                         f"{validation.params}")
        return _console_page(result)

    # --- 4. Read actions run immediately ---------------------------------
    outcome = ga.execute(validation)
    result["state"] = "ok" if outcome["status"] == "ok" else "failed"
    result["data"] = outcome.get("data")
    result["message"] = outcome.get("message")

    # PHASE 9. A request that came from the guided builder has no sentence of
    # its own, and the first version recorded the bare action id -- so the
    # history read "create_file -- create_file", which says nothing and teaches
    # nothing. guardian_guide can rebuild the English the filled-in form
    # corresponds to, so the history shows the sentence the user COULD have
    # typed to get the same result. That is the whole point of the builder: it
    # is a way to learn the phrasing, not a permanent replacement for it.
    remember({"query": text or guide.sentence_for(action_id, validation.params),
              "action_id": action_id,
              "state": result["state"],
              "confidence": confidence})
    return _console_page(result)


@app.route("/api/console/translate")
def api_console_translate():
    """Answer "what would this do?" without doing it.                (Phase 9)

    Two questions, one endpoint, because the console asks them from the same
    keystroke handler:

        ?q=<sentence>       what does the matcher make of this English?
        ?action_id=<id>     what command would this filled-in form produce?
                            (+ console_param_<name>=... for the values)

    A GET, AND THAT IS NOT AN OVERSIGHT. The rule this project uses everywhere
    else is "anything that changes something is a POST, because browsers
    pre-fetch GETs". The reasoning holds here and gives the opposite answer:
    this route changes nothing at all. It runs the matcher, runs the validator,
    and calls build_command(), which assembles a LIST and hands it to nobody.
    Pre-fetching it is harmless, which is exactly the test for whether a GET is
    appropriate.

    guardian_guide imports neither `subprocess` nor `os`, asserted against its
    parsed syntax tree by test_guide.py, so "this endpoint cannot execute
    anything" is a property of the module rather than a promise made here.
    """
    action_id = (request.args.get("action_id") or "").strip()

    if action_id:
        params = {
            key[len("console_param_"):]: value
            for key, value in request.args.items()
            if key.startswith("console_param_") and value != ""
        }
        return {"status": "ok", "kind": "action",
                **guide.translate(action_id, params)}

    return {"status": "ok", "kind": "sentence",
            **guide.understand(request.args.get("q", ""))}


@app.route("/console/confirm", methods=["POST"])
def console_confirm():
    """Execute a write action the user has explicitly confirmed.

    THE ONLY ROUTE IN PHASE 6 THAT CHANGES ANYTHING.

    It does NOT trust the preview it came from. The form carries an action id
    and some parameters, exactly like any other request, and they go through
    ga.validate() again from scratch. Forging this POST by hand with curl gets
    a would-be attacker precisely nothing that the console would not already
    have allowed -- which is the property that makes the preview a usability
    feature rather than the security boundary. The security boundary is, as
    always, the registry.
    """
    action_id = (request.form.get("action_id") or "").strip()

    # Parameters arrive as console_param_<name>, so they can never collide with
    # the form's own fields (action_id, q). Each is still just a string that
    # has to survive validation.
    params = {
        key[len("console_param_"):]: value
        for key, value in request.form.items()
        if key.startswith("console_param_") and value != ""
    }

    result = {"query": request.form.get("q", ""), "action_id": action_id,
              "confirmed": True}

    validation = ga.validate(action_id, params)
    if not validation.ok:
        result["state"] = "invalid"
        result["errors"] = validation.errors
        ga.log("REFUSED", f"{action_id} rejected at confirm: {validation.errors[0]}")
        return _console_page(result)

    action = validation.action
    result["description"] = action["description"]
    result["danger"] = action["danger"]
    result["params"] = validation.params

    # A read action reaching this route is not an attack, but it is a sign
    # something is wrong, so it is refused rather than quietly allowed.
    if action["danger"] != "write":
        result["state"] = "invalid"
        result["errors"] = [f"{action_id} is a read action and does not need confirming"]
        return _console_page(result)

    ga.log("ACTION", f"{action_id} confirmed by user: {validation.params}")

    outcome = ga.execute(validation)
    if outcome["status"] == "ok":
        result["state"] = "done"
        result["data"] = outcome["data"]
        detail = outcome["data"].get("message") if isinstance(outcome["data"], dict) else ""
        ga.log("SUCCESS", f"{action_id} -- {detail or 'completed'}")
    else:
        result["state"] = "failed"
        result["message"] = outcome["message"]
        ga.log("ERROR", f"{action_id} failed: {outcome['message']}")

    remember({"query": result["query"] or guide.sentence_for(action_id, validation.params),
              "action_id": action_id,
              "state": result["state"],
              "confidence": 1.0})
    return _console_page(result)


def _console_page(result):
    """Render the console with one result attached. One place, one shape."""
    return render_template(
        "console.html",
        actions=ga.ACTIONS,
        catalogue=guide.catalogue(),
        history=CONSOLE_HISTORY,
        threshold=nlp.min_confidence(),
        # The sandbox path, so a result can show WHERE a scheduled file will be
        # written without schedule.sh having to repeat it in its own JSON.
        workspace=str(ga.workspace_dir()),
        result=result,
    )


# ---------------------------------------------------------------------------
#  PHASES 7 AND 8 -- HISTORY, ANOMALIES, INCIDENTS
# ---------------------------------------------------------------------------
#
# THE SAME RULE AS EVERY ROUTE ABOVE. Nothing here takes a command, a path or a
# parameter from the request. An incident id is looked up and either exists or
# does not; a metric name is validated by the store's own character allow-list;
# an action id is checked against the incident's OWN recommended list by
# guardian_remediate, which then derives every parameter server-side.
#
# GET routes read. POST routes change something. That split is not decoration:
# browsers pre-fetch GETs, so anything reachable by a link must be safe to
# repeat, and everything that acts is unreachable except by a form submission.
# ---------------------------------------------------------------------------
@app.context_processor
def sidebar_context():
    """Values every page needs, supplied once instead of by every route.

    The sidebar shows how many incidents are open, on every page. Passing that
    through render_template() from each of the eleven routes would mean eleven
    places to forget it, and a sidebar that showed "0" on the one page somebody
    forgot would be worse than not showing a count at all.

    IT SWALLOWS ITS OWN ERRORS DELIBERATELY. This runs before every single
    template render, including the error page. If the database were unreadable
    and this raised, every page in the application would return 500 -- including
    the page explaining what went wrong. A missing count is a cosmetic problem;
    an unreachable error page is not.
    """
    try:
        open_incidents = gi.summary()["open"]
    except Exception:                                    # noqa: BLE001
        open_incidents = None
    return {"open_incidents": open_incidents, "guardian_host": _hostname()}


def _hostname():
    """This machine's name, for the sidebar footer.

    Read from /etc/hostname rather than shelled out to `hostname`, because
    there is no user input involved and the file is one open() -- starting a
    process to read a single word would be the more expensive way to be less
    reliable.
    """
    try:
        return Path("/etc/hostname").read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _incident_or_404(incident_id):
    """Look one incident up, turning a miss into a 404 rather than a traceback."""
    try:
        return gi.get(incident_id)
    except gi.IncidentError:
        abort(404, description=f"no such incident: {incident_id}")


@app.route("/incidents")
def incidents_page():
    """The incident list, newest first, filterable by status."""
    wanted = request.args.get("status") or "open"
    try:
        rows = gi.listing(status=wanted, limit=100)
    except gi.IncidentError:
        # An unknown status in the query string is the visitor's typo, not an
        # error worth a 404 -- fall back to the default view and say so.
        wanted = "open"
        rows = gi.listing(status="open", limit=100)
    return render_template(
        "incidents.html",
        incidents=rows,
        # PHASE 9. One short plain-English summary per row, keyed by incident
        # id. Built here rather than in the template because a Jinja loop
        # calling four functions per row is four chances to render one
        # incident's advice beside another's numbers.
        plain={row["id"]: explain.summarise(row) for row in rows},
        summary=gi.summary(),
        selected=wanted,
        statuses=gi.STATUSES,
        glossary=explain.GLOSSARY,
    )


@app.route("/incidents/<incident_id>")
def incident_page(incident_id):
    """One incident: evidence, root cause, timeline, and the buttons."""
    incident = _incident_or_404(incident_id)

    # What could be proposed, worked out WITHOUT proposing it -- the page needs
    # to know whether to offer a button, and asking propose() would move the
    # incident to WAITING_APPROVAL just by looking at the page.
    definition = gi.TYPES.get(incident["type"]) or {}
    writable = [
        action_id
        for action_id in (definition.get("recommended_actions") or [])
        if ga.ACTIONS.get(action_id, {}).get("danger") == "write"
    ]
    return render_template(
        "incident.html",
        incident=incident,
        # PHASE 9. The same record, said in English: what happened, why
        # Guardian said so, what it means, the one next step, and where this
        # incident has reached in its lifecycle. One call, so the four answers
        # on the page are always about the same incident.
        story=explain.explain(incident),
        glossary=explain.GLOSSARY,
        actions=ga.ACTIONS,
        writable=writable,
        # THE COMMANDS A PERSON CAN RUN WHEN GUARDIAN MAY NOT. Only offered
        # when there is no permitted remediation, because when there IS one the
        # page should be steering the reader towards the approval step rather
        # than towards a terminal. They are strings for the reader to copy;
        # this route neither runs them nor offers anything that could.
        manual_steps=explain.manual_steps(incident) if not writable else [],
        open_statuses=gi.OPEN_STATUSES,
    )


@app.route("/incidents/<incident_id>/investigate", methods=["POST"])
def incident_investigate(incident_id):
    """Run the incident type's declared READ-ONLY investigation.

    A POST even though it changes nothing on the machine, because it does change
    the incident: it appends to the timeline and moves DETECTED to
    INVESTIGATING. A GET that rewrote a record would be pre-fetched by the
    browser and would investigate every incident the user merely hovered over.
    """
    _incident_or_404(incident_id)
    try:
        rootcause.analyse(incident_id)
    except (rootcause.RootCauseError, gi.IncidentError, gs.StoreError) as error:
        abort(503, description=f"Investigation could not be saved: {error}")
    return redirect(url_for("incident_page", incident_id=incident_id))


@app.route("/incidents/<incident_id>/remediate", methods=["POST"])
def incident_remediate(incident_id):
    """Produce a PREVIEW and put the incident in front of a human.

    NOTHING RUNS HERE -- section 24 of the brief. The preview is a description,
    not an authorisation, and the incident moves to WAITING_APPROVAL so that the
    page can offer Approve and Reject as a separate, deliberate second step.
    """
    _incident_or_404(incident_id)
    try:
        remediate.propose(incident_id)
    except (remediate.RemediationError, gi.IncidentError) as error:
        abort(403, description=str(error))
    return redirect(url_for("incident_page", incident_id=incident_id))


@app.route("/incidents/<incident_id>/approve", methods=["POST"])
def incident_approve(incident_id):
    """Execute an approved remediation and verify it.

    THE ACTION ID COMES FROM THE FORM AND IS NOT TRUSTED. guardian_remediate
    re-reads the incident, checks the id against that incident type's own
    recommended list, derives every parameter server-side, and runs the registry
    validator again. A hand-crafted POST naming a different action is refused and
    the refusal is written to the incident's timeline as evidence.
    """
    _incident_or_404(incident_id)
    action_id = (request.form.get("action") or "").strip()
    try:
        remediate.approve(incident_id, action_id, operator="web")
    except (remediate.RemediationError, gi.IncidentError) as error:
        abort(403, description=str(error))
    return redirect(url_for("incident_page", incident_id=incident_id))


@app.route("/incidents/<incident_id>/reject", methods=["POST"])
def incident_reject(incident_id):
    """Decline a proposed remediation and hand the incident back."""
    _incident_or_404(incident_id)
    try:
        remediate.reject(incident_id, "rejected from the web interface")
    except gi.IncidentError as error:
        abort(403, description=str(error))
    return redirect(url_for("incident_page", incident_id=incident_id))


@app.route("/incidents/<incident_id>/ignore", methods=["POST"])
def incident_ignore(incident_id):
    """Close an incident as understood and not worth acting on."""
    _incident_or_404(incident_id)
    try:
        gi.transition(incident_id, gi.IGNORED, "ignored from the web interface")
    except gi.IncidentError as error:
        abort(403, description=str(error))
    return redirect(url_for("incidents_page"))


@app.route("/security")
def security_page():
    """Security-relevant incidents and the exposure of this machine."""
    everything = gi.listing(limit=200)
    security = [i for i in everything if i["category"] == "SECURITY"]
    return render_template(
        "security.html",
        incidents=security,
        summary=gi.summary(),
        network=module_data("network"),
        types=[t for t in gi.TYPES.values() if t.get("security_relevant")],
    )


@app.route("/network")
def network_page():
    """Interfaces, gateway, DNS and the traffic history."""
    return render_template("network.html", network=module_data("network"))


@app.route("/services")
def services_page():
    """Every monitored service, and whether Guardian may heal it."""
    return render_template(
        "services.html",
        services=module_data("services"),
        healable=healable_services(),
    )


@app.route("/automation")
def automation_page():
    """The daemon, the collection settings and the history store."""
    try:
        store_stats = gs.stats()
    except Exception:                                    # noqa: BLE001
        store_stats = None
    return render_template(
        "automation.html",
        settings=read_guardian_conf(),
        store=store_stats,
        schedules=_schedules(),
    )


def _schedules():
    """The user timers Phase 6 created, or an empty list if schedule.sh fails."""
    validation = ga.validate("list_schedules", {})
    if not validation.ok:
        return []
    result = ga.execute(validation)
    data = result.get("data")
    if isinstance(data, dict):
        return data.get("schedules") or []
    return data if isinstance(data, list) else []


@app.route("/settings")
def settings_page():
    """Every threshold, grouped, read straight from guardian.conf.

    READ-ONLY, AND THAT IS A DECISION, not an unfinished feature. Section 42 of
    the brief asks for the settings to be centralised and validated; they are,
    in guardian.conf, which is the single source of truth for every script and
    every module. A web form that wrote to it would mean the web process could
    edit the file that defines its own limits -- including HEALABLE_SERVICES and
    PROTECTED_SERVICES. The page therefore shows the values and names the file
    to edit, which keeps the policy where a human with a text editor controls it.
    """
    return render_template(
        "settings.html",
        settings=read_guardian_conf(),
        config_path=CONFIG_FILE,
        groups=SETTING_GROUPS,
    )


@app.route("/guide")
def guide_page():
    """A plain-English map of Guardian for a first-time operator."""
    return render_template("guide.html")


@app.route("/readiness")
def readiness_page():
    """Show whether Guardian's safe operating boundaries are ready."""
    return render_template("readiness.html", report=preflight.report())


# The settings page groups keys under headings. Held here rather than in the
# template so the page cannot silently omit a key nobody assigned a group to:
# anything not listed below appears under "Other".
SETTING_GROUPS = (
    ("Thresholds", ("CPU_WARNING", "CPU_CRITICAL", "RAM_WARNING", "RAM_CRITICAL",
                    "DISK_WARNING", "DISK_CRITICAL", "LOAD_WARNING_PER_CORE",
                    "LOAD_CRITICAL_PER_CORE", "PROCESS_CPU_WARNING",
                    "PROCESS_CPU_CRITICAL")),
    ("Services", ("MONITORED_SERVICES", "PROTECTED_SERVICES", "HEALABLE_SERVICES",
                  "HEAL_VERIFY_ATTEMPTS", "HEAL_VERIFY_DELAY")),
    ("Monitoring", ("DISK_MOUNT", "CPU_SAMPLE_INTERVAL", "PING_TARGET", "PING_COUNT",
                    "PING_TIMEOUT", "TOP_PROCESS_COUNT", "METRICS_INTERFACE",
                    "METRICS_DISK_DEVICE")),
    ("Automation", ("DAEMON_INTERVAL", "DAEMON_SERVICE", "DAEMON_COLLECT",
                    "HISTORY_PRUNE_EVERY")),
    ("History", ("HISTORY_DB", "HISTORY_RETENTION_HOURS", "HISTORY_MAX_ROWS",
                 "HISTORY_RECENT_SECONDS")),
    ("Anomaly detection", ("ANOMALY_RECENT_SECONDS", "ANOMALY_BASELINE_SECONDS",
                           "ANOMALY_MIN_SAMPLES", "ANOMALY_Z_WARNING",
                           "ANOMALY_Z_CRITICAL", "ANOMALY_MIN_CHANGE_PERCENT",
                           "ANOMALY_TREND_LOOKBACKS", "ANOMALY_METRICS")),
    ("Risk and severity", ("RISK_WEIGHT_SEVERITY", "RISK_WEIGHT_CONFIDENCE",
                           "RISK_WEIGHT_IMPACT", "RISK_WEIGHT_PERSISTENCE",
                           "RISK_WEIGHT_RECURRENCE", "RISK_WEIGHT_SECURITY",
                           "RISK_PERSISTENCE_FULL", "RISK_RECURRENCE_FULL",
                           "RISK_UNKNOWN_CONFIDENCE", "SEVERITY_ESCALATE_AFTER",
                           "SEVERITY_MIN_CONFIDENCE_FOR_HIGH")),
    ("Console and AI", ("WORKSPACE_DIR", "WORKSPACE_MAX_BYTES", "SYSTEMD_USER_DIR",
                        "TIMER_PREFIX", "MATCH_MIN_CONFIDENCE", "OLLAMA_URL",
                        "OLLAMA_MODEL", "OLLAMA_TIMEOUT")),
)


# ---------------------------------------------------------------------------
#  JSON APIs -- what the charts and the live refresh read
# ---------------------------------------------------------------------------
@app.route("/api/incidents")
def api_incidents():
    """The incident list as JSON."""
    try:
        return {"status": "ok", "incidents": gi.listing(
            status=request.args.get("status") or "open", limit=100)}
    except gi.IncidentError as error:
        return {"status": "error", "message": str(error)}, 400


@app.route("/api/incidents/<incident_id>")
def api_incident(incident_id):
    """One incident with its timeline."""
    return {"status": "ok", "incident": _incident_or_404(incident_id)}


@app.route("/api/anomalies")
def api_anomalies():
    """The detector's current verdict on every metric."""
    try:
        return {"status": "ok", **anomaly.scan()}
    except (anomaly.AnomalyError, gs.StoreError) as error:
        return {"status": "error", "message": str(error)}, 400


@app.route("/api/series/<metric>")
def api_series(metric):
    """One metric's history, for a chart.

    THE METRIC NAME COMES FROM THE URL, and it is checked twice before it
    reaches the database: guardian_store's anchored character allow-list, and
    then the fact that an unknown metric has no rows and raises. There is no SQL
    built from it -- it travels as a bound parameter -- so the allow-list is
    defence in depth rather than the only thing standing between a visitor and
    the query.

    `seconds` is clamped rather than trusted: a request for a hundred years of
    history would be a cheap way to make the server do a lot of work.
    """
    try:
        seconds = max(60, min(int(request.args.get("seconds", 3600)), 7 * 24 * 3600))
    except ValueError:
        seconds = 3600

    try:
        kind = gs.latest(metric)
        if kind is None:
            return {"status": "error", "message": f"no history for {metric}"}, 404
        if kind["kind"] == gs.KIND_COUNTER:
            derived = gs.rate_series(metric, seconds=seconds)
            points = derived["points"]
            unit = "per second"
        else:
            points = gs.series(metric, seconds=seconds)
            unit = "value"
        # NEWEST_TS IS SENT EVEN WHEN THE WINDOW IS EMPTY, and that is the whole
        # point of it. An empty `points` list has two completely different
        # causes -- this metric has never been sampled, or it has been sampled
        # plenty but not recently -- and a chart that cannot tell them apart
        # says "no history yet" while fifteen hours of history sits in the
        # database. The reader is then hunting the wrong bug. `latest()` has
        # already been called above and costs exactly one row, so naming the
        # newest timestamp here is free and lets the browser say WHICH of the
        # two happened. `time.time()` is not used to compute an age server-side:
        # the browser has its own clock and does the subtraction itself, which
        # keeps the API a statement of fact rather than of elapsed time.
        return {
            "status": "ok", "metric": metric, "kind": kind["kind"], "unit": unit,
            "newest_ts": kind["ts"],
            "points": [{"ts": p["ts"], "value": p["value"]} for p in points],
        }
    except gs.StoreError as error:
        return {"status": "error", "message": str(error)}, 400


@app.route("/api/metrics")
def api_metrics():
    """Every metric name the history holds, with its kind."""
    try:
        return {"status": "ok", "metrics": gs.metrics_known()}
    except gs.StoreError as error:
        return {"status": "error", "message": str(error)}, 400


@app.route("/api/overview")
def api_overview():
    """The dashboard's headline numbers in one request.

    ONE ENDPOINT RATHER THAN FIVE, because the live refresh runs every ten
    seconds: five requests would mean five SQLite connections and five parses
    for one screen. The diagnosis sweep is deliberately NOT included -- it costs
    3.25 seconds, which is a third of the refresh interval.
    """
    payload = {"status": "ok", "system": module_data("system")}
    try:
        payload["incidents"] = gi.summary()
    except gs.StoreError as error:
        payload["incidents"] = {"error": str(error)}
    try:
        payload["store"] = gs.stats()
    except gs.StoreError as error:
        payload["store"] = {"error": str(error)}
    payload["briefing"] = command_briefing()
    return payload


@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(503)
def show_error(error):
    return render_template("error.html", code=error.code, message=error.description), error.code


@app.route("/refresh")
def refresh():
    """A plain link target that sends the browser back to the dashboard."""
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # host="127.0.0.1" binds to the LOOPBACK interface only, so the dashboard is
    # reachable from Firefox on this machine and from nowhere else. Using
    # "0.0.0.0" would publish it to the whole VMware network -- including a page
    # with a button that restarts services.
    #
    # debug=False is equally deliberate. Flask's debug mode serves an
    # interactive Python console on any error page; anyone who could reach it
    # would be able to execute arbitrary code as this user. It is off.
    app.run(host="127.0.0.1", port=5000, debug=False)
