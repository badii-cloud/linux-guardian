#!/usr/bin/env python3
"""
Linux Guardian -- guardian_ollama.py                               (Phase 6)

THE OPTIONAL LOCAL LANGUAGE MODEL. Attempt number 2 of three:

    1. guardian_nlp.py    deterministic keyword matcher. Always available.
    2. THIS FILE          only if step 1 found NOTHING and Ollama is running.
    3. show the list      never guess, never execute.

Everything here is optional. If Ollama is not installed, not running, has no
model pulled, or answers with nonsense, every function in this file returns
None and the console carries on exactly as it did before. That is tested with
Ollama absent, which is the state this VM is actually in.

WHAT THE MODEL IS ALLOWED TO DO
-------------------------------
ONE THING: pick an id out of a list. It is given the user's sentence and the
action ids from the registry, and must answer with JSON of exactly this shape:

    {"action_id": "schedule_file",
     "params": {"name": "schedule", "day": "thursday", "time": "12:00"},
     "confidence": 0.91}

WHAT THE MODEL CAN NEVER DO
---------------------------
Produce a command. There is no code path anywhere in this project that turns
model output into a shell string, a path or a flag. Its answer is a NAME, and
that name is looked up in the registry -- the identical treatment an HTTP
request gets in app.py's ALLOWED_MODULES. If the model returns

    {"action_id": "rm -rf /"}

then `rm -rf /` is simply not a key in the registry, `_vet` returns None, and
nothing runs. The model cannot escalate beyond "suggest something that already
exists", because suggesting is all the surrounding code lets it do.

WHY THE PARAMETERS ARE RE-EXTRACTED RATHER THAN TRUSTED
-------------------------------------------------------
A language model can hallucinate: asked about Thursday it may confidently
answer "Friday". So the deterministic extractor in guardian_nlp.py is run over
the same sentence, and ANY parameter it finds overrides the model's. A regular
expression that located the literal word "thursday" in the text is better
evidence than a model's recollection of it. The model contributes the
classification; the regexes contribute the facts.

WHY urllib AND NOT requests
---------------------------
urllib is in the Python standard library, so there is nothing to install and
nothing that can be missing on the demo machine. `requests` happens to be
present on this VM, but depending on it would mean the console's behaviour
varies with what pip has done to a machine -- for a project that must work
offline and unattended, stdlib is the safer choice.
"""

import json
import urllib.error
import urllib.request

from guardian_actions import ACTIONS
from guardian_config import read_config

# How long to wait when merely ASKING whether Ollama is there. Kept short and
# separate from the generation timeout: discovering that a service is absent
# should be instant, and on 127.0.0.1 a refused connection returns immediately.
PROBE_TIMEOUT = 2.0


def settings():
    """Read the three Ollama settings from guardian.conf.

    Defaults are supplied for every one, so deleting the whole section from the
    config file disables the feature cleanly instead of raising.
    """
    config = read_config()
    try:
        timeout = float(config.get("OLLAMA_TIMEOUT", "8"))
    except ValueError:
        timeout = 8.0
    return {
        "url": config.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/"),
        "model": config.get("OLLAMA_MODEL", "llama3.2:1b"),
        "timeout": timeout,
    }


# ===========================================================================
#  1. IS IT THERE?
# ===========================================================================
def probe():
    """Ask Ollama what models it has. Returns (available, detail).

    Used by the console to explain itself honestly -- "Ollama is not running"
    is a far more useful thing to show a user than silence. It is also what the
    demo uses to prove the fallback: stop Ollama, run this, watch it report
    unavailable, and watch the console keep working anyway.
    """
    config = settings()
    try:
        with urllib.request.urlopen(f"{config['url']}/api/tags",
                                    timeout=PROBE_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        # URLError covers a refused connection, an unknown host and a timeout,
        # which are the three ways "Ollama is not running" actually looks.
        return False, f"not reachable at {config['url']} ({exc.reason})"
    except (TimeoutError, OSError) as exc:
        return False, f"not reachable at {config['url']} ({exc})"
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False, f"something is listening on {config['url']} but it is not Ollama"

    names = [m.get("name", "") for m in payload.get("models", [])]
    if not names:
        return False, "Ollama is running but has no model pulled "\
                      f"(try: ollama pull {config['model']})"
    if config["model"] not in names:
        return False, (f"Ollama is running but {config['model']} is not pulled "
                       f"(it has: {', '.join(names)})")
    return True, f"{config['model']} ready"


# ===========================================================================
#  2. THE PROMPT
# ===========================================================================
def build_prompt(text):
    """Build the classification prompt from the REGISTRY, never by hand.

    Generating the action list from ACTIONS means the prompt cannot drift out
    of step with what the system can actually do: add an action to
    actions.json and the model is told about it on the next request, with no
    second place to remember to edit.
    """
    catalogue = "\n".join(
        f"  {action_id} -- {action['description']}"
        for action_id, action in ACTIONS.items()
    )
    return f"""You classify requests for a Linux monitoring tool.

Choose the ONE action below that best matches the user's request.

ACTIONS:
{catalogue}

Answer with JSON only. No explanation, no markdown, no code fences.
Use exactly this shape:

{{"action_id": "<one id from the list above, or null>", "params": {{}}, "confidence": 0.0}}

RULES:
- action_id MUST be copied exactly from the list above, or be null if none fit.
- Never output a shell command, a file path, or any text outside the JSON.
- params may only use these keys: name, service, day, time, content.
- confidence is how certain you are, from 0.0 to 1.0.

USER REQUEST: {text}
"""


# ===========================================================================
#  3. ASK THE MODEL
# ===========================================================================
def classify(text):
    """Ask Ollama to classify one sentence. Returns a dict or None.

    None means "no usable answer" for ANY reason -- not installed, not running,
    timed out, model missing, invalid JSON, unknown action id. The caller does
    not need to tell those apart: in every case the console falls through to
    showing the action list, which is the safe behaviour.

    On success returns:
        {"action_id": str, "params": dict, "confidence": float, "raw": dict}
    """
    config = settings()

    body = json.dumps({
        "model": config["model"],
        "prompt": build_prompt(text),
        # format=json makes Ollama constrain the model's output to valid JSON.
        # It is a guarantee about SHAPE, not about CONTENT -- the model can
        # still return a well-formed object naming an action that does not
        # exist, which is exactly what _vet below is for.
        "format": "json",
        # stream=false: one complete response instead of a sequence of tokens.
        # Nothing here displays output as it arrives, so streaming would only
        # add parsing work.
        "stream": False,
        # temperature=0 asks for the most likely answer every time. A
        # classifier that gives a different answer to the same sentence twice
        # is not something anyone can demonstrate or defend.
        "options": {"temperature": 0},
    }).encode("utf-8")

    request = urllib.request.Request(
        f"{config['url']}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=config["timeout"]) as response:
            envelope = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError):
        return None                       # Ollama absent, refused or too slow
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None                       # not Ollama on the other end

    # Ollama wraps the model's text in {"response": "..."}. The model's actual
    # answer is that inner string, which still has to be parsed and vetted.
    try:
        answer = json.loads(envelope.get("response", ""))
    except (json.JSONDecodeError, TypeError):
        return None

    return _vet(answer)


# ===========================================================================
#  4. THE GATE -- where the model's answer stops being the model's answer
# ===========================================================================
def _vet(answer):
    """Check the model's reply against the registry. Returns a dict or None.

    THIS FUNCTION IS THE SECURITY BOUNDARY FOR EVERYTHING THE MODEL SAYS.
    Nothing downstream of it ever sees a value the model chose that was not
    checked here first. It is deliberately strict and deliberately boring:
    every branch either returns a known-good structure or returns None.
    """
    # 1. It must be a JSON object at all. A list, a number or a bare string is
    #    not an answer to the question that was asked.
    if not isinstance(answer, dict):
        return None

    action_id = answer.get("action_id")

    # 2. null is a legitimate, honest answer: "none of these fit". Treated the
    #    same as no answer, so the console shows the action list.
    if action_id is None:
        return None

    # 3. THE CHECK THAT MATTERS. The id must be a string, and it must be a key
    #    in the registry. "rm -rf /", "check_disk; whoami" and "CHECK_DISK" all
    #    fail here, because none of them is a key. There is no normalising, no
    #    fuzzy matching and no "did you mean" -- an id either is one of ours or
    #    the answer is discarded.
    if not isinstance(action_id, str) or action_id not in ACTIONS:
        return None

    # 4. Confidence must be a real number in range. A model that omits it, or
    #    writes "high", gets the benefit of the doubt at 0.0 -- which is below
    #    every threshold, so it becomes a suggestion rather than an action.
    confidence = answer.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        confidence = 0.0
    confidence = max(0.0, min(1.0, float(confidence)))

    # 5. Parameters are filtered down to the names THIS action declares.
    #    A model that invents a parameter is being noisy, not hostile, and
    #    dropping the extra key is kinder than refusing the whole request --
    #    validate() would otherwise reject it for an undeclared parameter.
    #    Values are forced to str because everything downstream expects text,
    #    and each one still has to survive its declared pattern afterwards.
    declared = {p["name"] for p in ACTIONS[action_id]["params"]}
    raw_params = answer.get("params")
    params = {}
    if isinstance(raw_params, dict):
        for key, value in raw_params.items():
            if key in declared and isinstance(value, (str, int, float)):
                params[key] = str(value)

    return {
        "action_id": action_id,
        "params": params,
        "confidence": confidence,
        "raw": answer,
    }
