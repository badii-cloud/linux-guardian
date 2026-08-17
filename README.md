# Linux Guardian

A web platform that monitors a Linux system, diagnoses it against configured
thresholds, detects service failures, recovers them automatically, logs every
action, and takes instructions in plain English.

For the current responsibility boundaries and dependency direction, see
[ARCHITECTURE.md](ARCHITECTURE.md).

COMP301 (Introduction to Linux). Built and tested on Kali GNU/Linux Rolling
2026.2 in VMware, offline, no SSH.

```
Firefox (localhost:5000) -> Flask -> subprocess -> Bash modules -> Kali Linux
                              ^
                              |
                     the command console:
        your words -> matcher -> action registry -> validator -> the same Bash
```

**The console never lets anything write a command.** A request is turned into
an *action id*, that id is looked up in `linux/actions.json`, and every
parameter is checked against a pattern declared next to it. The optional local
language model only ever picks an id from that list — see §7.

---

## 1. Setup — do this once

Two things need root. Neither is needed at demo time; do them now, while the VM
has a network.

### 1.1 Install jq

```bash
sudo apt install -y jq shellcheck
```

`jq` is **required**: `diagnosis.sh` parses the four modules' JSON with it.
`shellcheck` is optional but is what proves the scripts are clean.

### 1.2 Grant the three sudo rules healing needs

```bash
sudo install -m 0440 -o root -g root \
     config/linux-guardian.sudoers /etc/sudoers.d/linux-guardian
sudo visudo -c -f /etc/sudoers.d/linux-guardian     # must print "parsed OK"
```

This grants the `kali` user exactly three commands on exactly one unit, with no
password. Read the comments in that file — it explains every field, and why
`sudo -n` (fail, never prompt) is mandatory for a web app.

### 1.3 (Optional) Install the self-healing daemon

```bash
sudo cp systemd/linux-guardian.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now linux-guardian
journalctl -u linux-guardian -f
```

---

## 2. Running it

```bash
python3 app.py
```

Then open **http://127.0.0.1:5000** in Firefox. Flask 3.1.2 ships with Kali, so
there is nothing to install and no virtualenv to activate.

Twelve pages, grouped in the sidebar as Monitor / Respond / System. Start at
the **Dashboard** (live, refreshes itself every 10 s), the **Assistant** (type
what you want, or open *Build a command* and let it show you the wording), and
**Incidents** (what Guardian noticed, in plain English, with one next step).

Nine test suites, 426 checks, each exiting non-zero on any regression:

```bash
for t in test_*.py; do python3 "$t" >/dev/null || echo "FAILED: $t"; done

python3 test_actions.py    # the validator: traversal, injection, 25:00, funday
python3 test_guide.py      # every example sentence, fed back through the matcher
python3 test_explain.py    # every status has words; a null confidence is never 0%
```

Any module can also be run on its own, which is the fastest way to show what the
web page is actually made of:

```bash
./linux/system.sh    | jq .
./linux/network.sh   | jq .
./linux/process.sh   | jq .
./linux/services.sh  | jq .
./linux/diagnosis.sh | jq '{score, grade, summary}'
```

---

## 3. Demonstrating it live

```bash
# 1. Start apache2 so the dashboard has something green to show.
sudo systemctl start apache2

# 2. Refresh the dashboard. apache2 is "active", the Heal button is disabled,
#    and the health score rises.

# 3. Break it, the way a real failure would look:
sudo systemctl stop apache2

# 4. Refresh. apache2 is "inactive", its check is WARNING, the score drops,
#    and the Heal button is now clickable.

# 5. Click Heal.  ->  state_before: inactive, state_after: active, HEALED.

# 6. Show the audit trail: the Logs tab, or
tail -f logs/guardian.log

# 7. Show that it refuses to touch anything dangerous:
./linux/healing.sh ssh    | jq -c '{result, message}'
./linux/healing.sh nginx  | jq -c '{result, message}'

# 8. If the daemon is installed, stop apache2 and do nothing.
#    Within 30 seconds it comes back by itself:
sudo systemctl stop apache2; journalctl -u linux-guardian -f
```

### 3.1 Demonstrating the console (Phase 6)

Open the **Console** page and type these, in order:

| Type this | What happens |
|---|---|
| `how full is my disk` | runs immediately — it only reads |
| `is apache2 running` | one service, picked out of `services.sh` |
| `storage and memory` | **two readings tie → it asks instead of guessing** |
| `make me a sandwich` | refuses, and says the model was not reachable either |
| `create a file named schedule every thursday at 12 pm` | a **preview**. Nothing has run |
| *press Esc* | cancels it |
| *type it again, click Confirm* | now it writes the file and the timer |
| `list my files` | what is in the workspace — name, size, modified |
| `check if there is a file named test on desktop` | answers for the **workspace**, and says so. `~/Desktop` is outside the sandbox and always will be |
| `list my schedules` | reads the timer back |
| `cancel the schedule called schedule` | preview → Confirm → gone |

Then show the machine agrees:

```bash
systemctl --user list-timers                       # the timer is really there
cat ~/.config/systemd/user/guardian-schedule.timer # the unit we generated
systemd-analyze calendar "Thu 12:00"               # systemd's own reading of it
tail -20 logs/guardian.log                         # every request and outcome
```

The strongest thing to show a marker is that the guards hold even when the web
page is bypassed completely:

```bash
# The Bash scripts refuse on their own, with no Python involved:
./linux/workspace.sh create '../etc/passwd' x | jq -r .message
./linux/workspace.sh create '-rf'            x | jq -r .message
./linux/schedule.sh  create ok funday 12:00    | jq -r .message
./linux/schedule.sh  create ok Thu   25:00     | jq -r .message

# And forging the confirm POST by hand gains nothing:
curl -s -X POST http://127.0.0.1:5000/console/confirm \
     -d action_id=heal_service -d console_param_service=ssh | grep -o 'not allowed[^<]*'
```

---

## 4. What is where

| Path | Phase | Role |
|---|---|---|
| `config/guardian.conf` | all | **Every** threshold and target. Nothing is hard-coded elsewhere. |
| `config/linux-guardian.sudoers` | 3 | The three sudo rules healing needs, fully commented. |
| `linux/system.sh` | 1 | CPU %, RAM %, disk %, uptime, load, hostname, kernel |
| `linux/network.sh` | 1 | interface, IP, netmask, gateway, DNS, connectivity |
| `linux/process.sh` | 1 | top 10 by **current** CPU (pid, name, cpu%, mem MB) |
| `linux/services.sh` | 1 | apache2 and ssh: active / inactive / failed |
| `linux/diagnosis.sh` | 2 | judges all four, per-check PASS/WARNING/FAIL + score /100 |
| `linux/healing.sh` | 3 | recovers ONE allowed service, verifies, logs |
| `linux/guardian-daemon.sh` | 4 | watch loop, heals every `DAEMON_INTERVAL` seconds |
| `systemd/linux-guardian.service` | 4 | the unit, commented directive by directive |
| `app.py` + `templates/` | 5 | Flask on port 5000, Jinja2 templates |
| `logs/guardian.log` | 3+ | audit trail, including refusals |
| `linux/actions.json` | 6 | **the action registry** — if it is not in here it cannot happen |
| `guardian_actions.py` | 6 | validator, sandbox, executor, preview |
| `guardian_nlp.py` | 6 | keyword matcher + the three-attempt cascade |
| `guardian_ollama.py` | 6 | the optional local model. Never returns a command |
| `linux/workspace.sh` | 6 | writes files, only inside `workspace/` |
| `linux/schedule.sh` | 6 | systemd **user** timers: create / list / cancel |
| `test_actions.py`, `test_ollama.py` | 6 | the proofs, re-runnable live |
| `workspace/` | 6 | the sandbox. The only directory the console may write to |
| `guardian_guide.py` | 9 | the assistant's teaching layer: English in, argv out |
| `guardian_explain.py` | 9 | plain English for incidents: what / why / means / next |
| `test_guide.py`, `test_explain.py` | 9 | the proofs for both, re-runnable live |
| `docs/SYSTEM-REPORT.md` | 9 | the full map: every file's role and how it all moves |

---

## 5. The rules every Bash module follows

1. **stdout is one JSON object and nothing else.** No colours, no tables, no
   status messages. Flask hands stdout straight to `json.loads()`.
2. `#!/bin/bash` then `set -euo pipefail`.
3. Thresholds and targets come from `config/guardian.conf`, never hard-coded.
4. **Numbers are JSON numbers**, booleans are JSON booleans, and a value that
   genuinely does not exist is `null` — not `""`, not `"0"`.
5. `export LC_ALL=C`, so a comma-decimal locale can never emit `3,5` and break
   the JSON.
6. Paths resolve from `${BASH_SOURCE[0]}`; systemd runs these from `/`.
7. **Failure contract:** collect everything first, print once at the end. An
   `ERR` trap emits `{"status":"error","message":"…"}` and exits 1, so stdout is
   valid JSON even when the script fails.

Verify any module the same way:

```bash
./linux/<name>.sh | jq .        # must pretty-print
shellcheck linux/<name>.sh      # must be silent
```

All seven scripts and the config are clean at `shellcheck --severity=style`,
the strictest level.

---

## 6. The safety model

Phases 1 and 2 are **read-only** — they cannot change anything. Only
`healing.sh` acts, and it is guarded four times over:

1. **Character allow-list.** The service name must match
   `^[A-Za-z0-9@._-]+$`. `apache2; rm -rf /` is rejected before it reaches sudo.
2. **Deny list.** `PROTECTED_SERVICES` — ssh, NetworkManager, dbus,
   systemd-logind, systemd-journald — is checked first, so the refusal names the
   real danger. Comparison is on the base name, so `ssh.service` cannot slip
   past a rule written for `ssh`.
3. **Allow list.** `HEALABLE_SERVICES` is just `apache2`. Anything not named
   there is refused by default — the safe direction to fail in.
4. **Least-privilege sudo.** Three exact commands, one exact unit, absolute
   paths. No `stop`, no `disable`, no wildcards.

On the web side, an HTTP request never supplies a command, a path or an
argument — only a **name**, looked up in a dictionary defined in `app.py`.
`subprocess.run()` is always given a **list**, never a string, and `shell=True`
appears nowhere in the project. The server binds to `127.0.0.1` only, and
`debug=False` (Flask's debugger is a remote shell to anyone who can reach it).

Every refusal is written to `logs/guardian.log`. The log has to be able to prove
the tool never touched a protected service.

---

## 7. The console's safety model (Phase 6)

The same idea as `ALLOWED_MODULES`, extended to actions that take arguments.

**1. The registry is the boundary.** `linux/actions.json` lists every action,
its script, and a pattern for each parameter. A request supplies a *name*; if
it is not a key in that file, nothing runs.

**2. Nothing generates a command.** Parameters are validated, then appended to
an argv **list** — never joined into a string, and `shell=True` appears nowhere
in this project. `create_file` with content `a; rm -rf /` writes those nine
characters into a text file, because there is no shell to read the semicolon.

**3. Normalise, then validate.** `thursday` → `Thu` and `12 pm` → `12:00`
*before* the pattern runs, so the value that gets used is the value that was
checked. `25:00` normalises to `25:00`, fails `^([01][0-9]|2[0-3]):[0-5][0-9]$`
and is refused.

**4. Names cannot start with a hyphen.** `^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,39}$`.
A leading hyphen is not a filename to most Unix commands, it is a **flag** —
`-rf` is refused for that reason alone.

**5. Every rule is enforced twice, in two languages.** Python checks before
calling; the Bash script checks again on entry, because it is executable from a
terminal and a script that is only safe when its caller behaves is not safe.
The final path is resolved with `realpath` and must still be inside
`workspace/` — a regex reasons about text, `realpath` reasons about where the
filesystem would really put the file.

**6. Writes require a second, explicit request.** `POST /console` returns a
preview. Only `POST /console/confirm` executes, and it re-validates everything
from scratch — forging that POST by hand gains nothing the console would not
already have allowed.

**7. Schedules are unprivileged.** systemd **user** timers in
`~/.config/systemd/user/`, never root cron, so scheduled work can only touch
what this user could already touch. `systemd-analyze calendar` validates the
expression before any file is written.

**8. The language model is optional, and only classifies.** The deterministic
keyword matcher covers all 14 actions on its own; Ollama is consulted *only*
when that found nothing, so it can never override a deterministic match. Its
answer is an id, checked against the registry — return `rm -rf /` and it is
simply not a key. Parameters it supplies are overridden by the regex extractor
wherever that found something, because a model can hallucinate "Friday" for a
sentence that says Thursday. **Ollama is not installed on this VM**, which is
the tested and demonstrated state.
