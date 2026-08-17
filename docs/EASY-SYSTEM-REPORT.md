# Linux Guardian — easy system report

## 1. What this system does

Linux Guardian watches one Linux computer.  It collects health facts (CPU,
memory, disk, network, processes and services), checks them against rules,
stores a history, notices unusual changes, groups related problems into an
incident, and helps a person investigate or repair it.

It has two ways to use it:

* **Web pages** for monitoring, incidents, settings and logs.
* **Assistant console** where a person can type a request such as “how full is
  my disk?” or “create a file called notes”.

The important safety idea is simple: the user never supplies a shell command.
They supply an approved action name and values which are checked before a
program is started.

## 2. The big picture

```text
Browser
  -> app.py (web routes and pages)
  -> guardian_*.py (rules, safety, history and incident logic)
  -> linux/*.sh (ask Linux for facts or perform a limited action)
  -> Linux machine

metrics.sh -> guardian_store.py -> data/guardian.db
                                 -> anomaly detection -> incidents
```

There are three clear responsibilities:

1. **Bash scripts measure or perform the small Linux-level jobs.**
2. **Python decides what the data means and enforces the rules.**
3. **Flask displays results and accepts HTTP requests; it does not make system
   decisions itself.**

## 3. Step-by-step: opening the dashboard

1. A browser requests `/` from `app.py`.
2. `app.py` asks `guardian_system.py` to run only the approved
   `linux/diagnosis.sh` script.
3. `diagnosis.sh` runs the four read-only collectors:
   `system.sh`, `network.sh`, `process.sh` and `services.sh`.
4. It compares their readings with thresholds in `config/guardian.conf` and
   returns JSON with checks, warnings/failures and a health score out of 100.
5. `app.py` passes that JSON to `templates/index.html`.
6. JavaScript refreshes selected readings every ten seconds without replacing
   the whole page.

## 4. Step-by-step: the monitoring and incident path

1. `linux/guardian-daemon.sh` wakes at the configured interval (30 seconds by
   default).
2. It runs `linux/metrics.sh`, a quick collector designed for repeated
   sampling. It does not sleep for a CPU measurement or ping a network host.
3. `guardian_store.py` stores each metric in SQLite (`data/guardian.db`).
4. `guardian_anomaly.py` compares recent readings with older readings for the
   *same machine*. It labels a metric `LEARNING`, `NORMAL`, `WARNING` or
   `CRITICAL`.
5. `guardian_incidents.py` combines related abnormal metrics into one incident
   instead of showing several alerts for one underlying problem.
6. The incident appears on `/incidents`. A person may investigate it, request
   a repair proposal, approve it, reject it, or ignore it.
7. `guardian_rootcause.py` collects read-only evidence. `guardian_remediate.py`
   only performs an approved recommended action, then measures again to verify
   whether the repair worked.

An incident follows this path:

```text
DETECTED -> INVESTIGATING -> WAITING_APPROVAL -> REMEDIATING
                                             -> VERIFYING -> RESOLVED or FAILED
```

It may also resolve itself when the readings return to normal. In that case the
record explicitly says that no repair was run.

## 5. Step-by-step: the assistant console

1. The user writes a request in `/console`, for example `restart apache2`.
2. `guardian_nlp.py` first uses deterministic keyword matching and extracts
   values such as a service name or a time. If it has no match, it may ask the
   optional local Ollama model for an **action id**, never a command.
3. `guardian_actions.py` looks up that action id in `linux/actions.json`.
4. It normalises useful forms (`thursday` to `Thu`, `9am` to `09:00`) and checks
   required values, permitted service names, length limits and complete regular
   expressions.
5. Read-only actions run immediately. Write actions return a preview and need
   a separate Confirm request; confirmation validates everything again.
6. The command is built as a list of arguments with no shell. A semicolon in
   file content is data, not an instruction.
7. The relevant Bash script performs its own checks again and returns JSON.

The approved actions include health checks, process/service/log viewing,
workspace file creation/listing, user-timer scheduling, and healing a listed
service. Anything not in `actions.json` is refused.

## 6. Safety rules, in plain English

* The web request selects from a fixed list of scripts/actions; it cannot name
  a new program to run.
* Parameters must match an entire declared pattern, not merely contain a valid
  word.
* Programs receive an argument list, never a concatenated shell string.
* Workspace file names are resolved and required to remain directly inside
  `workspace/`.
* Write actions need preview plus confirmation.
* `healing.sh` can only heal configured services. The supplied sudoers policy
  permits start/restart/reset-failed for `apache2.service`, not arbitrary root
  commands and not stopping services.
* Bash scripts repeat their own validation, so a caller cannot bypass Python
  validation by calling a script directly.

## 7. File-by-file map

### Root Python application and domain modules

| File | Easy description |
|---|---|
| `app.py` | The web application. Defines page/API routes, renders templates and connects the other modules. |
| `guardian_system.py` | Small safe gateway for the fixed monitoring scripts. |
| `guardian_config.py` | Reads `guardian.conf` as text data; it never executes configuration as code. |
| `guardian_actions.py` | Loads the action registry, validates values, builds safe argument lists, executes approved actions and narrows their JSON results. |
| `guardian_nlp.py` | Keyword matcher and parameter extractor for console English. It asks Ollama only if keyword matching has no answer. |
| `guardian_ollama.py` | Optional local-model client and strict response vetting. It accepts only a permitted action id plus parameters. |
| `guardian_store.py` | SQLite schema, metric storage, querying, aggregation, rates and retention/pruning. |
| `guardian_anomaly.py` | Learns historical baselines and decides whether a change is statistically and materially unusual. |
| `guardian_incidents.py` | Incident type registry checks, correlation, deduplication, timeline and legal status transitions. |
| `guardian_risk.py` | Calculates severity/risk and exposes the contributions that formed a score. |
| `guardian_rootcause.py` | Runs declared read-only investigations and separates facts, inference and recommendation. |
| `guardian_remediate.py` | Creates proposals, requires approval, runs a recommended action and verifies its result by measuring again. |
| `guardian_preflight.py` | Read-only readiness checks for the readiness page. |
| `guardian_guide.py` | Supplies the guided action builder, example sentences, parameter help and safe command previews. |
| `guardian_explain.py` | Turns technical incident fields into ordinary-language explanations and one next step. |

### Linux engine and registries

| File | Easy description |
|---|---|
| `linux/system.sh` | CPU, memory, disk, load, uptime, hostname and kernel JSON. |
| `linux/network.sh` | Network interface, address, gateway, DNS and gateway reachability JSON. |
| `linux/process.sh` | Top configured number of processes by current CPU use. |
| `linux/services.sh` | State of each service in `MONITORED_SERVICES`. |
| `linux/diagnosis.sh` | Runs the four collectors, applies thresholds and calculates health score/checks. |
| `linux/healing.sh` | Safely starts/restarts one allowed service and verifies its state afterwards. |
| `linux/guardian-daemon.sh` | Repeating collector/healer loop used for unattended operation. |
| `linux/metrics.sh` | Fast periodic metric sampler for the database and anomaly engine. |
| `linux/workspace.sh` | Lists or creates text files only in the project workspace. |
| `linux/schedule.sh` | Creates/lists/cancels systemd **user** timers for workspace files. |
| `linux/actions.json` | Registry of the 14 console actions, their scripts, fixed arguments, parameters and whether confirmation is required. |
| `linux/incidents.json` | Registry of incident types, symptoms, investigation action and permitted recommendations. |

Every `linux/*.sh` script follows one output contract: stdout is one JSON object
only, including on an error. This lets Python parse it reliably.

### Configuration, service and stored state

| File/path | Easy description |
|---|---|
| `config/guardian.conf` | Single policy/configuration source: thresholds, monitored/healable services, locations, timeouts, retention and risk settings. |
| `config/linux-guardian.sudoers` | Optional least-privilege sudo policy for healing `apache2`. Install manually to `/etc/sudoers.d/`. |
| `systemd/linux-guardian.service` | Optional system service that starts the daemon at boot as user `kali`. |
| `data/guardian.db` | Runtime SQLite history and incident records, not program source. |
| `logs/guardian.log` | Runtime audit log of actions, success, errors and refusals. |
| `workspace/test.txt`, `workspace/notes.txt` | Example/runtime files in the only directory the console can write. |
| `__pycache__/` | Python-generated bytecode cache; safe to regenerate and not source code. |

### Web user interface

| File/path | Easy description |
|---|---|
| `templates/base.html` | Shared sidebar, navigation and page shell. |
| `templates/index.html` | Dashboard and live health summary. |
| `templates/console.html` | Natural-language assistant and guided action builder. |
| `templates/incidents.html` | Incident list. |
| `templates/incident.html` | One incident’s evidence, timeline and response controls. |
| `templates/processes.html`, `services.html`, `network.html`, `logs.html` | Dedicated views for those monitoring results. |
| `templates/security.html`, `automation.html`, `settings.html`, `readiness.html` | Security explanation, scheduled tasks, read-only settings and readiness checks. |
| `templates/guide.html` | Human-readable assistant/action guide. |
| `templates/heal.html` | Service-healing confirmation/result view. |
| `templates/error.html` | Shared error page. |
| `static/css/guardian.css` | Local styles, layout and status colours. |
| `static/js/charts.js` | Local SVG chart drawing and live-page refresh behaviour; no internet CDN is required. |

### Documentation, developer support and tests

| File | Easy description |
|---|---|
| `README.md` | Installation, use, live demonstration and security overview. |
| `ARCHITECTURE.md` | Short responsibility/dependency diagram. |
| `CLAUDE.md` | Project working notes/instructions. |
| `.shellcheckrc` | Lets ShellCheck understand the sourced Bash configuration. |
| `.claude/settings.local.json` | Local editor/tool settings, not Guardian runtime behaviour. |
| `docs/SYSTEM-REPORT.md` | Detailed technical version of this report, including data model and design rationale. |
| `docs/PHASE-PROMPTS.md` | Project-phase prompts/notes. |
| `docs/VIVA-QA.md` | Viva/presentation questions and answers. |
| `test_actions.py` | Action registry, validation, sandbox and language-matching tests. |
| `test_ollama.py` | Optional-model unavailable/hostile-response tests. |
| `test_store.py` | Database schema, storage, statistics, rates and pruning tests. |
| `test_anomaly.py` | Baseline, confidence, trend and anomaly decision tests. |
| `test_incidents.py` | Correlation, deduplication, state-machine and risk tests. |
| `test_rootcause.py` | Investigation/root-cause interpretation tests. |
| `test_remediate.py` | Proposal, approval, repair and verification tests. |
| `test_guide.py` | Guided-builder/example/translation tests. |
| `test_explain.py` | Plain-English incident explanation tests. |

## 8. What changes the machine?

Most features only read the system. These features can make a change:

* `healing.sh`: starts/restarts a service on the healable list.
* `workspace.sh create`: writes a `.txt` file under `workspace/`.
* `schedule.sh create` / `cancel`: manages named systemd user timer/service
  files under the user’s systemd configuration directory.
* `guardian-daemon.sh`: can trigger the configured healing path automatically.

All other collectors, dashboards, history analysis, explanations and
investigations are read-only.

## 9. Verification note

The test files are designed to be run individually with `python3 test_*.py`.
In the current restricted execution environment, the Ollama test cannot open
its temporary localhost test server (`PermissionError`), so the full suite
cannot be certified here. The tests that ran before that point passed; run the
suite on the normal Kali VM to exercise the local HTTP test as well.
