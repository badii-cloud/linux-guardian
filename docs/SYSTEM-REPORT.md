# Linux Guardian — system report

*A complete map of the project: what every file is for, and how the parts move
when somebody uses it. Written to be read start to finish before a viva.*

Generated 2026-08-16 against the working tree on this VM.

---

## 1. What the project is, in one paragraph

Linux Guardian is a self-healing system monitor for one Kali machine. It
**measures** the host with Bash, **judges** those measurements against
thresholds in one config file, **remembers** them in SQLite so it can tell
"high" from "high *for this machine*", **groups** abnormal readings into
incidents, **investigates** them read-only, and **proposes** a repair that a
human has to approve before anything changes. A Flask web interface and a
natural-language console sit on top; neither of them contains any system logic
of its own.

---

## 2. The architecture in one line

```
Firefox (127.0.0.1:5000) → Flask → subprocess(argv list) → Bash modules → Kali
                             ↑                                   ↓
                        SQLite history  ←  metrics.sh  ←  daemon loop (30 s)
```

Three rules explain almost every design decision in the repo:

| Rule | Consequence |
|---|---|
| **Bash measures, Python decides, Flask displays** | No Python module shells out to `ps`/`df`; no template computes a verdict. |
| **stdout is exactly one JSON object** | Flask hands script output straight to `json.loads()`. No colours, no progress text — even on failure. |
| **A request supplies a NAME, never a command** | Every name is looked up in a registry written by a human. An unknown name is a 404 before anything runs. |

---

## 3. The tree

```
linux-guardian/                       ~20,600 lines total
├── config/
│   ├── guardian.conf                 445 lines · 59 keys · the only policy file
│   └── linux-guardian.sudoers        3 NOPASSWD rules, apache2 only
├── linux/                            the Bash engine — 4,325 lines, 10 scripts
│   ├── system.sh  network.sh  process.sh  services.sh     Phase 1 · measure
│   ├── diagnosis.sh                                       Phase 2 · judge
│   ├── healing.sh                                         Phase 3 · repair
│   ├── guardian-daemon.sh                                 Phase 4+7 · loop
│   ├── metrics.sh                                         Phase 7 · sample
│   ├── workspace.sh  schedule.sh                          Phase 6 · sandbox
│   ├── actions.json                                       14 approved actions
│   └── incidents.json                                     10 incident types
├── guardian_*.py  app.py             the Python brain — 15 files
├── templates/                        16 Jinja2 pages
├── static/css/guardian.css           one stylesheet, zero CDN
├── static/js/charts.js               hand-drawn SVG charts, no library
├── test_*.py                         9 suites, 426 checks
├── data/guardian.db                  SQLite history (schema v2)
├── logs/guardian.log                 the audit trail
├── systemd/linux-guardian.service    optional unit for hands-off healing
└── workspace/                        the ONLY directory the console may write
```

---

## 4. Every file and what it is for

### 4.1 Configuration — the single source of truth

| File | Role |
|---|---|
| `config/guardian.conf` | **59 keys in 12 numbered sections.** Every threshold, target, service list, retention window, weight and timeout. Written as plain `KEY="value"` lines so Bash can `source` it *and* Python can read it with a regex **without executing it** — a web process that ran its own config file would turn every edit into server-side code. |
| `config/linux-guardian.sudoers` | Installed to `/etc/sudoers.d/`. Grants exactly three NOPASSWD rules — `start`, `restart`, `reset-failed` on `apache2.service` — and nothing else. Guardian has **no `stop` privilege at all**, by design. |
| `.shellcheckrc` | Lets `shellcheck` follow the `source` into `guardian.conf` so the linter sees the variables. |

The config is why nothing in the repo hard-codes `192.168.138.2`, `apache2` or
`80`. Section 8 owns the console, 9 the sampler, 10 the database, 11 the
detector, 12 severity and risk.

### 4.2 The Bash engine — `linux/*.sh`

Each of these prints **one JSON object and nothing else**, starts with
`set -euo pipefail`, sources the config, resolves its own path from
`${BASH_SOURCE[0]}`, sets `LC_ALL=C` so a comma-decimal locale cannot emit
`3,5` and break JSON, and installs an `ERR` trap that still emits valid JSON
when it fails.

| Script | Phase | What it does |
|---|---|---|
| `system.sh` | 1 | CPU % (1-second `/proc/stat` delta), RAM %, disk %, load average, uptime, hostname, kernel. |
| `network.sh` | 1 | Interface, link state, MAC, IPv4 + netmask, gateway, DNS servers, and a real ping to the **VMware gateway** — not 8.8.8.8, so the demo stays green offline. |
| `process.sh` | 1 | Top *N* processes by CPU with pid, name, cpu %, resident MB. |
| `services.sh` | 1 | State of every unit in `MONITORED_SERVICES` via `systemctl show` — machine-readable `key=value`, not scraped `status` text. |
| `diagnosis.sh` | 2 | Runs all four above, applies the thresholds, emits a **PASS / WARNING / FAIL per check plus a score out of 100**. This is the only place the verdict rule lives — which is why the live refresh never rebuilds HTML. Costs ~3,253 ms. |
| `healing.sh` | 3 | Recovers one service. Four independent guards: deny-list, allow-list, character allow-list, then *verify by re-measuring*. Idempotent — a healthy service returns `already_healthy`, so the daemon never restarts something already up. |
| `guardian-daemon.sh` | 4 + 7 | The loop. Every `DAEMON_INTERVAL` (30 s): **collect, then heal** — a sample taken after an intervention would describe the machine *after* the fix. Collection is subordinate: a broken store logs one line and the daemon keeps watching apache2, and both failures log **only on transition** so a broken disk does not get 2,880 identical lines a day. |
| `metrics.sh` | 7 | The cheap sampler: **52 ms** versus diagnosis.sh's 3,253 ms, because it never sleeps and never touches the network. Publishes **gauges** (true on their own) and **counters** (only meaningful when differenced) as two separate JSON objects. A missing sensor emits `null`, never `0` — a fabricated zero would manufacture an anomaly on the next sample. |
| `workspace.sh` | 6 | Creates/lists text files, and **only** inside `$WORKSPACE_DIR`. Like `healing.sh`, most of it is about what it refuses. |
| `schedule.sh` | 6 | Creates/lists/cancels **systemd user timers** (`guardian-<name>.timer` + `.service` in `~/.config/systemd/user/`), never root cron. `systemd-analyze calendar` validates the expression before a file is written — systemd's own parser, not just our regex. |

### 4.3 The registries — declarative safety

| File | Role |
|---|---|
| `linux/actions.json` | **The complete list of 14 things the console may do.** Each entry declares its script, fixed args, which JSON key answers the question (`select`), whether it is `read` or `write`, and an **anchored regular expression per parameter**. JSON has no comments, so documentation lives in `_`-prefixed keys the loader strips. |
| `linux/incidents.json` | **10 incident types.** Declares which metrics are symptoms of the same condition, the base severity, the impact weight, the read-only `investigate` action, and the `recommended_actions`. Correlation is **declared, not learned** — statistical correlation needs weeks of labelled data this machine does not have. |

The safety property that ties them together: `recommended_actions` may only
name ids that already exist in `actions.json`, and `investigate` must be a
`danger: "read"` action. Both are checked at load; a test plants a fake id and
proves the check fires.

### 4.4 The Python brain — `guardian_*.py`

None of these import Flask. That is deliberate: every one can be exercised
from a terminal with no web server running, which is what the seven test
suites do.

| Module | Lines | Role |
|---|---|---|
| `guardian_config.py` | 43 | The sole boundary for reading `guardian.conf` **as data**. Expands only `${GUARDIAN_ROOT}` and `${HOME}` — never `os.path.expandvars`, which would expand the whole inherited environment. |
| `guardian_system.py` | 40 | The fixed gateway from web code to the five monitoring modules. `subprocess.run([list])`, `shell=False`, allow-listed filenames. |
| `guardian_actions.py` | 741 | **The wall between typed text and a running process.** Loads the registry, normalises (`thursday` → `Thu`, `12 pm` → `12:00`), caps length, `re.fullmatch`es the anchored pattern, checks the config allow-list, then resolves the path with `realpath` and refuses anything outside the workspace. Builds argv as a **list, never a string**. |
| `guardian_nlp.py` | 535 | The deterministic matcher: a dictionary of trigger phrases covering all 14 actions unaided. Scores on **evidence** = trigger words matched + parameters the action can actually use. Two equally-good readings get the winner's confidence pulled *below* the threshold, so the console asks instead of guessing. |
| `guardian_ollama.py` | 276 | The optional local model — consulted **only** when the dictionary returned nothing, so it can never override a deterministic match. Ollama is not installed on this VM; that is the tested demo state. |
| `guardian_store.py` | 1,433 | SQLite. One row per metric per tick, **narrow not wide**, `PRIMARY KEY (metric, ts) WITHOUT ROWID`. `aggregate()` refuses to average a counter; `rate()` refuses a gauge. stddev is **Welford's algorithm** — the textbook formula is 36 % wrong at counter magnitudes. |
| `guardian_anomaly.py` | 630 | Asks *"is this abnormal?"* where `diagnosis.sh` asks *"is this bad?"* — 95 % disk is bad and normal; 40 % CPU on a 3 % machine is abnormal and harmless. Two tests must both pass: **statistical** (≥ 3σ) and **material** (≥ 10 % of baseline). Confidence is **Chebyshev**, not the normal curve. |
| `guardian_incidents.py` | 961 | Groups anomalies into incidents, deduplicates by **type + component**, and enforces the state machine — `REMEDIATING → RESOLVED` is *not* a legal transition; it must pass through `VERIFYING`. |
| `guardian_risk.py` | 285 | Severity and risk, kept separate because risk applies to *actions* too. Risk is a **weighted average**, not a sum of penalties — it cannot exceed 100 and cannot be gamed by adding factors. Returns `contributions`, so "risk 65" is explainable. |
| `guardian_rootcause.py` | 551 | Runs the incident type's declared read-only investigation and interprets it into **three separate lists — FACT / INFERENCE / RECOMMENDATION**. It imports neither `subprocess` nor `os`, asserted against the parsed AST. It refuses to name a cause when there isn't one. |
| `guardian_remediate.py` | 505 | `propose → WAITING_APPROVAL → approve → REMEDIATING → verify → RESOLVED / FAILED`. `approve()` takes an incident id and an action id and **nothing else** — every parameter is derived server-side. The exit code is never proof; verification re-measures. |
| `guardian_preflight.py` | 60 | Six read-only readiness checks for the `/readiness` page. |
| `guardian_guide.py` | 400 | **Phase 9.** The assistant's teaching layer: which words trigger each action, what each parameter must look like, and the argv the English becomes. Every example is verified against the real matcher by the test suite. |
| `guardian_explain.py` | 470 | **Phase 9.** Turns an incident record into plain English — what happened, why Guardian said so, what it means, and the one next step. |
| `app.py` | 1,000 | Flask. 13 HTML routes, 10 JSON APIs, and no logic of its own. |

### 4.5 The web layer

| Path | Role |
|---|---|
| `templates/base.html` | The shell: CSS-grid sidebar (Monitor / Respond / System) + content column. Grid, not `position:fixed`, so wide tables know their real width. |
| `templates/index.html` | Dashboard — score, checks, live metrics, briefing. **Every number is rendered by Jinja**, including the ones JS later updates. |
| `templates/console.html` | The natural-language assistant. |
| `templates/incidents.html` · `incident.html` | Incident list and the full incident record. |
| `templates/processes · services · network · security · automation · settings · logs · guide · readiness · heal · error` | One page per concern. |
| `static/css/guardian.css` | One local stylesheet. Colour discipline: `--pass`/`--warn`/`--fail` mean **health status only**; every control is `--accent` blue. |
| `static/js/charts.js` | Hand-drawn inline SVG. No Chart.js: a CDN is blank offline, and vendoring 200 KB of minified code would ship something nobody here can explain line by line. |

### 4.6 Tests and operations

| File | Role |
|---|---|
| `test_actions.py` | Registry integrity + the validator refusing traversal, injection, `25:00`, `funday`. |
| `test_ollama.py` | Stubs the API to prove the vetting gate rejects `rm -rf /`, unknown ids, prose, truncated JSON, a 5 s hang. |
| `test_store.py` | 48 checks including the **file on disk actually shrinking** after a prune. |
| `test_anomaly.py` | 40 checks — including the zero-variance blind spot that reported a 20× traffic spike as NORMAL. |
| `test_incidents.py` | 55 checks — deduplication, the state machine, the symptom-union regression. |
| `test_rootcause.py` · `test_remediate.py` | AST assertions and a stubbed action that lies about succeeding. |
| `test_guide.py` | 56 checks — every example sentence fed back through the real matcher, plus the whole Phase 6 hostile-input list re-run through the guided form. |
| `test_explain.py` | 45 checks — every status, type and risk band has wording; a null confidence never prints as 0%; a self-resolved incident never claims a fix ran. |
| `systemd/linux-guardian.service` | Optional unit for hands-off healing. Not installed; the Heal button works without it. |
| `logs/guardian.log` | One file, one format, written by Bash *and* Python: `[ACTION]` → `[SUCCESS]` / `[ERROR]` / `[REFUSED]`. |

---

## 5. How the system actually works — five walkthroughs

### 5.1 Loading the dashboard

1. `GET /` → `dashboard()`.
2. `module_data("diagnosis")` looks `"diagnosis"` up in `ALLOWED_MODULES` — an unknown name is a 404 *before* anything runs.
3. `subprocess.run(["/…/linux/diagnosis.sh"], shell=False)`.
4. `diagnosis.sh` sources the config, runs the four Phase 1 modules, applies the thresholds, prints one JSON object with a score.
5. Flask parses it and Jinja renders every row — including the passing ones.
6. Every 10 s, JS fetches `/api/overview` + `/api/system` and **rewrites text in place**. It never builds HTML; it only toggles `hidden`. A failed fetch overwrites nothing and the "updated Xs ago" clock goes stale, so old numbers announce themselves.

### 5.2 Asking the assistant a question

```
"how full is my disk"
  → _tokenise      ["how","full","disk"]            filler words dropped
  → match()        check_disk  0.91  via "disk"     ranked on evidence
  → validate()     id is in the registry, 0 params  ← the security boundary
  → build_command  ["/…/linux/system.sh"]           a LIST, never a string
  → execute()      json.loads(stdout)
  → _narrow()      select:"disk" → just the disk object
  → console.html   a gauge, a fact table, and the raw JSON one click away
```

The cascade is **keyword → Ollama → show the list**. Ollama is asked only about
sentences the dictionary had no opinion on, so adding or removing it cannot
change any behaviour that already worked. An unmatched query returns in ~1 ms
because a refused connection on loopback is instant.

### 5.3 Creating a file — the write path

Write actions **never** run on the first request.

```
POST /console          → validate → danger=="write" → return a PREVIEW, run nothing
POST /console/confirm  → validate AGAIN from scratch → execute
```

The confirm route does not trust the preview it came from: it re-validates the
action id and every parameter. Forging that POST with `curl` gains nothing,
because **the registry is the boundary, not the preview**.

### 5.4 The daemon — how history becomes an incident

Every 30 seconds:

```
metrics.sh (52 ms)
   → store.observe()
        1. store the sample          ← FIRST and UNCONDITIONALLY
        2. detect      guardian_anomaly.scan()
        3. correlate   guardian_incidents.process()
```

The sample is stored before anything tries to interpret it, so a failure to
*understand* data can never cost the data itself.

Detection needs `ANOMALY_MIN_SAMPLES` (20) before it will say anything; below
that the verdict is the distinct word **`LEARNING`**, which sorts last so it
never pushes a real finding down the page.

The baseline window **ends where the recent window begins** — no overlap — so a
long spike can never drag up the average it is judged against.

Correlation then turns *N* abnormal metrics into **one** incident. This is the
whole reason Phase 8 exists: Phase 7 ended with one CPU load producing four
CRITICAL alarms, and an alert list where one cause fills four rows is one people
stop reading.

### 5.5 Investigating and fixing an incident

```
DETECTED ──Investigate──▶ INVESTIGATING ──Propose──▶ WAITING_APPROVAL
                                                          │
                                            Approve ──────┤────── Reject
                                                          ▼
                              REMEDIATING ──▶ VERIFYING ──▶ RESOLVED
                                                     └────▶ FAILED (still open)
```

* **Investigate** runs the type's declared **read-only** action through the same validator the console uses.
* **Propose** produces a description and moves the incident in front of a human. Nothing runs.
* **Approve** re-reads the incident, checks the action id against *that type's own* recommended list, derives every parameter server-side, and runs the registry validator again — four independent checks, the fourth being `healing.sh` itself.
* **Verify** re-measures. An exit code is never taken as proof; a stubbed action that reports `status: ok` while the unit is dead is caught, and the incident goes to `FAILED` and stays **open**.
* An incident that clears on its own is auto-resolved — but only from `DETECTED` or `INVESTIGATING`. One sitting at `WAITING_APPROVAL` has a human involved, and closing it from underneath them would destroy the record of what was being decided. The timeline says plainly *"returned to normal on their own; no action was taken"* — never that something fixed it.

---

### 5.6 The guided builder — Phase 9

The console used to be an empty text box: powerful if you already knew the
words, useless if you did not. Every action now has a card that shows the
translation as it is built.

```
        [ name ]  notes          ← a labelled box, with its rule underneath
        [content] hello

You type    create a file called notes containing hello
Linux runs  linux/workspace.sh create notes hello
```

Three properties make it defensible rather than merely convenient:

* **It is not a second door.** The card is a plain HTML form posting `action_id` and `console_param_<name>` to the *same* `/console` route the text box uses. A value typed into a labelled box and a value a regular expression found in a sentence arrive at `ga.validate()` as the same string. The test suite re-runs the entire Phase 6 hostile-input list through the form — traversal, `evil.sh`, `-rf`, `ssh`, `nginx`, `funday`, `25:00` — and every one is refused with an empty argv.
* **The examples are checked, not claimed.** Every example sentence is fed back through `nlp.match()` by the test suite and must resolve to the action it is filed under. An example that stops working fails the build.
* **The trigger words shown are the real ones.** They are read out of `guardian_nlp.TRIGGERS`, the dictionary that actually does the matching, so there is no second list to keep in step.

`GET /api/console/translate` powers the live version. It runs the matcher, runs
the validator, calls `build_command()` and hands the list to nobody — which is
exactly why a GET is correct here despite the project's usual rule: pre-fetching
it is harmless, and that *is* the test for whether a GET is appropriate.

### 5.7 Reading an incident — Phase 9

The incident page used to open with `CRITICAL · 74 · 98% · 9×`. Every figure was
honest and none of them told a person what had happened. It now opens with four
answers in a fixed order — **what happened · why Guardian says so · what it
means · what to do now** — and the numbers follow, each carrying the sentence
that explains it.

The lifecycle is drawn rather than described:

```
✓ Noticed  →  ✓ Investigated  →  Approved  →  Fixed  →  Checked  →  Closed
                                 YOU ARE HERE
```

which turns the safety argument into a picture: approval sits *before* the fix,
verification *after* it.

Three details are about honesty rather than presentation:

* An incident that recovered on its own marks approval, fix and check **`skipped`**, never `done` — a tick there would put a repair in the record that never happened.
* A `null` confidence prints *"Guardian cannot put a number on how sure it is"*, never `0%`. That is the zero-variance case, and 0% would claim certainty that the finding was meaningless.
* Status **values** never change — `WAITING_APPROVAL` is a database key, a CSS class and a state-machine state. Only the printed label becomes "Waiting for you", and a status nobody has labelled shows as SHOUTING_SNAKE_CASE so the omission gets noticed.

---

## 6. The safety model — five walls, none trusting the next

| # | Wall | Where |
|---|---|---|
| 1 | A request supplies a **name**, never a command | `ALLOWED_MODULES`, `ACTIONS`, `TYPES` |
| 2 | Every parameter matched against an **anchored** pattern declared next to the script | `actions.json` + `guardian_actions.validate()` |
| 3 | Commands are built as **argv lists** with `shell=False` | `build_command()` — there is no shell to interpret a `;` |
| 4 | Paths resolved with `realpath` and required to be **directly inside** the workspace | `resolve_in_workspace()` |
| 5 | Bash re-checks everything from scratch | `healing.sh`, `workspace.sh`, `schedule.sh` |

Deleting any single one still leaves the system safe. Two further properties
matter as much:

* **Write actions need two deliberate requests**, and the second one re-validates from zero.
* **`/settings` is read-only on purpose.** A form would let the web process rewrite the file that defines its own limits — including `HEALABLE_SERVICES`.

---

## 7. The data model

```
sample_runs   one row per tick        (ts, source, duration)
samples       one row per metric      PRIMARY KEY (metric, ts) WITHOUT ROWID
incidents     one row per condition   fingerprint = type + component
incident_events  the timeline         records CHANGES, not ticks
```

`samples` is **narrow, not wide**: adding a field to `metrics.sh` needs no
schema change and the statistics stay generic. ~52 bytes/row → ~30 MB per week
at 30 metrics every 30 s.

Retention has **two guards that fail differently**: by age (expresses the
intent, useless if the clock is wrong) and by row count (never consults the
clock, so a VM resuming from suspend believing it is 1970 still cannot fill the
disk). Whole *ticks* are deleted, never individual rows — a half-deleted moment
would read to the baseline engine as the machine losing sensors.

---

## 8. What runs when

| Trigger | What runs | Cost |
|---|---|---|
| Open the dashboard | `diagnosis.sh` → 4 modules | ~3,253 ms |
| Live refresh (10 s) | `/api/overview` → `system.sh` + SQLite | ~1,000 ms |
| Daemon tick (30 s) | `metrics.sh` + store + detect + correlate | ~52 ms + SQLite |
| Retention (every 120 ticks ≈ 1 h) | prune + incremental vacuum + WAL truncate | — |
| Assistant read action | one module, narrowed by `select` | 50–3,250 ms |
| Assistant write action | preview, then a second confirmed request | — |

---

## 9. Verified, not asserted

* `shellcheck --severity=style` — zero warnings across all 10 scripts.
* Every numeric JSON field is a JSON **number**; booleans are booleans.
* `diagnosis.sh`: 88/100 with apache2 down → 94/100 after healing it.
* Live heal: `inactive → active` in 0.12 s; re-running returns `already_healthy`.
* All four healing guards refuse correctly, including `apache2; rm -rf /` and `../../bin/sh`.
* Anomaly detection on 75 real samples with 2 of 4 cores loaded: **4 CRITICAL, 26 NORMAL, zero false positives**.
* Full incident cycle observed live: one incident, six symptoms, escalation and self-resolution, all in the timeline.
* 9 test suites, **426 checks**, all passing; each exits non-zero on any regression.
* Every page returns HTTP 200; the guided form refuses all ten hostile inputs.

---

## 10. The honest weaknesses

1. **User timers only run while the user has a session.** `Linger=no` on this VM; `loginctl enable-linger` would change that and is not needed for the demo.
2. **Ollama is not installed.** That is the tested state, and the console covers all 14 actions without it.
3. **Correlation is declared, not learned** — a deliberate trade of sophistication for defensibility.
4. **`guardian_actions.py` still carries its own copies of `read_config`/`config_words`** from before `guardian_config.py` was extracted; they shadow the imports. Harmless today, worth collapsing.
5. **The systemd unit is not installed**, so hands-off healing must be demonstrated by running the daemon in a terminal.
