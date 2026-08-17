# Linux Guardian — session prompts, one per session, in order

Saved verbatim as given on 2026-08-14. Paste one of these at the start of a new
session. `CLAUDE.md` is loaded automatically and carries the standing rules
(JSON-only stdout, `set -euo pipefail`, sourced config, real JSON numbers, a
comment above every command explaining what/flags/why-not-the-alternative,
`jq` + `shellcheck` proof after each script).

---

## Phase 1 — the Bash engine (COMPLETE)

Four scripts in `linux/`, one per session, approval between each:

1. `system.sh` — CPU %, RAM %, disk %, uptime, load average, hostname, kernel — **DONE**
2. `network.sh` — interface name, IP, gateway, DNS server, connectivity status — **DONE**
3. `process.sh` — top 10 processes by CPU (pid, name, cpu%, mem MB) — **DONE**
4. `services.sh` — status of apache2 and ssh (active/inactive/failed) — **DONE**

`network.sh` must ping `PING_TARGET` from the config (the VMware gateway,
192.168.138.2), **not** 8.8.8.8, so it stays green with no internet.
No script may stop, restart or modify anything — Phase 1 is read-only.

---

## Phase 2 — diagnosis (DONE)

> Write `linux/diagnosis.sh`. It runs all four Phase 1 scripts, evaluates each
> against thresholds in `guardian.conf`, and outputs JSON with per-check
> PASS/WARNING/FAIL plus an overall score out of 100. Explain the scoring logic.

---

## Phase 3 — healing (DONE)

> Write `linux/healing.sh`. Takes a service name as argument. Must refuse
> anything in `PROTECTED_SERVICES`. Only apache2 is allowed. Flow: detect state
> → attempt recovery → verify → log to `logs/guardian.log`. Outputs JSON with
> the result.

---

## Phase 4 — daemon (DONE)

> Write the systemd unit and a daemon loop script that checks apache2 every 30
> seconds and heals it automatically. Explain the unit file directive by
> directive.

---

## Phase 5 — Flask (DONE)

> Now build `app.py` — Flask, port 5000. Routes call the Bash scripts via
> subprocess and pass parsed JSON to Jinja2 templates. Whitelist of action names
> only, no command strings.
