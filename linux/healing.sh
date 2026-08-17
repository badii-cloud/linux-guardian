#!/bin/bash
# =============================================================================
#  Linux Guardian -- linux/healing.sh                          (Phase 3)
#
#  PURPOSE : Recover ONE named service, and record what happened.
#  USAGE   : ./healing.sh <service-name>          e.g. ./healing.sh apache2
#
#  FLOW    : validate -> refuse or allow -> detect state -> act -> VERIFY -> log
#
#  THIS IS THE FIRST SCRIPT IN THE PROJECT THAT CHANGES THE SYSTEM.
#  Phases 1 and 2 only look. From here on the tool can act, so nearly half of
#  this file is about deciding what it is NOT allowed to touch.
#
#  THE SAFETY MODEL -- TWO INDEPENDENT LISTS, CHECKED IN THIS ORDER
#    1. PROTECTED_SERVICES  a DENY list. Named things that must never be
#       touched: restarting ssh can lock an administrator out of a remote
#       machine; systemd-logind, dbus or NetworkManager will take the desktop
#       down with them. Checked FIRST so the refusal is explicit and logged
#       with the real reason.
#    2. HEALABLE_SERVICES   an ALLOW list, currently just apache2. Anything not
#       named here is refused even if it is not on the deny list.
#
#  WHY BOTH. A deny list alone can only block what somebody thought of in
#  advance; every service invented tomorrow is permitted by default. An allow
#  list alone would work, but it would report "not allowed" for ssh without
#  saying that ssh is specifically dangerous. Together: the allow list makes
#  the safe direction the default, and the deny list explains WHY for the cases
#  that matter most.
#
#  PRIVILEGES: starting a service requires root. This script does NOT run as
#  root and must never prompt for a password (a web request would hang for
#  ever). It uses `sudo -n`, backed by the rule in config/linux-guardian.sudoers
#  which grants exactly three commands on exactly one unit. See that file.
# =============================================================================


set -euo pipefail
set -E
export LC_ALL=C

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname -- "$SCRIPT_DIR")"

emit_error() {
    printf '{"module":"healing","status":"error","message":"%s"}\n' "$1"
    exit 1
}
trap 'emit_error "healing.sh failed at line $LINENO"' ERR

json_string() {
    local text="${1:-}"
    if [[ -z "$text" ]]; then
        printf 'null'
        return
    fi
    text="${text//\\/\\\\}"
    text="${text//\"/\\\"}"
    printf '"%s"' "$text"
}


# -----------------------------------------------------------------------------
# Load the configuration.
# -----------------------------------------------------------------------------
CONFIG_FILE="$PROJECT_ROOT/config/guardian.conf"
[[ -r "$CONFIG_FILE" ]] || emit_error "config file not found or not readable: $CONFIG_FILE"

export GUARDIAN_ROOT="$PROJECT_ROOT"
# shellcheck source=../config/guardian.conf
source "$CONFIG_FILE"

PROTECTED_SERVICES="${PROTECTED_SERVICES:-ssh sshd systemd-logind NetworkManager dbus}"
HEALABLE_SERVICES="${HEALABLE_SERVICES:-apache2}"
HEAL_VERIFY_ATTEMPTS="${HEAL_VERIFY_ATTEMPTS:-5}"
HEAL_VERIFY_DELAY="${HEAL_VERIFY_DELAY:-1}"
LOG_FILE="${LOG_FILE:-$PROJECT_ROOT/logs/guardian.log}"

command -v systemctl > /dev/null 2>&1 || emit_error "systemctl not found: this module requires systemd"


# =============================================================================
#  LOGGING -- the audit trail
# =============================================================================
#
# Every decision this script makes is written to logs/guardian.log, including
# the refusals. An action that was REFUSED is exactly as important to record as
# one that was carried out: the log has to answer "did this tool ever touch
# ssh?" and the honest answer must be provable, not assumed.
#
#   mkdir -p   create the directory, and do not complain if it already exists
#              (-p also creates missing parents). Without -p, a second run
#              would fail on the existing directory.
#   >>         APPEND. A single > would truncate the log on every run and throw
#              away the entire history -- the opposite of an audit trail.
#   date '+%F %T'   %F is the ISO date (2026-08-14), %T the time (18:30:00).
#              ISO order is used so the file sorts chronologically with `sort`.
# -----------------------------------------------------------------------------
mkdir -p -- "$(dirname -- "$LOG_FILE")"

log_line() {
    local level="$1" message="$2"
    printf '%s [%s] healing.sh: %s\n' "$(date '+%F %T')" "$level" "$message" >> "$LOG_FILE"
}


# =============================================================================
#  RUNNING systemctl WITH THE RIGHT PRIVILEGES
# =============================================================================
#
#   EUID          a Bash variable holding the EFFECTIVE user id. 0 means root.
#                 CHOSEN OVER `whoami` or `id -u`: EUID is already in memory,
#                 so this costs no process, and "effective" is the id that
#                 actually decides permission.
#   sudo -n       NON-INTERACTIVE. If a password would be required, sudo fails
#                 immediately instead of waiting for input.
#                 THIS FLAG IS THE WHOLE POINT: healing.sh is called from a web
#                 request in Phase 5 and from a background daemon in Phase 4.
#                 Neither has a terminal. Without -n, a missing sudoers rule
#                 would make the dashboard hang for ever on an invisible
#                 password prompt instead of reporting a clear error.
# -----------------------------------------------------------------------------
run_systemctl() {
    if (( EUID == 0 )); then
        systemctl "$@"
    else
        sudo -n systemctl "$@"
    fi
}

# Read one property of a unit. `systemctl show` is used rather than is-active
# for the reason explained at length in services.sh: is-active exits 3 for an
# inactive unit and 4 for a missing one, which `set -e` would treat as fatal,
# whereas show always exits 0. Reading state needs no privileges.
unit_property() {
    systemctl show "$1" --property="$2" --value 2>/dev/null || printf ''
}


# =============================================================================
#  STEP 1 -- VALIDATE THE ARGUMENT
# =============================================================================
#
# $# is the number of arguments. Exactly one is required.
# -----------------------------------------------------------------------------
if (( $# != 1 )); then
    emit_error "usage: healing.sh <service-name>  (exactly one argument required)"
fi

requested_service="$1"

# INPUT VALIDATION, and it is not a formality. In Phase 5 this argument arrives
# from an HTTP request. The name is passed to sudo, so anything unexpected in it
# is a privilege-escalation attempt.
#
#   =~            Bash's regular-expression match operator.
#   ^[A-Za-z0-9@._-]+$   anchored at both ends: the WHOLE name must consist of
#                 letters, digits, @ . _ or -. Those are the characters systemd
#                 actually allows in a unit name (@ for templated units such as
#                 getty@tty1). Everything else -- spaces, semicolons, quotes,
#                 slashes, $, backticks -- is rejected before it reaches sudo.
#
# This is an ALLOW list of characters, not a list of forbidden ones, for the
# same reason HEALABLE_SERVICES is an allow list: it fails safe.
if [[ ! "$requested_service" =~ ^[A-Za-z0-9@._-]+$ ]]; then
    log_line "REFUSED" "rejected malformed service name"
    emit_error "invalid service name: only letters, digits, @ . _ and - are allowed"
fi

# Compare on the BASE name so that "apache2" and "apache2.service" are treated
# as the same thing. Otherwise a caller could bypass the deny list simply by
# adding the suffix.
#   ${var%.service}   remove that suffix if present
service_base="${requested_service%.service}"

if [[ "$requested_service" == *.* ]]; then
    unit_name="$requested_service"
else
    unit_name="$requested_service.service"
fi


# =============================================================================
#  STEP 2 -- THE TWO SAFETY LISTS
# =============================================================================

# Does a space-separated list contain this exact word?
# Splitting into a real array with `read -r -a` avoids relying on unquoted word
# splitting, and comparing whole elements avoids the classic substring bug where
# "ssh" would appear to match "sshd" -- or worse, where "h" would match "ssh".
list_contains() {
    local list="$1" wanted="$2"
    local -a elements
    local element
    read -r -a elements <<< "$list"
    for element in "${elements[@]}"; do
        if [[ "$element" == "$wanted" ]]; then
            return 0
        fi
    done
    return 1
}

# The refusal path is shared by both lists: log it, print the JSON, exit 1.
refuse() {
    local reason="$1"
    log_line "REFUSED" "$service_base -- $reason"
    cat << EOF
{
  "module": "healing",
  "status": "ok",
  "timestamp": $(date +%s),
  "timestamp_human": "$(date '+%F %T')",
  "service": $(json_string "$service_base"),
  "unit": $(json_string "$unit_name"),
  "allowed": false,
  "result": "refused",
  "action": "none",
  "state_before": null,
  "state_after": null,
  "healthy": false,
  "message": $(json_string "$reason"),
  "log_file": $(json_string "$LOG_FILE")
}
EOF
    exit 1
}

# DENY LIST FIRST, so the refusal names the real danger.
if list_contains "$PROTECTED_SERVICES" "$service_base"; then
    refuse "$service_base is a PROTECTED service and must never be restarted by this tool"
fi

# ALLOW LIST SECOND: anything not explicitly permitted is refused by default.
if ! list_contains "$HEALABLE_SERVICES" "$service_base"; then
    refuse "$service_base is not in HEALABLE_SERVICES (allowed: $HEALABLE_SERVICES)"
fi


# =============================================================================
#  STEP 3 -- DETECT THE CURRENT STATE
# =============================================================================
load_state="$(unit_property "$unit_name" LoadState)"
state_before="$(unit_property "$unit_name" ActiveState)"

# You cannot start what is not installed. Reporting this clearly is far more
# useful than letting systemctl fail with "Unit not found" a second later.
if [[ "$load_state" == "not-found" ]]; then
    log_line "ERROR" "$service_base -- unit $unit_name is not installed"
    cat << EOF
{
  "module": "healing",
  "status": "ok",
  "timestamp": $(date +%s),
  "timestamp_human": "$(date '+%F %T')",
  "service": $(json_string "$service_base"),
  "unit": $(json_string "$unit_name"),
  "allowed": true,
  "result": "not_installed",
  "action": "none",
  "state_before": $(json_string "$state_before"),
  "state_after": $(json_string "$state_before"),
  "healthy": false,
  "message": $(json_string "unit $unit_name is not installed on this system"),
  "log_file": $(json_string "$LOG_FILE")
}
EOF
    exit 1
fi

# ALREADY HEALTHY: do nothing. A self-healing tool that restarts a working
# service every time it looks at it is not healing, it is causing outages.
if [[ "$state_before" == "active" ]]; then
    log_line "INFO" "$service_base -- already active, no action taken"
    cat << EOF
{
  "module": "healing",
  "status": "ok",
  "timestamp": $(date +%s),
  "timestamp_human": "$(date '+%F %T')",
  "service": $(json_string "$service_base"),
  "unit": $(json_string "$unit_name"),
  "allowed": true,
  "result": "already_healthy",
  "action": "none",
  "state_before": $(json_string "$state_before"),
  "state_after": $(json_string "$state_before"),
  "healthy": true,
  "message": $(json_string "$unit_name was already active; nothing to do"),
  "log_file": $(json_string "$LOG_FILE")
}
EOF
    exit 0
fi


# =============================================================================
#  STEP 4 -- ATTEMPT RECOVERY
# =============================================================================
#
# THE reset-failed STEP IS THE ONE PEOPLE LEAVE OUT.
# When a unit fails, systemd remembers it and applies a rate limit
# (StartLimitBurst / StartLimitIntervalSec: by default 5 starts in 10 seconds).
# A daemon that retries every 30 seconds will trip that limit and every later
# attempt is refused with "start request repeated too quickly" -- the healing
# stops working precisely when it is needed most. `systemctl reset-failed`
# clears the remembered failure and the counter.
#
#   || true   reset-failed is housekeeping, not the goal. If it fails (for
#             instance because the unit was merely inactive and never failed)
#             we still want to try starting the service, so its exit status is
#             deliberately discarded rather than tripping `set -e`.
# -----------------------------------------------------------------------------
read -r heal_start_time _ < /proc/uptime

if [[ "$state_before" == "failed" ]]; then
    action="reset-failed+start"
    log_line "ACTION" "$service_base -- state=$state_before, clearing failure counter"
    run_systemctl reset-failed "$unit_name" > /dev/null 2>&1 || true
else
    action="start"
fi

log_line "ACTION" "$service_base -- state=$state_before, running: systemctl start $unit_name"

# `systemctl start` may legitimately fail (no sudo rule, bad config file, port
# already taken). That is a RESULT to report, not a crash, so its exit status is
# captured rather than allowed to trip `set -e`.
start_exit_code=0
start_output="$(run_systemctl start "$unit_name" 2>&1)" || start_exit_code=$?


# =============================================================================
#  STEP 5 -- VERIFY  (never trust the exit code alone)
# =============================================================================
#
# `systemctl start` returns as soon as systemd considers the unit activated.
# apache2 can still die a second later while reading its own configuration, and
# a naive script would have already reported success. So we re-read the actual
# state, up to HEAL_VERIFY_ATTEMPTS times.
#
# The loop stops the moment the unit is active, so the normal case costs one
# check and no waiting at all.
# -----------------------------------------------------------------------------
state_after="$state_before"
verify_attempts=0

while (( verify_attempts < HEAL_VERIFY_ATTEMPTS )); do
    verify_attempts=$(( verify_attempts + 1 ))
    state_after="$(unit_property "$unit_name" ActiveState)"
    if [[ "$state_after" == "active" ]]; then
        break
    fi
    # Do not sleep after the final attempt -- there is nothing left to wait for.
    if (( verify_attempts < HEAL_VERIFY_ATTEMPTS )); then
        sleep "$HEAL_VERIFY_DELAY"
    fi
done

read -r heal_end_time _ < /proc/uptime
duration_seconds="$(awk -v a="$heal_end_time" -v b="$heal_start_time" \
    'BEGIN { printf "%.2f", a - b }')"

if [[ "$state_after" == "active" ]]; then
    result="healed"
    healthy="true"
    message="$unit_name recovered: $state_before -> $state_after in ${duration_seconds}s"
    log_line "SUCCESS" "$service_base -- $message"
    exit_code=0
else
    result="heal_failed"
    healthy="false"
    # start_output holds systemctl's own explanation (for example the sudo
    # refusal). Only its first line is kept: the JSON message is for a
    # dashboard, not a transcript, and the full text is in the log.
    first_line="${start_output%%$'\n'*}"
    message="$unit_name did NOT recover: still $state_after after $verify_attempts checks. ${first_line}"
    log_line "FAILURE" "$service_base -- $message (systemctl exit $start_exit_code)"
    exit_code=1
fi


# =============================================================================
#  OUTPUT
# =============================================================================
cat << EOF
{
  "module": "healing",
  "status": "ok",
  "timestamp": $(date +%s),
  "timestamp_human": "$(date '+%F %T')",
  "service": $(json_string "$service_base"),
  "unit": $(json_string "$unit_name"),
  "allowed": true,
  "result": "$result",
  "action": "$action",
  "state_before": $(json_string "$state_before"),
  "state_after": $(json_string "$state_after"),
  "healthy": $healthy,
  "verify_attempts": $verify_attempts,
  "duration_seconds": $duration_seconds,
  "systemctl_exit_code": $start_exit_code,
  "message": $(json_string "$message"),
  "log_file": $(json_string "$LOG_FILE")
}
EOF

exit "$exit_code"
