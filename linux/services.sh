#!/bin/bash
# =============================================================================
#  Linux Guardian -- linux/services.sh        (Phase 1, module 4 of 4)
#
#  PURPOSE : Report the state of every service listed in MONITORED_SERVICES
#            (apache2 and ssh) as ONE JSON object on standard output.
#
#  THE CENTRAL DECISION OF THIS MODULE -- WHY `systemctl show`
#            The obvious command is `systemctl is-active apache2`. It is the
#            wrong tool here for two concrete reasons, both measured on this
#            machine:
#
#            1. IT EXITS NON-ZERO ON PURPOSE.
#                 systemctl is-active ssh              -> "inactive", exit 3
#                 systemctl is-active not-a-real-unit  -> "inactive", exit 4
#               Under `set -e` that terminates the script. A service being
#               stopped is the ANSWER WE ARE LOOKING FOR, not a failure, so we
#               would have to write "|| true" after every call and then work out
#               afterwards which exit code meant what.
#
#            2. IT ANSWERS ONE QUESTION AT A TIME. Active state, enabled state,
#               main PID and "is it even installed" would be four separate
#               commands, four processes, and four chances for the service to
#               change state between them.
#
#            `systemctl show` is systemd's MACHINE-READABLE interface. It prints
#            stable "Key=Value" lines, returns ALL the properties in one call,
#            and -- verified on this machine -- exits 0 even for a unit that
#            does not exist, reporting LoadState=not-found instead.
#
#            `systemctl status` was rejected too: it is built for humans. It
#            prints colour, indentation and the last few journal lines, and its
#            layout changes between systemd versions. Parsing it would be
#            guessing at a format nobody promised to keep.
#
#  SAFETY  : 100% READ-ONLY. It asks systemd questions. It never starts, stops,
#            restarts, enables or disables anything. Starting apache2 is
#            Phase 3's job (healing.sh), and even then only for apache2.
# =============================================================================


# -----------------------------------------------------------------------------
# The safety switches -- identical in every module of this project.
#   -e  stop on the first failing command
#   -u  stop if an unset variable is used
#   -o pipefail  a pipeline fails if ANY stage fails, not only the last
# -----------------------------------------------------------------------------
set -euo pipefail

# Let the ERR trap fire inside functions and command substitutions too.
set -E

# Force the C locale so printf always writes a decimal POINT, never a comma,
# and so systemctl does not translate its property values into another language.
export LC_ALL=C


# -----------------------------------------------------------------------------
# Locate the project, so the script works from any working directory
# (systemd runs it from "/", Flask from wherever the terminal happened to be).
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname -- "$SCRIPT_DIR")"


# -----------------------------------------------------------------------------
# The failure contract: even a crash must produce valid JSON, because Flask
# feeds our stdout straight into json.loads().
# -----------------------------------------------------------------------------
emit_error() {
    printf '{"module":"services","status":"error","message":"%s"}\n' "$1"
    exit 1
}
# SINGLE quotes delay $LINENO until the trap fires, so it names the real line.
trap 'emit_error "services.sh failed at line $LINENO"' ERR


# -----------------------------------------------------------------------------
# JSON HELPERS -- identical in every module that needs them.
#
# json_string does two jobs:
#   1. An EMPTY value becomes the JSON literal `null`, not "". JSON has no idea
#      of "empty"; null is how it says "this value does not exist" and Python
#      receives it as None. A stopped service has no start timestamp at all, so
#      "" would be a lie.
#   2. It ESCAPES the two characters that can break out of a JSON string.
#      A unit's Description is written by whoever authored the unit file, so it
#      is not text this project controls.
#
#   ${var//pattern/replacement}   replace EVERY occurrence.
# ORDER MATTERS: backslashes first. Escaping quotes first would then double the
# backslashes we had just added.
# -----------------------------------------------------------------------------
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

json_number() {
    if [[ -n "${1:-}" ]]; then
        printf '%s' "$1"
    else
        printf 'null'
    fi
}


# -----------------------------------------------------------------------------
# Load the configuration.
#   source runs the file in THIS shell so its variables survive; running it as
#   a program would start a child shell and lose them.
# -----------------------------------------------------------------------------
CONFIG_FILE="$PROJECT_ROOT/config/guardian.conf"
[[ -r "$CONFIG_FILE" ]] || emit_error "config file not found or not readable: $CONFIG_FILE"

export GUARDIAN_ROOT="$PROJECT_ROOT"
# shellcheck source=../config/guardian.conf
source "$CONFIG_FILE"

MONITORED_SERVICES="${MONITORED_SERVICES:-apache2 ssh}"

# command -v looks a command up in $PATH and fails if it is not there.
# CHOSEN OVER `which`: command -v is a shell BUILTIN required by POSIX, while
# `which` is a separate program that is not installed everywhere and whose exit
# status is unreliable across distributions.
# This check turns "systemctl: command not found" -- which would print a raw
# error and produce no JSON at all -- into a proper error object.
command -v systemctl > /dev/null 2>&1 || emit_error "systemctl not found: this module requires systemd"


# -----------------------------------------------------------------------------
# Turn the configured list into a real Bash array.
#
# MONITORED_SERVICES is one string, "apache2 ssh". Writing `for s in $MONITORED_SERVICES`
# would work, but it relies on unquoted word splitting -- the exact habit that
# breaks the moment a value contains a space, and shellcheck warns about it for
# good reason. `read -r -a` splits the string into an array explicitly, which
# says what we mean.
#   -a NAME   read the words into array NAME
#   -r        do not treat backslash as an escape character
#   <<<       here-string: feed a variable to a command as its standard input
# -----------------------------------------------------------------------------
read -r -a monitored_list <<< "$MONITORED_SERVICES"


# =============================================================================
#  INSPECT EACH SERVICE
# =============================================================================
services_json=""
count_total=0
count_running=0
count_failed=0
count_not_installed=0

for service_name in "${monitored_list[@]}"; do
    count_total=$(( count_total + 1 ))

    # systemd unit names carry a type suffix: apache2.service, ssh.socket,
    # multi-user.target. systemctl assumes ".service" when none is given, but we
    # make it explicit so the JSON is unambiguous about what was actually
    # queried. (Assumption: a plain name with no dot means a service. Our config
    # only ever holds plain names such as "apache2" and "ssh".)
    if [[ "$service_name" == *.* ]]; then
        unit_name="$service_name"
    else
        unit_name="$service_name.service"
    fi

    # ONE call fetches every property we need.
    #   --property=A,B,C   ask for exactly these, comma separated. Without it,
    #                      systemctl prints all ~200 properties of the unit.
    # NOTE: systemd returns them in ITS OWN order, not the order requested
    # (verified: Description came back first even though it was asked for last).
    # That is why the values are read into a lookup table by NAME below, and
    # never by line position.
    unit_properties="$(systemctl show "$unit_name" \
        --property=Description,LoadState,ActiveState,SubState,UnitFileState,MainPID,ActiveEnterTimestamp)"

    # declare -A creates an ASSOCIATIVE array: a table whose keys are strings.
    # It is re-declared on every pass of the loop so one service can never
    # inherit a leftover value from the previous one.
    declare -A property
    property=()

    # IFS='=' tells read to split each line on the FIRST "=" only, because
    # `value` is the last variable named and therefore receives all the rest of
    # the line. That matters: a Description may legitimately contain "=".
    #   IFS='=' applies to this one command only -- it is not changed globally.
    while IFS='=' read -r key value; do
        if [[ -n "$key" ]]; then
            property["$key"]="$value"
        fi
    done <<< "$unit_properties"

    # ${map[key]:-} returns an empty string when the key is absent instead of
    # aborting under `set -u`.
    load_state="${property[LoadState]:-}"
    active_state="${property[ActiveState]:-}"
    sub_state="${property[SubState]:-}"
    enabled_state="${property[UnitFileState]:-}"
    main_pid="${property[MainPID]:-0}"
    active_since="${property[ActiveEnterTimestamp]:-}"
    description="${property[Description]:-}"

    # --- turn systemd's vocabulary into the booleans a dashboard needs --------
    #
    # LoadState answers a question `is-active` cannot: does this unit EXIST?
    #   loaded     -> the unit file was found and parsed
    #   not-found  -> the software is not installed at all
    #   masked     -> installed, but deliberately blocked from ever starting
    # Phase 3 (healing.sh) depends on this: attempting to restart something that
    # is not installed must be refused, not attempted.
    if [[ "$load_state" == "not-found" ]]; then
        installed="false"
        count_not_installed=$(( count_not_installed + 1 ))
    else
        installed="true"
    fi

    # ActiveState is the active / inactive / failed value this module is for.
    #   active   running normally
    #   inactive stopped, and nothing went wrong
    #   failed   it stopped BECAUSE something went wrong  <- what Phase 3 heals
    if [[ "$active_state" == "active" ]]; then
        running="true"
        count_running=$(( count_running + 1 ))
    else
        running="false"
    fi

    if [[ "$active_state" == "failed" ]]; then
        failed="true"
        count_failed=$(( count_failed + 1 ))
    else
        failed="false"
    fi

    # UnitFileState answers "will it come back by itself after a reboot?".
    # enabled-runtime means enabled only until the next reboot, so it counts as
    # enabled now but is deliberately reported as its own string as well.
    if [[ "$enabled_state" == "enabled" || "$enabled_state" == "enabled-runtime" ]]; then
        enabled="true"
    else
        enabled="false"
    fi

    # systemd reports MainPID=0 when there is no main process. 0 is not a pid;
    # it is systemd's way of saying "none", so it becomes JSON null.
    if [[ "$main_pid" == "0" ]]; then
        main_pid=""
    fi

    # A comma goes BETWEEN entries and never after the last one -- a trailing
    # comma is the most common way of writing invalid JSON.
    if [[ -n "$services_json" ]]; then
        services_json+=","
    fi

    # printf -v NAME writes into a variable instead of to the screen, with no
    # subshell and no command substitution.
    printf -v entry '\n    {\n      "name": %s,\n      "unit": %s,\n      "description": %s,\n      "installed": %s,\n      "load_state": %s,\n      "active_state": %s,\n      "sub_state": %s,\n      "enabled_state": %s,\n      "running": %s,\n      "failed": %s,\n      "enabled": %s,\n      "main_pid": %s,\n      "active_since": %s\n    }' \
        "$(json_string "$service_name")" \
        "$(json_string "$unit_name")" \
        "$(json_string "$description")" \
        "$installed" \
        "$(json_string "$load_state")" \
        "$(json_string "$active_state")" \
        "$(json_string "$sub_state")" \
        "$(json_string "$enabled_state")" \
        "$running" \
        "$failed" \
        "$enabled" \
        "$(json_number "$main_pid")" \
        "$(json_string "$active_since")"

    services_json+="$entry"
done

# "[]" is how JSON spells an empty list, and the dashboard must still receive a
# valid document when there is nothing to report.
# PRECISELY WHEN THIS FIRES: ${VAR:-default} above treats an EMPTY value the
# same as an unset one, so MONITORED_SERVICES="" falls back to "apache2 ssh"
# rather than reaching here. This branch is reached when the value is present
# but contains no service names -- for example a line left as a single space --
# which read -r -a turns into an array of zero elements. (Verified both ways.)
if [[ -z "$services_json" ]]; then
    services_array="[]"
else
    services_array="[$services_json
  ]"
fi


# =============================================================================
#  TIMESTAMP
# =============================================================================
timestamp_epoch="$(date +%s)"
timestamp_human="$(date '+%Y-%m-%d %H:%M:%S')"


# =============================================================================
#  OUTPUT -- one JSON object, printed once, at the very end
# =============================================================================
# Nothing was printed before this point, so stdout holds either one complete
# document or one complete error document -- never half of either.
#
# The summary block exists for Phase 2: diagnosis.sh can score service health
# from these four counters without walking the array itself.
#
# QUOTING RULES:
#   strings  -> json_string (quoted, escaped, or null)
#   numbers  -> bare        (main_pid, the counters)
#   booleans -> bare true / false -- NOT the strings "true" / "false"
# =============================================================================
cat << EOF
{
  "module": "services",
  "status": "ok",
  "timestamp": $timestamp_epoch,
  "timestamp_human": "$timestamp_human",
  "summary": {
    "total": $count_total,
    "running": $count_running,
    "failed": $count_failed,
    "not_installed": $count_not_installed
  },
  "services": $services_array
}
EOF
