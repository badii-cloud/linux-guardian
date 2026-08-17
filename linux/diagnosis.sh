#!/bin/bash
# =============================================================================
#  Linux Guardian -- linux/diagnosis.sh                        (Phase 2)
#
#  PURPOSE : Run all four Phase 1 modules, judge every measurement against the
#            thresholds in guardian.conf, and produce ONE JSON object holding a
#            PASS / WARNING / FAIL verdict per check plus an overall health
#            score out of 100.
#
#  Phase 1 MEASURES. Phase 2 JUDGES. That separation is deliberate: the four
#  modules contain no opinion about what "too high" means, so the thresholds
#  live in exactly one file and are applied in exactly one script.
#
#  SAFETY  : Still 100% READ-ONLY. This script decides that something is wrong;
#            it does not act on it. Acting is Phase 3 (healing.sh).
#
#  DEPENDENCY: jq -- see the guard below for why.
# =============================================================================


# -----------------------------------------------------------------------------
# The safety switches -- identical in every module of this project.
# -----------------------------------------------------------------------------
set -euo pipefail
set -E
export LC_ALL=C

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname -- "$SCRIPT_DIR")"

emit_error() {
    printf '{"module":"diagnosis","status":"error","message":"%s"}\n' "$1"
    exit 1
}
trap 'emit_error "diagnosis.sh failed at line $LINENO"' ERR

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
# WHY jq, AND WHY NOT grep / sed / awk
#
# This script has to read values out of the JSON the four modules produce.
# Reaching for `grep '"usage_percent"' | sed 's/.*: //'` is the classic mistake:
# JSON is not a line-based format. Whitespace, key order and nesting are all
# free to change, the same key name can appear at two different depths
# (usage_percent exists under cpu, memory AND disk in system.sh), and a value
# may legitimately contain a colon or a brace inside a string. A text tool has
# no idea which "usage_percent" it just matched.
#
# jq is a real JSON parser: it understands the document's STRUCTURE, so
# ".memory.usage_percent" can only ever mean one thing.
#
# It is not installed by default on Kali, so we check for it and say exactly
# what to do rather than failing with "jq: command not found" and no JSON.
#   command -v   POSIX shell builtin that looks a command up in $PATH.
#                CHOSEN OVER `which`, a separate program that is not installed
#                everywhere and whose exit status is unreliable.
# -----------------------------------------------------------------------------
command -v jq > /dev/null 2>&1 || emit_error "jq is required but not installed -- run: sudo apt install -y jq"


# -----------------------------------------------------------------------------
# Load the configuration and give every threshold a safe default, so a deleted
# line degrades the score rather than killing the script under `set -u`.
# -----------------------------------------------------------------------------
CONFIG_FILE="$PROJECT_ROOT/config/guardian.conf"
[[ -r "$CONFIG_FILE" ]] || emit_error "config file not found or not readable: $CONFIG_FILE"

export GUARDIAN_ROOT="$PROJECT_ROOT"
# shellcheck source=../config/guardian.conf
source "$CONFIG_FILE"

CPU_WARNING="${CPU_WARNING:-70}";                     CPU_CRITICAL="${CPU_CRITICAL:-90}"
RAM_WARNING="${RAM_WARNING:-75}";                     RAM_CRITICAL="${RAM_CRITICAL:-90}"
DISK_WARNING="${DISK_WARNING:-80}";                   DISK_CRITICAL="${DISK_CRITICAL:-90}"
LOAD_WARNING_PER_CORE="${LOAD_WARNING_PER_CORE:-1.0}"
LOAD_CRITICAL_PER_CORE="${LOAD_CRITICAL_PER_CORE:-2.0}"
PROCESS_CPU_WARNING="${PROCESS_CPU_WARNING:-70}";     PROCESS_CPU_CRITICAL="${PROCESS_CPU_CRITICAL:-90}"


# =============================================================================
#  HELPERS
# =============================================================================

# ---------------------------------------------------------------------------
# classify <value> <warning> <critical>  ->  prints PASS, WARNING or FAIL
#
# Bash arithmetic is INTEGER ONLY, so `if (( 21.6 > 70 ))` is a syntax error.
# Every threshold comparison in this script therefore goes through awk, which
# understands floating point.
#
# The order of the tests matters: critical is checked FIRST, because a value of
# 95 is above both thresholds and must report the worse of the two.
# The comparison is ">=" so that a threshold of 90 means "90 is already too
# much", which is what a reader expects "critical: 90" to mean.
# ---------------------------------------------------------------------------
classify() {
    awk -v value="$1" -v warning="$2" -v critical="$3" 'BEGIN {
        if (value >= critical)     { print "FAIL" }
        else if (value >= warning) { print "WARNING" }
        else                       { print "PASS" }
    }'
}

# ---------------------------------------------------------------------------
# add_check <id> <label> <value> <unit> <warning> <critical> <result> <message>
#
# Appends one check object to the JSON array being built and updates the
# counters the score is computed from. Every check in this script goes through
# this one function, so the shape of a check object is defined in exactly one
# place.
# ---------------------------------------------------------------------------
checks_json=""
checks_total=0
checks_passed=0
checks_warning=0
checks_failed=0

add_check() {
    local id="$1" label="$2" value="$3" unit="$4"
    local warning="$5" critical="$6" result="$7" message="$8"

    checks_total=$(( checks_total + 1 ))
    case "$result" in
        PASS)    checks_passed=$(( checks_passed + 1 )) ;;
        WARNING) checks_warning=$(( checks_warning + 1 )) ;;
        FAIL)    checks_failed=$(( checks_failed + 1 )) ;;
    esac

    # A comma goes BETWEEN entries, never after the last one.
    if [[ -n "$checks_json" ]]; then
        checks_json+=","
    fi

    # value/warning/critical are printed with %s and no quotes -> real JSON
    # numbers. When a module failed there is no number to report, so the caller
    # passes an empty string and we substitute the JSON literal null.
    local value_json="${value:-null}"
    local warning_json="${warning:-null}"
    local critical_json="${critical:-null}"

    printf -v entry '\n    {\n      "id": %s,\n      "label": %s,\n      "value": %s,\n      "unit": %s,\n      "warning_threshold": %s,\n      "critical_threshold": %s,\n      "result": %s,\n      "message": %s\n    }' \
        "$(json_string "$id")" "$(json_string "$label")" \
        "$value_json" "$(json_string "$unit")" \
        "$warning_json" "$critical_json" \
        "$(json_string "$result")" "$(json_string "$message")"

    checks_json+="$entry"
}

# ---------------------------------------------------------------------------
# run_module <name>  ->  prints the module's JSON, or "" if it failed
#
# `set -e` would abort the whole script the moment a module exited non-zero.
# But a module failing is information we want to REPORT, not a reason to die,
# so its status is captured deliberately with "|| exit_code=$?".
#
# A module is only trusted if BOTH are true: it exited 0, AND its own JSON says
# status == "ok". The second test matters because the modules catch their own
# errors and still print valid JSON with status "error".
# ---------------------------------------------------------------------------
run_module() {
    local name="$1"
    local output="" exit_code=0

    output="$("$SCRIPT_DIR/$name.sh" 2>/dev/null)" || exit_code=$?
    if (( exit_code != 0 )); then
        return 0    # prints nothing; caller sees an empty string
    fi
    # jq -e sets a non-zero exit status when the filter yields false or null,
    # which is how we test the status field without a second parse.
    if ! printf '%s' "$output" | jq -e '.status == "ok"' > /dev/null 2>&1; then
        return 0
    fi
    printf '%s' "$output"
}


# =============================================================================
#  STEP 1 -- RUN THE FOUR PHASE 1 MODULES
# =============================================================================
system_json="$(run_module system)"
network_json="$(run_module network)"
process_json="$(run_module process)"
services_json="$(run_module services)"

module_status() { if [[ -n "$1" ]]; then printf 'ok'; else printf 'error'; fi; }


# =============================================================================
#  STEP 2 -- JUDGE THE SYSTEM MODULE  (CPU, memory, disk, load average)
# =============================================================================
if [[ -n "$system_json" ]]; then
    # ONE jq call extracts every value this block needs.
    #   [ ... ] | @tsv   builds an array and prints it tab separated, which is
    #                    the safe separator here: a tab can never appear inside
    #                    any of these numbers.
    #   IFS=$'\t' read   split on tabs only, for this one command.
    system_values="$(printf '%s' "$system_json" | jq -r '[
        .cpu.usage_percent,
        .memory.usage_percent,
        .disk.usage_percent,
        .load_average.last_1min,
        .cpu.cores
    ] | @tsv')"
    IFS=$'\t' read -r cpu_usage ram_usage disk_usage load_1min cpu_cores <<< "$system_values"

    result="$(classify "$cpu_usage" "$CPU_WARNING" "$CPU_CRITICAL")"
    add_check "cpu" "CPU usage" "$cpu_usage" "%" "$CPU_WARNING" "$CPU_CRITICAL" "$result" \
        "CPU usage is ${cpu_usage}% (warning at ${CPU_WARNING}%, critical at ${CPU_CRITICAL}%)"

    result="$(classify "$ram_usage" "$RAM_WARNING" "$RAM_CRITICAL")"
    add_check "memory" "Memory usage" "$ram_usage" "%" "$RAM_WARNING" "$RAM_CRITICAL" "$result" \
        "Memory usage is ${ram_usage}% (warning at ${RAM_WARNING}%, critical at ${RAM_CRITICAL}%)"

    result="$(classify "$disk_usage" "$DISK_WARNING" "$DISK_CRITICAL")"
    add_check "disk" "Disk usage" "$disk_usage" "%" "$DISK_WARNING" "$DISK_CRITICAL" "$result" \
        "Root filesystem is ${disk_usage}% full (warning at ${DISK_WARNING}%, critical at ${DISK_CRITICAL}%)"

    # LOAD AVERAGE IS JUDGED PER CORE, and this is the one threshold that would
    # be wrong if taken literally. A load of 4.00 means "four processes wanted
    # the CPU at once": on this 4-core VM that is exactly full, but on a 1-core
    # VM it is a four-times overload. Dividing by the core count turns the raw
    # figure into a comparable ratio, which is why cpu.cores is in system.sh's
    # output at all.
    # NOTE ON THE VARIABLE NAME: this awk variable is called load_value, not
    # `load`, because `load` is a BUILT-IN FUNCTION NAME in gawk (it loads an
    # extension) and gawk refuses it with "cannot use gawk builtin `load' as
    # variable name". Found while testing this script -- the error trap caught
    # it and reported the exact line, which is what the trap is for.
    load_per_core="$(awk -v load_value="$load_1min" -v cores="$cpu_cores" \
        'BEGIN { printf "%.2f", (cores > 0 ? load_value / cores : load_value) }')"
    result="$(classify "$load_per_core" "$LOAD_WARNING_PER_CORE" "$LOAD_CRITICAL_PER_CORE")"
    add_check "load" "Load average per core" "$load_per_core" "ratio" \
        "$LOAD_WARNING_PER_CORE" "$LOAD_CRITICAL_PER_CORE" "$result" \
        "1-minute load ${load_1min} across ${cpu_cores} cores = ${load_per_core} per core"
else
    # The module could not be trusted, so its four checks cannot be evaluated.
    # They are recorded as FAIL rather than silently dropped: a check that
    # vanishes would quietly RAISE the score, which is the opposite of what a
    # broken sensor should do.
    for pair in "cpu:CPU usage" "memory:Memory usage" "disk:Disk usage" "load:Load average per core"; do
        add_check "${pair%%:*}" "${pair#*:}" "" "" "" "" "FAIL" "system.sh did not return usable data"
    done
fi


# =============================================================================
#  STEP 3 -- JUDGE THE PROCESS MODULE  (is one process running away?)
# =============================================================================
if [[ -n "$process_json" ]]; then
    # The array is already sorted, so element 0 is the busiest process.
    # // "" and // 0 supply a default when the array is empty, so jq prints
    # something rather than the word "null".
    process_values="$(printf '%s' "$process_json" | jq -r '[
        (.processes[0].cpu_percent // 0),
        (.processes[0].name // "none"),
        (.processes[0].pid // 0)
    ] | @tsv')"
    IFS=$'\t' read -r top_cpu top_name top_pid <<< "$process_values"

    result="$(classify "$top_cpu" "$PROCESS_CPU_WARNING" "$PROCESS_CPU_CRITICAL")"
    add_check "top_process" "Busiest single process" "$top_cpu" "% of one core" \
        "$PROCESS_CPU_WARNING" "$PROCESS_CPU_CRITICAL" "$result" \
        "Busiest process is ${top_name} (pid ${top_pid}) at ${top_cpu}% of one core"
else
    add_check "top_process" "Busiest single process" "" "" "" "" "FAIL" \
        "process.sh did not return usable data"
fi


# =============================================================================
#  STEP 4 -- JUDGE THE NETWORK MODULE
# =============================================================================
#
# Connectivity is not a number against a threshold, so it is judged by rule:
#   FAIL     nothing came back at all -- the gateway is unreachable
#   WARNING  it answered, but some packets were lost -- a degraded link
#   PASS     every packet came back
# -----------------------------------------------------------------------------
if [[ -n "$network_json" ]]; then
    network_values="$(printf '%s' "$network_json" | jq -r '[
        .connectivity.reachable,
        .connectivity.packet_loss_percent,
        .connectivity.target
    ] | @tsv')"
    IFS=$'\t' read -r net_reachable net_loss net_target <<< "$network_values"

    if [[ "$net_reachable" != "true" ]]; then
        result="FAIL"
        message="Gateway ${net_target} is unreachable (100% packet loss)"
    elif [[ "$net_loss" != "0" ]]; then
        result="WARNING"
        message="Gateway ${net_target} replied but lost ${net_loss}% of packets"
    else
        result="PASS"
        message="Gateway ${net_target} replied to every packet"
    fi
    # The thresholds are given as 1 and 100 so the dashboard can still draw a
    # bar: 1% loss is already a warning, 100% loss is total failure.
    add_check "network" "Gateway connectivity" "$net_loss" "% packet loss" 1 100 "$result" "$message"
else
    add_check "network" "Gateway connectivity" "" "" "" "" "FAIL" \
        "network.sh did not return usable data"
fi


# =============================================================================
#  STEP 5 -- JUDGE EVERY MONITORED SERVICE
# =============================================================================
#
# One check per service, and the list comes from services.sh's own output
# rather than from MONITORED_SERVICES directly, so the two can never disagree.
#
#   FAIL     not installed        -- you asked us to watch something absent
#   FAIL     active_state=failed  -- it stopped BECAUSE something went wrong
#   WARNING  installed, inactive  -- stopped cleanly, but it is not serving
#   PASS     active
# -----------------------------------------------------------------------------
if [[ -n "$services_json" ]]; then
    services_tsv="$(printf '%s' "$services_json" | jq -r '.services[] | [
        .name, .installed, .active_state, .running, .failed
    ] | @tsv')"

    # A here-string keeps the loop in the CURRENT shell. Piping into `while`
    # would run it in a subshell and every counter it updated would be lost.
    while IFS=$'\t' read -r svc_name svc_installed svc_state svc_running svc_failed; do
        if [[ -z "$svc_name" ]]; then
            continue
        fi
        if [[ "$svc_installed" != "true" ]]; then
            result="FAIL"
            message="Service ${svc_name} is not installed on this system"
        elif [[ "$svc_failed" == "true" ]]; then
            result="FAIL"
            message="Service ${svc_name} is in the failed state"
        elif [[ "$svc_running" != "true" ]]; then
            result="WARNING"
            message="Service ${svc_name} is installed but ${svc_state}"
        else
            result="PASS"
            message="Service ${svc_name} is active"
        fi
        # No numeric value or threshold applies to a service, so those three
        # fields are empty and become JSON null.
        add_check "service_${svc_name}" "Service: ${svc_name}" "" "" "" "" "$result" "$message"
    done <<< "$services_tsv"
else
    add_check "services" "Monitored services" "" "" "" "" "FAIL" \
        "services.sh did not return usable data"
fi


# =============================================================================
#  STEP 6 -- THE SCORE
# =============================================================================
#
#  THE FORMULA
#      score = 100 x (PASS_count + 0.5 x WARNING_count) / total_checks
#
#  WHY EVERY CHECK WEIGHS THE SAME
#  It is tempting to declare that "network down" should count three times as
#  much as "disk at 81%". But there is no measurement in this project that
#  justifies the number three, or any other number. Inventing weights would be
#  inventing precision the data does not contain, and every one of them would
#  have to be defended. Equal weighting is one sentence to defend and it cannot
#  be accused of hiding a bad result behind a small coefficient.
#
#  WHY A WARNING IS WORTH HALF
#  A warning means "still working, but heading the wrong way". Scoring it as a
#  pass would make the score blind to a disk filling up; scoring it as a
#  failure would make a single 81% disk look like a dead machine. Half is the
#  honest middle, and it makes the score move smoothly as the machine degrades
#  instead of jumping between 100 and 0.
#
#  WHY THE SCORE IS NOT THE WHOLE STORY
#  A score alone can hide a fatal problem: with eight checks, a completely dead
#  network still leaves a score of 87. So the score is published ALONGSIDE a
#  grade computed by a different, stricter rule:
#      FAIL     if ANY single check failed
#      WARNING  if any check warned
#      PASS     only if everything passed
#  The number is for the trend line on the dashboard; the grade is the verdict.
# -----------------------------------------------------------------------------
if (( checks_total > 0 )); then
    score="$(awk -v p="$checks_passed" -v w="$checks_warning" -v t="$checks_total" \
        'BEGIN { printf "%.0f", 100 * (p + 0.5 * w) / t }')"
else
    score=0
fi

if (( checks_failed > 0 )); then
    overall_grade="FAIL"
elif (( checks_warning > 0 )); then
    overall_grade="WARNING"
else
    overall_grade="PASS"
fi

if [[ -z "$checks_json" ]]; then
    checks_array="[]"
else
    checks_array="[$checks_json
  ]"
fi

timestamp_epoch="$(date +%s)"
timestamp_human="$(date '+%Y-%m-%d %H:%M:%S')"


# =============================================================================
#  OUTPUT
# =============================================================================
cat << EOF
{
  "module": "diagnosis",
  "status": "ok",
  "timestamp": $timestamp_epoch,
  "timestamp_human": "$timestamp_human",
  "score": $score,
  "grade": "$overall_grade",
  "summary": {
    "total": $checks_total,
    "passed": $checks_passed,
    "warning": $checks_warning,
    "failed": $checks_failed
  },
  "modules": {
    "system": "$(module_status "$system_json")",
    "network": "$(module_status "$network_json")",
    "process": "$(module_status "$process_json")",
    "services": "$(module_status "$services_json")"
  },
  "checks": $checks_array
}
EOF
