#!/bin/bash
# =============================================================================
#  Linux Guardian -- linux/guardian-daemon.sh        (Phase 4, extended Phase 7)
#
#  PURPOSE : Once every DAEMON_INTERVAL seconds, do two things:
#
#              1. COLLECT   take one metrics.sh sample and store it in the
#                           history database (Phase 7). This is what gives the
#                           project a memory, and therefore what makes "high
#                           FOR THIS MACHINE" a question it can answer.
#              2. HEAL      check DAEMON_SERVICE (apache2) and call healing.sh
#                           whenever it is not active. This is what makes the
#                           project SELF-healing rather than a dashboard with a
#                           button on it.
#
#  WHY ONE LOOP AND NOT A SECOND systemd TIMER FOR THE SAMPLING: this process is
#  already awake on exactly the right interval. A separate timer would be a
#  second unit to install and explain, a second thing that can be stopped
#  without anyone noticing, and -- the real problem -- a second schedule that
#  drifts, so a stored sample and a health check that look like the same moment
#  would not be one. One wake-up, one moment, one row.
#
#  THE ORDER WITHIN A TICK IS collect-then-heal, and it is deliberate: healing
#  can take seconds, and a sample taken afterwards would be a sample of the
#  machine AFTER the intervention. The history should record what the machine
#  looked like when the decision was made.
#
#  RUN BY  : systemd, via systemd/linux-guardian.service. It can also be run by
#            hand from a terminal for testing -- Ctrl-C stops it cleanly.
#
#  THIS SCRIPT DOES NOT OUTPUT JSON, and that is deliberate. Every other script
#  in linux/ is called by Flask, which parses its stdout. Nothing parses this
#  one: it is a long-running process whose output goes to the systemd journal
#  for a human to read. So it prints plain, timestamped, human-readable lines.
#
#  IT HAS NO PRIVILEGES OF ITS OWN. It does not call systemctl start; it calls
#  healing.sh, which re-applies PROTECTED_SERVICES and HEALABLE_SERVICES every
#  single time. Pointing DAEMON_SERVICE at ssh would not grant the daemon any
#  new power -- it would simply log a refusal every 30 seconds.
# =============================================================================


set -euo pipefail
set -E
export LC_ALL=C

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname -- "$SCRIPT_DIR")"

CONFIG_FILE="$PROJECT_ROOT/config/guardian.conf"
if [[ ! -r "$CONFIG_FILE" ]]; then
    # A daemon has no JSON contract to honour, so it reports failures the normal
    # way: a message on standard error and a non-zero exit status. systemd will
    # record both, and Restart=on-failure will keep trying.
    printf 'FATAL: config file not found or not readable: %s\n' "$CONFIG_FILE" >&2
    exit 1
fi

export GUARDIAN_ROOT="$PROJECT_ROOT"
# shellcheck source=../config/guardian.conf
source "$CONFIG_FILE"

DAEMON_INTERVAL="${DAEMON_INTERVAL:-30}"
DAEMON_SERVICE="${DAEMON_SERVICE:-apache2}"
LOG_FILE="${LOG_FILE:-$PROJECT_ROOT/logs/guardian.log}"
DAEMON_COLLECT="${DAEMON_COLLECT:-1}"
HISTORY_PRUNE_EVERY="${HISTORY_PRUNE_EVERY:-120}"

HEALING_SCRIPT="$SCRIPT_DIR/healing.sh"
[[ -x "$HEALING_SCRIPT" ]] || { printf 'FATAL: %s is missing or not executable\n' "$HEALING_SCRIPT" >&2; exit 1; }

# ---------------------------------------------------------------------------
# The history store, and the ONE thing that is different about it: a missing or
# broken store is NOT fatal, while a missing healing.sh is.
#
# That asymmetry is the whole safety argument for adding collection to this
# loop. Healing is the daemon's duty; history is a convenience it performs on
# the way past. If Python is absent, or guardian_store.py has been deleted, or
# the disk holding the database is full, the daemon must still be watching
# apache2 thirty seconds from now. So collection is switched OFF at startup with
# one logged line, and the loop carries on.
# ---------------------------------------------------------------------------
STORE_SCRIPT="$PROJECT_ROOT/guardian_store.py"
collect_disabled_reason=""

if (( DAEMON_COLLECT == 0 )); then
    collect_disabled_reason="DAEMON_COLLECT=0 in guardian.conf"
elif [[ ! -r "$STORE_SCRIPT" ]]; then
    collect_disabled_reason="$STORE_SCRIPT not found"
elif ! command -v python3 > /dev/null 2>&1; then
    # command -v is the POSIX shell builtin that looks a command up in $PATH.
    # CHOSEN OVER `which`, a separate program that is not installed everywhere
    # and whose exit status is unreliable. Same test diagnosis.sh uses for jq.
    collect_disabled_reason="python3 is not installed"
fi

mkdir -p -- "$(dirname -- "$LOG_FILE")"


# -----------------------------------------------------------------------------
# say <level> <message>
#
# Writes to BOTH destinations, on purpose:
#   stdout    -> captured by systemd and readable with `journalctl -u
#                linux-guardian`, which is where a Linux administrator looks
#                first and which handles rotation automatically.
#   $LOG_FILE -> the project's own audit trail, the same file healing.sh writes
#                to, so the whole story of an incident is in one place and the
#                Flask app can display it in Phase 5.
#
# printf is used rather than echo because its output format is fixed and
# documented; echo's handling of backslashes varies between implementations.
# -----------------------------------------------------------------------------
say() {
    local level="$1" message="$2" line
    line="$(date '+%F %T') [$level] guardian-daemon: $message"
    printf '%s\n' "$line"
    printf '%s\n' "$line" >> "$LOG_FILE"
}


# =============================================================================
#  SHUTTING DOWN CLEANLY
# =============================================================================
#
# `systemctl stop` sends SIGTERM and then waits. If the daemon ignores it,
# systemd waits TimeoutStopSec and finally SIGKILLs it -- which looks like a
# crash in the journal and leaves no closing log line.
#
# THE BASH TRAP THAT CATCHES EVERYONE: a trap does NOT interrupt a foreground
# child process. With a plain `sleep 30`, Bash finishes waiting for sleep before
# it will even look at the signal, so `systemctl stop` appears to hang for up to
# 30 seconds.
#
# THE FIX, used in the main loop below: start sleep in the BACKGROUND and use
# the `wait` builtin. `wait` is interruptible -- a signal makes it return
# immediately -- so the trap runs at once and the daemon exits in milliseconds.
#
#   trap ... TERM   SIGTERM: what systemctl stop sends
#   trap ... INT    SIGINT: what Ctrl-C sends, so manual testing behaves the same
# -----------------------------------------------------------------------------
keep_running=1
sleep_pid=""

# shellcheck disable=SC2317,SC2329
# TWO warning codes are suppressed here, and both are the SAME false positive
# seen by two different versions of shellcheck:
#
#   SC2317  "Command appears to be unreachable"  -- shellcheck <= 0.10, which
#           pointed at the LINES INSIDE the function.
#   SC2329  "This function is never invoked"     -- shellcheck 0.11.0 split that
#           check in two and points at the DEFINITION instead.
#
# Both are wrong for the same reason, and the reason is worth understanding
# rather than just silencing: shellcheck follows the written flow of the script
# and never sees on_terminate being called, because the only thing that calls it
# is the KERNEL delivering a signal to the `trap` on the line below. No line of
# text in this file invokes it, so a purely textual analysis concludes it is
# dead code. It is not -- it is the shutdown path.
#
# A detail worth knowing, because it looks like magic otherwise: on 0.11.0 the
# warning is triggered by the `exit 0` on the LAST line of this script. Without
# an explicit exit, shellcheck's control-flow graph lets the script run off the
# end and it still models the handler as reachable; the explicit exit becomes
# the terminal node and that edge disappears. Verify it in six lines (the `$ `
# prompts are deliberate -- a comment whose first word is "shellcheck" is itself
# parsed as a directive, which is a trap this very comment block fell into):
#     $ printf '#!/bin/bash\nk=1\nf() { k=0; }\ntrap f TERM INT\n' > t.sh
#     $ printf 'while (( k )); do sleep 1; done\n'                >> t.sh
#     $ shellcheck t.sh          # silent
#     $ printf 'exit 0\n'                                         >> t.sh
#     $ shellcheck t.sh          # SC2329
#
# BOTH codes are named so the script lints clean whichever shellcheck version is
# installed on the marking machine. The suppression is scoped to this one
# function, so genuinely dead code anywhere else in the file is still reported.
on_terminate() {
    keep_running=0
    if [[ -n "$sleep_pid" ]]; then
        # || true: by the time the signal arrives the sleep may already have
        # finished, and killing a process that no longer exists is not an error
        # worth dying over.
        kill "$sleep_pid" 2> /dev/null || true
    fi
}
trap on_terminate TERM INT


# -----------------------------------------------------------------------------
# Read a unit's current state. No privileges required -- `systemctl show`
# always exits 0, even for a unit that does not exist, which is exactly why it
# is used here instead of `is-active` (see services.sh for the full argument).
# -----------------------------------------------------------------------------
current_state() {
    systemctl show "$1" --property=ActiveState --value 2> /dev/null || printf 'unknown'
}

unit_name="$DAEMON_SERVICE"
if [[ "$unit_name" != *.* ]]; then
    unit_name="$unit_name.service"
fi


# =============================================================================
#  COLLECTION  (Phase 7)
# =============================================================================
#
# collect_sample -- take one reading and store it. Returns 0 on success.
#
# THE COMMAND IS AN ARGUMENT LIST WITH NO USER INPUT IN IT: python3, a path
# derived from this script's own location, and one fixed literal word. There is
# no string being assembled and nothing here that a value could be injected
# into, which is the project's architectural rule applied even where there is
# currently nothing to protect against.
#
# `observe` makes guardian_store.py do the whole tick itself -- sample, store,
# detect anomalies, raise or update incidents -- rather than this script running
# three programs and piping JSON between them. One process instead of three, one
# place where the sequence is written down, and the JSON never has to survive a
# shell pipeline on its way between the stages.
#
# ITS FAILURE BEHAVIOUR IS THE POINT OF PUTTING IT THERE: `observe` stores the
# sample FIRST and unconditionally, then attempts detection. If the detector or
# the incident engine breaks, the reading is still safely in the history and the
# next tick tries again. A failure to interpret data must never cost the data.
#
# 2>&1 folds stderr into the captured output. A Python traceback is not JSON, so
# without this it would go straight to the journal UNLABELLED, interleaved with
# the daemon's own lines and attributable to nothing.
# -----------------------------------------------------------------------------
collect_output=""
collect_sample() {
    local exit_code=0
    collect_output="$(python3 "$STORE_SCRIPT" observe 2>&1)" || exit_code=$?
    return "$exit_code"
}

# prune_history -- apply the retention policy. Failure is logged, never fatal.
prune_output=""
prune_history() {
    local exit_code=0
    prune_output="$(python3 "$STORE_SCRIPT" prune 2>&1)" || exit_code=$?
    return "$exit_code"
}


# =============================================================================
#  THE WATCH LOOP
# =============================================================================
say "INFO" "started -- watching $unit_name every ${DAEMON_INTERVAL}s (pid $$)"

if [[ -n "$collect_disabled_reason" ]]; then
    say "WARN" "history collection is OFF: $collect_disabled_reason -- healing continues"
else
    say "INFO" "history collection is ON, pruning every $HISTORY_PRUNE_EVERY ticks"
fi

# previous_state exists to keep the log readable. Without it the daemon would
# write two lines a minute for ever -- about 2,900 lines a day of "still fine" --
# and the one line that matters would be impossible to find. So the loop stays
# SILENT while nothing changes, and speaks only on a transition or an action.
previous_state=""
heal_attempts=0
heal_successes=0

# THE SAME "only speak on a transition" RULE APPLIES TO COLLECTION, and it
# matters more here. A database that has become unwritable would otherwise log a
# failure every thirty seconds -- 2,880 identical lines a day, filling the very
# disk whose exhaustion caused the failure. So the daemon logs the FIRST failure
# and then the recovery, and says nothing in between.
tick=0
samples_stored=0
collect_failing=0

while (( keep_running )); do

    tick=$(( tick + 1 ))

    # --- 1. COLLECT ---------------------------------------------------------
    if [[ -z "$collect_disabled_reason" ]]; then
        if collect_sample; then
            samples_stored=$(( samples_stored + 1 ))
            if (( collect_failing )); then
                say "INFO" "history collection recovered"
                collect_failing=0
            fi

            # AN INCIDENT OPENING OR CLOSING IS NEWS, and news is the only thing
            # this loop is allowed to print. `observe` pre-formats it into a
            # single "headline" field precisely so that this line can be one
            # sed rather than a JSON parser the daemon must not depend on.
            #
            #   sed -n            print nothing unless told to
            #   s/.../\1/p        substitute, then print only lines that matched
            #   "[^"]*"           the field's value: everything up to the next
            #                     double quote. Safe here because the headline
            #                     is built from an incident title and two
            #                     severity words, none of which can contain one.
            #
            # When nothing happened the field is JSON null -- unquoted -- so the
            # pattern does not match, headline is empty, and the daemon stays
            # silent. A quiet machine writes no lines at all.
            headline="$(printf '%s' "$collect_output" | sed -n 's/.*"headline": "\([^"]*\)".*/\1/p')"
            if [[ -n "$headline" ]]; then
                say "WARN" "$headline"
            fi
        elif (( ! collect_failing )); then
            # guardian_store.py honours the project's JSON contract, so its
            # refusal message is already a sentence explaining itself. `tr` folds
            # the pretty-printed object onto one line, because a multi-line
            # record in a line-oriented log file cannot be grepped.
            #   tr -d '\n'  delete every newline
            #   tr -s ' '   SQUEEZE runs of spaces down to one, which is what
            #               removes the pretty-printer's indentation once the
            #               newlines in front of it are gone.
            # CHOSEN OVER `jq -c`: that would make this daemon's logging depend
            # on jq, and the daemon must keep running on a machine where jq was
            # never installed. tr is in coreutils and is always present.
            say "ERROR" "history collection failed: $(printf '%s' "$collect_output" | tr -d '\n' | tr -s ' ')"
            collect_failing=1
        fi

        # Retention, on its own much slower schedule. $(( a % b )) is Bash
        # arithmetic remainder: true once every HISTORY_PRUNE_EVERY ticks.
        if (( HISTORY_PRUNE_EVERY > 0 && tick % HISTORY_PRUNE_EVERY == 0 )); then
            if prune_history; then
                say "INFO" "retention run: $(printf '%s' "$prune_output" | tr -d '\n' | tr -s ' ')"
            else
                say "ERROR" "retention failed: $(printf '%s' "$prune_output" | tr -d '\n' | tr -s ' ')"
            fi
        fi
    fi

    # --- 2. HEAL ------------------------------------------------------------
    state="$(current_state "$unit_name")"

    if [[ "$state" == "active" ]]; then
        # Only worth a line if it is NEWS -- i.e. it was not active last time.
        if [[ -n "$previous_state" && "$previous_state" != "active" ]]; then
            say "INFO" "$unit_name is active again"
        fi
    else
        say "WARN" "$unit_name is $state -- calling healing.sh"
        heal_attempts=$(( heal_attempts + 1 ))

        # healing.sh exits non-zero when it refuses or when recovery failed.
        # That must NOT kill the daemon: the whole point of a watchdog is to
        # still be running for the next attempt. So its exit status is captured
        # deliberately instead of being left to `set -e`.
        #
        # Its JSON goes to the journal as one line. The daemon does not parse it
        # -- healing.sh has already written the human-readable summary to
        # guardian.log -- but keeping the raw record makes an incident
        # reconstructable afterwards.
        heal_exit=0
        heal_output="$("$HEALING_SCRIPT" "$DAEMON_SERVICE" 2>&1)" || heal_exit=$?

        if (( heal_exit == 0 )); then
            heal_successes=$(( heal_successes + 1 ))
            say "INFO" "healing.sh succeeded for $DAEMON_SERVICE"
        else
            say "ERROR" "healing.sh failed for $DAEMON_SERVICE (exit $heal_exit)"
        fi
        printf '%s\n' "$heal_output"
    fi

    previous_state="$state"

    # A signal may have arrived while healing was in progress. Checking here
    # means we do not start a fresh 30-second sleep just to be interrupted.
    if (( ! keep_running )); then
        break
    fi

    # THE INTERRUPTIBLE SLEEP (see the long comment above).
    #   &        run sleep in the background
    #   $!       the process id of that background job
    #   wait     block until it finishes -- but return immediately on a signal
    #   || true  `wait` returns non-zero when a signal interrupts it, and that
    #            is the normal shutdown path here, not an error.
    sleep "$DAEMON_INTERVAL" &
    sleep_pid=$!
    wait "$sleep_pid" 2> /dev/null || true
    sleep_pid=""
done

say "INFO" "stopped cleanly after $tick tick(s): $samples_stored sample(s) stored, $heal_attempts healing attempt(s), $heal_successes successful"
exit 0
