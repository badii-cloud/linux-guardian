#!/bin/bash
# =============================================================================
#  Linux Guardian -- linux/schedule.sh                             (Phase 6)
#
#  PURPOSE : Create, list and cancel repeating schedules, using SYSTEMD USER
#            TIMERS. Each schedule is a pair of generated unit files:
#
#              ~/.config/systemd/user/guardian-<name>.timer     WHEN it runs
#              ~/.config/systemd/user/guardian-<name>.service   WHAT it runs
#
#  USAGE   : ./schedule.sh create <name> <Day> <HH:MM>
#            ./schedule.sh list
#            ./schedule.sh cancel <name>
#
#  WHY A USER TIMER AND NOT root cron
#    A user timer needs NO sudo at all. It runs as this user, is managed with
#    `systemctl --user`, and can only ever touch files this user could already
#    touch. Writing to root's crontab would mean a web page could schedule work
#    as root -- exactly the privilege escalation the whole project is built to
#    prevent. It is also consistent: Phase 4 already uses systemd, so there is
#    one scheduling mechanism in the report instead of two.
#
#  WHY A TIMER AND NOT `sleep` IN A LOOP
#    systemd owns the schedule, so it survives this script exiting, a logout
#    and (with Persistent=true) a reboot. It also gives `systemctl --user
#    list-timers`, which shows exactly when each job will next fire -- something
#    a hand-written loop cannot answer.
#
#  A LIMITATION WORTH KNOWING BEFORE THE DEMO
#    User timers run only while the user has a session, unless lingering is
#    enabled (`sudo loginctl enable-linger kali`). On this VM you are logged in
#    at the desktop, so they run. Lingering is NOT enabled here because it needs
#    root and is not required for the demonstration.
# =============================================================================


set -euo pipefail
set -E
export LC_ALL=C

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname -- "$SCRIPT_DIR")"

MODULE="schedule"

emit_error() {
    printf '{"module":"%s","status":"error","message":"%s"}\n' "$MODULE" "$1"
    exit 1
}
trap 'emit_error "schedule.sh failed at line $LINENO"' ERR


# -----------------------------------------------------------------------------
# Configuration.
# -----------------------------------------------------------------------------
CONFIG_FILE="$PROJECT_ROOT/config/guardian.conf"
[[ -r "$CONFIG_FILE" ]] || emit_error "config file not found or not readable: $CONFIG_FILE"

export GUARDIAN_ROOT="$PROJECT_ROOT"
# shellcheck source=../config/guardian.conf
source "$CONFIG_FILE"

SYSTEMD_USER_DIR="${SYSTEMD_USER_DIR:-$HOME/.config/systemd/user}"
TIMER_PREFIX="${TIMER_PREFIX:-guardian-}"
LOG_FILE="${LOG_FILE:-$PROJECT_ROOT/logs/guardian.log}"
WORKER="$SCRIPT_DIR/workspace.sh"

command -v jq > /dev/null 2>&1 || emit_error "jq not found: install it with 'sudo apt install -y jq'"
command -v systemctl > /dev/null 2>&1 || emit_error "systemctl not found: this module requires systemd"
[[ -x "$WORKER" ]] || emit_error "workspace.sh is missing or not executable: $WORKER"

json_string() {
    printf '%s' "${1-}" | jq -Rs .
}

mkdir -p -- "$(dirname -- "$LOG_FILE")"

log_line() {
    local level="$1" message="$2"
    printf '%s [%s] schedule.sh: %s\n' "$(date '+%F %T')" "$level" "$message" >> "$LOG_FILE"
}


# -----------------------------------------------------------------------------
# IS THERE A USER SYSTEMD INSTANCE TO TALK TO?
#
# `systemctl --user` needs two things in the environment: XDG_RUNTIME_DIR and a
# session bus. A process started from a graphical login has both. One started
# from a bare cron job or an ssh session without lingering does NOT, and every
# systemctl call would fail with "Failed to connect to bus", which is a
# confusing thing to show a user.
#
# show-environment is a harmless read-only query, so it is a cheap way to ask
# "can I reach the user manager at all?" before doing anything else.
# -----------------------------------------------------------------------------
user_systemd_available() {
    systemctl --user show-environment > /dev/null 2>&1
}


# -----------------------------------------------------------------------------
# THE THREE VALIDATION RULES, REPEATED IN BASH.
#
# guardian_actions.py already applied exactly these. They are here as well
# because this script is executable on its own, and a script that is only safe
# when its caller behaves is not a safe script.
# -----------------------------------------------------------------------------
NAME_PATTERN='^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,39}$'
DAY_PATTERN='^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)$'
TIME_PATTERN='^([01][0-9]|2[0-3]):[0-5][0-9]$'

require_valid_name() {
    if [[ ! "${1-}" =~ $NAME_PATTERN ]]; then
        log_line "REFUSED" "rejected name: ${1-}"
        emit_error "invalid name: 1-40 characters of letters, digits, underscore or hyphen, not starting with a hyphen"
    fi
}


# -----------------------------------------------------------------------------
# WHERE A UNIT FILE FOR THIS NAME LIVES -- and proof it cannot be anywhere else.
#
# Every unit this project writes is called guardian-<name>.timer/.service. The
# prefix is what makes `list` and `cancel` safe: they only ever consider files
# that start with it, so a unit a human wrote by hand can never be listed as
# ours and can never be deleted by us.
# -----------------------------------------------------------------------------
unit_path() {
    local name="$1" suffix="$2" path real_path real_dir

    mkdir -p -- "$SYSTEMD_USER_DIR"
    real_dir="$(realpath -- "$SYSTEMD_USER_DIR")"

    path="$real_dir/${TIMER_PREFIX}${name}.${suffix}"
    real_path="$(realpath -m -- "$path")"

    if [[ "$(dirname -- "$real_path")" != "$real_dir" ]]; then
        log_line "REFUSED" "unit path escaped $real_dir: $name"
        emit_error "refusing to write a unit outside $real_dir"
    fi

    printf '%s' "$real_path"
}


# =============================================================================
#  ARGUMENTS
# =============================================================================
ACTION="${1-}"
[[ -n "$ACTION" ]] || emit_error "usage: schedule.sh create <name> <Day> <HH:MM> | list | cancel <name>"


case "$ACTION" in

# =============================================================================
#  CREATE
# =============================================================================
create)
    NAME="${2-}"
    DAY="${3-}"
    TIME="${4-}"

    require_valid_name "$NAME"

    [[ "$DAY" =~ $DAY_PATTERN ]] || {
        log_line "REFUSED" "rejected day: $DAY"
        emit_error "invalid day: expected one of Mon Tue Wed Thu Fri Sat Sun"
    }
    [[ "$TIME" =~ $TIME_PATTERN ]] || {
        log_line "REFUSED" "rejected time: $TIME"
        emit_error "invalid time: expected 24-hour HH:MM between 00:00 and 23:59"
    }

    user_systemd_available || emit_error "no systemd user session is reachable (XDG_RUNTIME_DIR / DBUS_SESSION_BUS_ADDRESS not set)"

    # -------------------------------------------------------------------------
    # THE OnCalendar EXPRESSION -- this is the heart of the whole feature.
    #
    # Full systemd calendar syntax is:
    #
    #     DayOfWeek Year-Month-Day Hour:Minute:Second
    #
    # Every field may be omitted, and an omitted field means "every one of
    # these". We build exactly:
    #
    #     OnCalendar=Thu 12:00
    #      |          |    |
    #      |          |    +-- Hour:Minute. Seconds are omitted and default to
    #      |          |        :00, so this is 12:00:00 exactly.
    #      |          +------- Day of week. Mon Tue Wed Thu Fri Sat Sun.
    #      +------------------ the date is MISSING entirely, which is what makes
    #                          this repeat: with no Year-Month-Day the rule
    #                          matches EVERY date whose weekday is Thu.
    #
    # So "Thu 12:00" reads as: every Thursday, at twelve noon, for ever.
    #
    # Other forms systemd accepts, for the report:
    #     OnCalendar=Mon..Fri 09:00     a RANGE of weekdays
    #     OnCalendar=Mon,Thu 09:00      a LIST of weekdays
    #     OnCalendar=*-*-01 00:00       the first of every month
    #     OnCalendar=hourly             a named shorthand
    #
    # WHY NOT OnUnitActiveSec: that measures time since the unit last ran, so
    # it drifts and cannot express "Thursday". OnCalendar is wall-clock, which
    # is what "every Thursday at 12:00" actually means.
    # -------------------------------------------------------------------------
    ON_CALENDAR="$DAY $TIME"

    # ASK SYSTEMD ITSELF whether the expression is valid, before writing any
    # file. systemd-analyze parses it with the very same code the timer will
    # use and prints the next times it would fire. Validating with the real
    # parser instead of trusting our own regex is the difference between "we
    # think this is right" and "systemd agrees this is right".
    if ! NEXT_ELAPSE="$(systemd-analyze calendar "$ON_CALENDAR" 2> /dev/null | grep -m1 'Next elapse:' | sed 's/^ *Next elapse: *//')"; then
        emit_error "systemd rejected the calendar expression: $ON_CALENDAR"
    fi
    [[ -n "$NEXT_ELAPSE" ]] || emit_error "systemd could not compute a next run for: $ON_CALENDAR"

    TIMER_FILE="$(unit_path "$NAME" timer)"
    SERVICE_FILE="$(unit_path "$NAME" service)"
    TIMER_UNIT="${TIMER_PREFIX}${NAME}.timer"

    log_line "ACTION" "$NAME -- creating timer for $ON_CALENDAR"

    # -------------------------------------------------------------------------
    # THE SERVICE UNIT -- WHAT runs.
    #
    #   Type=oneshot   the command runs, finishes, and the unit is done. The
    #                  default (Type=simple) is for long-running daemons and
    #                  would make systemd think the job failed the moment the
    #                  script exited.
    #   ExecStart      an ABSOLUTE path, because a unit has no PATH to speak of
    #                  and no working directory to be relative to. The two
    #                  arguments after it are separate words, so the name is a
    #                  single argv entry no matter what is in it -- there is no
    #                  shell here to split or interpret anything.
    #
    # A quoted heredoc ('UNIT') is used so that $ inside the block is written
    # literally rather than expanded by THIS shell. The only values that get
    # substituted are the ones we explicitly interpolate.
    # -------------------------------------------------------------------------
    cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=Linux Guardian scheduled write for '$NAME'
Documentation=file://$PROJECT_ROOT/README.md

[Service]
Type=oneshot
ExecStart=$WORKER tick $NAME
UNIT

    # -------------------------------------------------------------------------
    # THE TIMER UNIT -- WHEN it runs.
    #
    #   OnCalendar     the schedule, explained above.
    #   Persistent=true   if the machine was switched off when the timer should
    #                  have fired, run it once as soon as it comes back.
    #                  Essential on a VM that is suspended between lectures --
    #                  without it a missed Thursday is simply lost.
    #   Unit=          which service to start. This is actually the DEFAULT
    #                  (systemd pairs guardian-x.timer with guardian-x.service
    #                  automatically), but it is written out so the connection
    #                  between the two files is visible rather than implied.
    #   WantedBy=timers.target   what `systemctl --user enable` hooks this into,
    #                  so the timer comes back by itself at every login.
    # -------------------------------------------------------------------------
    cat > "$TIMER_FILE" <<UNIT
[Unit]
Description=Linux Guardian schedule for '$NAME' ($ON_CALENDAR)

[Timer]
OnCalendar=$ON_CALENDAR
Persistent=true
Unit=${TIMER_PREFIX}${NAME}.service

[Install]
WantedBy=timers.target
UNIT

    # daemon-reload makes systemd re-read the unit directory. Without it the
    # files exist on disk but systemd has never heard of them, and `enable`
    # would fail with "unit not found".
    systemctl --user daemon-reload

    # enable  create the symlink into timers.target.wants, so it survives logout
    # --now   AND start it immediately, instead of waiting for the next login
    systemctl --user enable --now "$TIMER_UNIT" > /dev/null 2>&1 \
        || emit_error "systemctl --user enable --now $TIMER_UNIT failed"

    ACTIVE_STATE="$(systemctl --user show "$TIMER_UNIT" --property=ActiveState --value)"

    MESSAGE="scheduled $NAME.txt for $ON_CALENDAR"
    log_line "SUCCESS" "$NAME -- $MESSAGE (next: $NEXT_ELAPSE)"

    printf '{'
    printf '"module":%s,'        "$(json_string "$MODULE")"
    printf '"status":"ok",'
    printf '"action":"create",'
    printf '"name":%s,'          "$(json_string "$NAME")"
    printf '"day":%s,'           "$(json_string "$DAY")"
    printf '"time":%s,'          "$(json_string "$TIME")"
    printf '"on_calendar":%s,'   "$(json_string "$ON_CALENDAR")"
    printf '"timer_unit":%s,'    "$(json_string "$TIMER_UNIT")"
    printf '"timer_file":%s,'    "$(json_string "$TIMER_FILE")"
    printf '"service_file":%s,'  "$(json_string "$SERVICE_FILE")"
    printf '"active_state":%s,'  "$(json_string "$ACTIVE_STATE")"
    printf '"next_run":%s,'      "$(json_string "$NEXT_ELAPSE")"
    printf '"message":%s'        "$(json_string "$MESSAGE")"
    printf '}\n'
    ;;


# =============================================================================
#  LIST
# =============================================================================
list)
    user_systemd_available || emit_error "no systemd user session is reachable"

    mkdir -p -- "$SYSTEMD_USER_DIR"

    # nullglob: when a glob matches NOTHING, expand it to nothing at all.
    # Without it, Bash leaves the pattern as a literal string and the loop runs
    # once with a filename that does not exist -- the single commonest bug in
    # shell scripts that iterate over files.
    shopt -s nullglob

    ROWS=""
    COUNT=0

    for TIMER_FILE in "$SYSTEMD_USER_DIR/${TIMER_PREFIX}"*.timer; do
        BASE="$(basename -- "$TIMER_FILE")"          # guardian-notes.timer
        UNIT_NAME="$BASE"
        NAME="${BASE#"$TIMER_PREFIX"}"               # strip the prefix
        NAME="${NAME%.timer}"                        # strip the suffix

        # Read the schedule back out of the file we wrote, rather than
        # remembering it somewhere else. The unit file is the single source of
        # truth for what was scheduled.
        ON_CALENDAR="$(sed -n 's/^OnCalendar=//p' "$TIMER_FILE" | head -1)"

        # systemctl show is used rather than is-active for the same reason as
        # services.sh: it exits 0 even for a unit systemd has never heard of,
        # so a missing unit is an empty value instead of a failed script.
        ACTIVE_STATE="$(systemctl --user show "$UNIT_NAME" --property=ActiveState --value 2> /dev/null || printf 'unknown')"
        NEXT_RUN="$(systemctl --user show "$UNIT_NAME" --property=NextElapseUSecRealtime --value 2> /dev/null || printf '')"

        [[ $COUNT -gt 0 ]] && ROWS+=","
        ROWS+="{"
        ROWS+="\"name\":$(json_string "$NAME"),"
        ROWS+="\"unit\":$(json_string "$UNIT_NAME"),"
        ROWS+="\"on_calendar\":$(json_string "$ON_CALENDAR"),"
        ROWS+="\"active_state\":$(json_string "$ACTIVE_STATE"),"
        ROWS+="\"next_run\":$(json_string "$NEXT_RUN")"
        ROWS+="}"
        COUNT=$(( COUNT + 1 ))
    done

    printf '{'
    printf '"module":%s,'  "$(json_string "$MODULE")"
    printf '"status":"ok",'
    printf '"action":"list",'
    printf '"count":%s,'   "$COUNT"
    printf '"schedules":[%s],' "$ROWS"
    printf '"message":%s'  "$(json_string "$COUNT schedule(s)")"
    printf '}\n'
    ;;


# =============================================================================
#  CANCEL
# =============================================================================
cancel)
    NAME="${2-}"
    require_valid_name "$NAME"

    user_systemd_available || emit_error "no systemd user session is reachable"

    TIMER_FILE="$(unit_path "$NAME" timer)"
    SERVICE_FILE="$(unit_path "$NAME" service)"
    TIMER_UNIT="${TIMER_PREFIX}${NAME}.timer"

    # Refusing on a schedule that does not exist is more useful than silently
    # succeeding: it tells the user their name was wrong instead of letting
    # them believe something was cancelled.
    [[ -f "$TIMER_FILE" ]] || {
        log_line "REFUSED" "no such schedule: $NAME"
        emit_error "no schedule called '$NAME' exists"
    }

    log_line "ACTION" "$NAME -- cancelling $TIMER_UNIT"

    # disable  remove the symlink, so it does not come back at next login
    # --now    AND stop it immediately
    # || true  a unit that is already stopped is not an error worth dying over;
    #          the files still have to be removed either way
    systemctl --user disable --now "$TIMER_UNIT" > /dev/null 2>&1 || true

    # rm -f: do not complain if a file is already gone. Both paths came from
    # unit_path(), so both are proven to be inside SYSTEMD_USER_DIR and to
    # carry our prefix -- this cannot remove a unit a human wrote.
    rm -f -- "$TIMER_FILE" "$SERVICE_FILE"

    systemctl --user daemon-reload

    MESSAGE="cancelled the schedule for $NAME"
    log_line "SUCCESS" "$NAME -- $MESSAGE"

    printf '{'
    printf '"module":%s,'       "$(json_string "$MODULE")"
    printf '"status":"ok",'
    printf '"action":"cancel",'
    printf '"name":%s,'         "$(json_string "$NAME")"
    printf '"timer_unit":%s,'   "$(json_string "$TIMER_UNIT")"
    printf '"message":%s'       "$(json_string "$MESSAGE")"
    printf '}\n'
    ;;

*)
    emit_error "unknown action: $ACTION (expected create, list or cancel)"
    ;;
esac
