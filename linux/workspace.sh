#!/bin/bash
# =============================================================================
#  Linux Guardian -- linux/workspace.sh                            (Phase 6)
#
#  PURPOSE : Write a text file, and ONLY ever inside the sandbox directory
#            $WORKSPACE_DIR. This is the first script in the project that
#            creates a file, so like healing.sh in Phase 3, most of it is about
#            what it refuses to do.
#
#  USAGE   : ./workspace.sh create <name> [content]
#            ./workspace.sh tick   <name>
#
#            create  write the file, replacing it if it is already there
#            tick    append one timestamped line. This is the action a systemd
#                    timer calls -- see schedule.sh. It is deliberately NOT in
#                    actions.json, because nothing a user types should reach it;
#                    only a unit file this project generated calls it.
#
#  WHY THE VALIDATION IS REPEATED HERE
#    guardian_actions.py has already checked the name against exactly the same
#    rule before this script was called. Checking again is not distrust of that
#    code, it is the recognition that THIS FILE IS EXECUTABLE ON ITS OWN. A
#    marker will run it straight from a terminal, and a future phase might call
#    it from somewhere that forgot. A script that is only safe when its caller
#    behaves is not a safe script.
#
#  THE SANDBOX RULE
#    name -> $WORKSPACE_DIR/<name>.txt, and the REAL resolved path must still
#    be directly inside $WORKSPACE_DIR. The name pattern already forbids '/'
#    and '.', so in principle it cannot escape; realpath is asked anyway,
#    because a regex reasons about text and realpath reasons about where the
#    filesystem would really put the file. A symlink planted in the workspace
#    is a case where only the second answer is correct.
# =============================================================================


set -euo pipefail
set -E
export LC_ALL=C

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname -- "$SCRIPT_DIR")"

MODULE="workspace"

# -----------------------------------------------------------------------------
# THE FAILURE CONTRACT (project rule 7).
# stdout must be one valid JSON object even when the script dies, because Flask
# hands stdout straight to json.loads(). An error that printed nothing would
# surface in the browser as "did not return valid JSON" instead of the real
# reason.
# -----------------------------------------------------------------------------
emit_error() {
    printf '{"module":"%s","status":"error","message":"%s"}\n' "$MODULE" "$1"
    exit 1
}
trap 'emit_error "workspace.sh failed at line $LINENO"' ERR


# -----------------------------------------------------------------------------
# Load the configuration.
# -----------------------------------------------------------------------------
CONFIG_FILE="$PROJECT_ROOT/config/guardian.conf"
[[ -r "$CONFIG_FILE" ]] || emit_error "config file not found or not readable: $CONFIG_FILE"

export GUARDIAN_ROOT="$PROJECT_ROOT"
# shellcheck source=../config/guardian.conf
source "$CONFIG_FILE"

WORKSPACE_DIR="${WORKSPACE_DIR:-$PROJECT_ROOT/workspace}"
WORKSPACE_MAX_BYTES="${WORKSPACE_MAX_BYTES:-65536}"
LOG_FILE="${LOG_FILE:-$PROJECT_ROOT/logs/guardian.log}"


# -----------------------------------------------------------------------------
# JSON ENCODING -- done with jq, not by hand.
#
# healing.sh escapes strings itself, which is fine there: a systemd unit name
# can only contain a handful of characters. Here the value is FILE CONTENT the
# user typed, so it can contain quotes, backslashes, tabs and newlines. A
# hand-rolled escaper that forgets newlines emits a JSON string with a real
# line break inside it, which is invalid JSON and would break the console.
#
#   jq -R   read the input as a RAW string instead of parsing it as JSON
#   jq -s   SLURP: treat the whole input as one value, not one per line
#   .       print it back -- now correctly quoted and escaped
#
# jq is already a hard dependency of this project (diagnosis.sh refuses to run
# without it), so this adds nothing new to install.
# -----------------------------------------------------------------------------
command -v jq > /dev/null 2>&1 || emit_error "jq not found: install it with 'sudo apt install -y jq'"

json_string() {
    printf '%s' "${1-}" | jq -Rs .
}


# -----------------------------------------------------------------------------
# THE AUDIT TRAIL. Same file and same format as Phase 3, so one log still tells
# the whole story of what this machine was asked to do.
# -----------------------------------------------------------------------------
mkdir -p -- "$(dirname -- "$LOG_FILE")"

log_line() {
    local level="$1" message="$2"
    printf '%s [%s] workspace.sh: %s\n' "$(date '+%F %T')" "$level" "$message" >> "$LOG_FILE"
}


# -----------------------------------------------------------------------------
# THE NAME RULE, written out again in Bash.
#
#   ^[a-zA-Z0-9_]          the FIRST character: a letter, digit or underscore.
#                          The hyphen is excluded HERE and only here, so a name
#                          can never be "-rf". A value starting with a hyphen is
#                          not a filename to most Unix commands, it is a FLAG.
#   [a-zA-Z0-9_-]{0,39}$   the rest: hyphen now allowed, up to 39 more, so 40
#                          characters in total.
#
# There is no '.' and no '/' anywhere in the pattern, which is what stops
# "../etc/passwd" and "notes/../../x", and also stops the user choosing an
# extension -- ".txt" is added below by this script, so a .service or .sh file
# can never be written.
#
# =~ is Bash's regular-expression match. The pattern is stored in a VARIABLE
# and used unquoted, because a quoted right-hand side is treated as a literal
# string by Bash rather than as a pattern -- a classic and silent mistake.
# -----------------------------------------------------------------------------
NAME_PATTERN='^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,39}$'

require_valid_name() {
    local candidate="$1"
    if [[ ! "$candidate" =~ $NAME_PATTERN ]]; then
        log_line "REFUSED" "rejected name: $candidate"
        emit_error "invalid name: 1-40 characters of letters, digits, underscore or hyphen, not starting with a hyphen"
    fi
}


# -----------------------------------------------------------------------------
# RESOLVE A NAME TO AN ABSOLUTE PATH, AND PROVE IT IS STILL IN THE SANDBOX.
#
#   mkdir -p     create the workspace if this is the first run. -p also means
#                "do not fail if it already exists", so a second run is fine.
#   realpath     print the canonical absolute path: every symbolic link
#                followed, every '..' and '.' flattened. CHOSEN OVER string
#                comparison on the name, because the question that matters is
#                where the filesystem would REALLY put the file.
#   realpath -m  do not require the path to exist. The file is about to be
#                created, so it does not exist yet; -m still resolves the parts
#                that do exist, which is the part a symlink attack would use.
#   --           end of options. If a path ever began with a hyphen, realpath
#                would otherwise read it as a flag.
# -----------------------------------------------------------------------------
resolve_target() {
    local name="$1" target real_target real_workspace

    mkdir -p -- "$WORKSPACE_DIR"

    real_workspace="$(realpath -- "$WORKSPACE_DIR")"
    target="$real_workspace/$name.txt"
    real_target="$(realpath -m -- "$target")"

    # Two conditions, because they answer two different questions:
    #   the path is SOMEWHERE under the workspace, and
    #   its parent is EXACTLY the workspace, so not in a subdirectory either.
    if [[ "$real_target" != "$real_workspace/"* ]] \
       || [[ "$(dirname -- "$real_target")" != "$real_workspace" ]]; then
        log_line "REFUSED" "path escaped the workspace: $name -> $real_target"
        emit_error "refusing to write outside the workspace"
    fi

    printf '%s' "$real_target"
}


# =============================================================================
#  ARGUMENTS
# =============================================================================
#
# ${1-} rather than $1: with `set -u` an unset $1 would abort the script with a
# raw Bash error on stderr and nothing on stdout, breaking the JSON contract.
# The dash supplies an empty default so the error is OURS and is valid JSON.
ACTION="${1-}"
NAME="${2-}"
CONTENT="${3-}"

[[ -n "$ACTION" ]] || emit_error "usage: workspace.sh create|tick <name> [content] | list"

# WHY THE NAME IS VALIDATED PER-BRANCH AND NOT UP HERE:
# 'list' operates on the directory, not on a file, so it has no name to check.
# Validating before the case statement would make `workspace.sh list` fail with
# "invalid name" -- which is both wrong and confusing. create and tick each ask
# for a validated name and a resolved path as their first act instead, so the
# check still happens before anything is touched.
case "$ACTION" in

    list)
        # -------------------------------------------------------------------
        # READ-ONLY. Lists what the console has created, and nothing else: the
        # glob is anchored to $WORKSPACE_DIR and matches only *.txt, so this
        # cannot report on a file anywhere else on the machine even if one were
        # somehow linked in.
        #
        # mkdir -p first: on a fresh checkout the directory does not exist yet,
        # and "no workspace" and "empty workspace" should look the same to the
        # user -- both mean "you have not created anything".
        # -------------------------------------------------------------------
        mkdir -p -- "$WORKSPACE_DIR"

        # nullglob: when a glob matches NOTHING, expand it to nothing at all.
        # Without it Bash leaves the pattern as a literal string and the loop
        # runs once with a filename that does not exist -- the single commonest
        # bug in shell scripts that iterate over files.
        shopt -s nullglob

        ROWS=""
        COUNT=0
        TOTAL_BYTES=0

        for FOUND in "$WORKSPACE_DIR"/*.txt; do
            BASE="$(basename -- "$FOUND")"
            ENTRY_NAME="${BASE%.txt}"

            # stat -c '%s'  the size in bytes. CHOSEN OVER `wc -c`, which would
            #               read the whole file just to count it; stat asks the
            #               filesystem for the size it already knows.
            ENTRY_BYTES="$(stat -c '%s' -- "$FOUND")"

            # date -r FILE  format that file's modification time. CHOSEN OVER
            #               `stat -c '%y'`, which prints nanoseconds and a
            #               timezone offset that nobody reading a web page
            #               wants. Same '+%F %T' format as the log, so the two
            #               can be compared by eye.
            ENTRY_MODIFIED="$(date -r "$FOUND" '+%F %T')"

            TOTAL_BYTES=$(( TOTAL_BYTES + ENTRY_BYTES ))

            [[ $COUNT -gt 0 ]] && ROWS+=","
            ROWS+="{"
            ROWS+="\"name\":$(json_string "$ENTRY_NAME"),"
            ROWS+="\"file\":$(json_string "$BASE"),"
            ROWS+="\"bytes\":$ENTRY_BYTES,"
            ROWS+="\"modified\":$(json_string "$ENTRY_MODIFIED")"
            ROWS+="}"
            COUNT=$(( COUNT + 1 ))
        done

        printf '{'
        printf '"module":%s,'    "$(json_string "$MODULE")"
        printf '"status":"ok",'
        printf '"action":"list",'
        printf '"workspace":%s,' "$(json_string "$WORKSPACE_DIR")"
        printf '"count":%s,'     "$COUNT"
        printf '"total_bytes":%s,' "$TOTAL_BYTES"
        printf '"files":[%s],'   "$ROWS"
        printf '"message":%s'    "$(json_string "$COUNT file(s) in the workspace")"
        printf '}\n'
        exit 0
        ;;

    create)
        require_valid_name "$NAME"
        TARGET="$(resolve_target "$NAME")"

        # --- the size limit ------------------------------------------------
        # Checked here as well as in Python. ${#CONTENT} is the length of the
        # string in characters, which Bash computes without starting a process.
        if (( ${#CONTENT} > WORKSPACE_MAX_BYTES )); then
            log_line "REFUSED" "content too large for $NAME: ${#CONTENT} bytes"
            emit_error "content is larger than the ${WORKSPACE_MAX_BYTES} byte limit"
        fi

        # Was the file already there? Recorded so the console can say
        # "replaced" rather than "created" and the log stays truthful.
        EXISTED=false
        [[ -e "$TARGET" ]] && EXISTED=true

        # A file created with no content at all is a confusing demo result, so
        # an empty request gets one explanatory line instead.
        if [[ -z "$CONTENT" ]]; then
            CONTENT="Created by Linux Guardian on $(date '+%F %T')."
        fi

        log_line "ACTION" "$NAME -- writing $TARGET"

        # printf '%s\n' rather than echo: echo's handling of backslashes and of
        # a leading "-n" varies between shells and builtins, so content
        # containing "\t" or starting with "-n" could be silently mangled.
        # printf's behaviour is fixed and documented.
        printf '%s\n' "$CONTENT" > "$TARGET"

        BYTES="$(stat -c '%s' -- "$TARGET")"

        if [[ "$EXISTED" == true ]]; then
            MESSAGE="replaced $NAME.txt ($BYTES bytes)"
        else
            MESSAGE="created $NAME.txt ($BYTES bytes)"
        fi
        log_line "SUCCESS" "$NAME -- $MESSAGE"
        ;;

    tick)
        require_valid_name "$NAME"
        TARGET="$(resolve_target "$NAME")"

        # Called only by a systemd timer this project generated. It APPENDS,
        # so a weekly schedule builds up a visible history of every firing
        # rather than overwriting itself into a single line.
        #
        # >> appends, > would truncate. This is the same distinction the log
        # function relies on, and getting it wrong here would mean a year of
        # weekly runs left exactly one line of evidence.
        LINE="$(date '+%F %T') -- guardian timer fired for $NAME"
        printf '%s\n' "$LINE" >> "$TARGET"

        BYTES="$(stat -c '%s' -- "$TARGET")"
        EXISTED=true
        MESSAGE="appended one line to $NAME.txt ($BYTES bytes)"
        log_line "SUCCESS" "$NAME -- timer fired, appended one line"
        ;;

    *)
        emit_error "unknown action: $ACTION (expected create, tick or list)"
        ;;
esac


# =============================================================================
#  OUTPUT -- collected first, printed once, at the very end (rule 7)
# =============================================================================
printf '{'
printf '"module":%s,'   "$(json_string "$MODULE")"
printf '"status":"ok",'
printf '"action":%s,'   "$(json_string "$ACTION")"
printf '"name":%s,'     "$(json_string "$NAME")"
printf '"path":%s,'     "$(json_string "$TARGET")"
printf '"bytes":%s,'    "$BYTES"
printf '"existed":%s,'  "$EXISTED"
printf '"message":%s'   "$(json_string "$MESSAGE")"
printf '}\n'
