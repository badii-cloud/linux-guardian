#!/bin/bash
# =============================================================================
#  Linux Guardian -- linux/process.sh         (Phase 1, module 3 of 4)
#
#  PURPOSE : List the TOP_PROCESS_COUNT processes currently using the most CPU,
#            with pid, name, CPU percent and resident memory in MB, as ONE JSON
#            object on standard output.
#
#  THE CENTRAL PROBLEM OF THIS MODULE -- WHY NOT JUST `ps`
#            `ps -eo pid,comm,pcpu --sort=-pcpu` looks like the obvious answer
#            and it is WRONG for a live monitor. The %CPU that ps reports is
#            the process's average over its ENTIRE LIFETIME: total CPU time
#            divided by how long the process has existed. A browser that
#            hammered the CPU an hour ago and has been asleep ever since still
#            appears at the top of the list.
#
#            Measured on this machine, side by side:
#                ps   ranked: firefox-esr 25.5%, Xorg 16.9%
#                top  ranked: Xorg 25.5%, firefox-esr 18.6%
#            A DIFFERENT top-10, from the same machine, at the same second.
#
#            `top -b -n 1` has the same flaw (its first iteration has nothing
#            to compare against, so it also reports the lifetime average), and
#            `top -b -n 2` truncates process names to 8 characters
#            ("firefox+", "qtermin+") which is useless in a dashboard column.
#
#            So we do what top itself does internally: read the per-process CPU
#            counters TWICE, a moment apart, and divide the difference by the
#            time that actually elapsed. This is exactly the same principle as
#            system.sh, applied per process instead of to the whole machine --
#            one idea to explain, used twice.
#
#  SAFETY  : 100% READ-ONLY. It reads /proc. It never sends a signal, never
#            kills, never renices anything.
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

# Force the C locale: printf and awk must write a decimal POINT, never a comma,
# or the JSON numbers would be invalid. `sort` also depends on this -- in some
# locales it would parse "23.5" as a different value.
export LC_ALL=C


# -----------------------------------------------------------------------------
# Locate the project, so the script works from any working directory
# (systemd runs it from "/", Flask from wherever the terminal was).
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname -- "$SCRIPT_DIR")"


# -----------------------------------------------------------------------------
# The failure contract: even a crash must produce valid JSON, because Flask
# feeds our stdout straight into json.loads().
# -----------------------------------------------------------------------------
emit_error() {
    printf '{"module":"process","status":"error","message":"%s"}\n' "$1"
    exit 1
}
# SINGLE quotes delay $LINENO until the trap fires, so it names the real line.
trap 'emit_error "process.sh failed at line $LINENO"' ERR


# -----------------------------------------------------------------------------
# JSON STRING ESCAPING -- the one place in this project where the data is not
# fully under our control.
#
# A process name comes from whoever started the program, and ANY user on this
# machine can choose it: `cp /bin/sleep './evil"name'` would put a double quote
# straight into our JSON and break the document -- or worse, inject extra JSON
# fields into the dashboard. For a tool whose job is to WATCH the system, that
# is exactly the input we must not trust.
#
#   ${var//pattern/replacement}  replace EVERY occurrence (a single / replaces
#                                only the first one).
# ORDER MATTERS: backslashes are escaped FIRST. If we escaped the quotes first,
# the backslash pass would then double the backslashes we had just added.
#
# HONEST LIMIT: this escapes \ and " -- the two characters that can break out of
# a JSON string here. It does not escape control characters; the kernel already
# forbids newlines in a process name, and `read` stops at one anyway.
# -----------------------------------------------------------------------------
json_escape() {
    local text="${1:-}"
    text="${text//\\/\\\\}"
    text="${text//\"/\\\"}"
    printf '%s' "$text"
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

TOP_PROCESS_COUNT="${TOP_PROCESS_COUNT:-10}"
CPU_SAMPLE_INTERVAL="${CPU_SAMPLE_INTERVAL:-1}"


# -----------------------------------------------------------------------------
# TWO CONSTANTS WE MUST ASK THE SYSTEM FOR, NOT GUESS
#
# getconf prints system configuration values defined by POSIX.
#
#   CLK_TCK   How many "clock ticks" make one second. The kernel counts every
#             process's CPU time in ticks, not seconds. On this machine it is
#             100, so 1 tick = 10 ms. It is 100 on virtually every Linux, but
#             hard-coding 100 would silently produce wrong percentages on a
#             kernel built differently -- and a wrong number that LOOKS right is
#             the worst kind of bug in a monitoring tool.
#
#   PAGESIZE  How many bytes in one memory page (4096 here). /proc reports a
#             process's memory as a COUNT OF PAGES, so we cannot convert to
#             megabytes without it.
# -----------------------------------------------------------------------------
clock_ticks_per_second="$(getconf CLK_TCK)"
page_size_bytes="$(getconf PAGESIZE)"


# =============================================================================
#  THE SAMPLER
# =============================================================================
#
# Prints one line per process:  "<pid> <total_cpu_ticks>"
#
# /proc/<pid>/stat holds 52 fields about one process. We need two of them:
#     field 14 utime  CPU ticks spent in USER mode   (running its own code)
#     field 15 stime  CPU ticks spent in KERNEL mode (doing syscalls for it)
# Their sum is all the CPU that process has ever consumed.
#
# THE PARSING TRAP -- why we do not simply take $14 and $15:
# field 2 is the process name, wrapped in parentheses, AND IT MAY CONTAIN
# SPACES. A real example from this machine:
#     19487 (Isolated Web Co) S 18263 18263 ...
# Splitting that on spaces makes "(Isolated" and "Web" and "Co)" three separate
# fields, so everything after them shifts by two and $14 is the wrong number.
#
# THE FIX: throw away everything up to and including the LAST ")". What remains
# starts at field 3 (the state letter), so counting again from there:
#     position 1  = state, 2 = ppid, ... 12 = utime, 13 = stime
# In a Bash array, which is numbered from 0, those are indexes 11 and 12.
#
#   ${var##*)}   delete the LONGEST match of "*)" from the START of the value.
#                "Longest" is what makes it stop at the LAST ")" rather than
#                the first, which is precisely the behaviour we need.
#   read -r -a   -a reads the words into an ARRAY instead of separate variables.
# -----------------------------------------------------------------------------
sample_cpu_ticks() {
    local stat_file pid stat_line fields_after_name
    local -a stat_fields

    # /proc/[0-9]* matches only the numeric directories -- one per process --
    # and skips /proc/cpuinfo, /proc/meminfo, /proc/self and the rest.
    for stat_file in /proc/[0-9]*/stat; do

        # A process can exit between the moment the shell expands the pattern
        # above and the moment we open its file. That is normal on a live
        # system, not an error, so we skip it silently.
        #   { ...; } 2>/dev/null   groups the command so the redirection is in
        #                          place BEFORE the file is opened; otherwise
        #                          Bash's "No such file" would still be printed.
        #   || continue            skip to the next process. Commands on the
        #                          left of || are exempt from `set -e`, so this
        #                          does not trip the error trap.
        { read -r stat_line < "$stat_file"; } 2>/dev/null || continue

        # Extract the pid from the path with pure parameter expansion:
        #   ${var#/proc/}  remove the prefix   -> "996/stat"
        #   ${var%/stat}   remove the suffix   -> "996"
        # Cheaper and clearer than running basename/dirname 253 times.
        pid="${stat_file#/proc/}"
        pid="${pid%/stat}"

        fields_after_name="${stat_line##*)}"
        read -r -a stat_fields <<< "$fields_after_name"

        # A guard, not decoration: if the line were truncated, ${#array[@]}
        # would be small and `set -u` would abort on an unset index below.
        if (( ${#stat_fields[@]} < 13 )); then
            continue
        fi

        printf '%s %s\n' "$pid" "$(( stat_fields[11] + stat_fields[12] ))"
    done
}


# =============================================================================
#  SAMPLE 1  ->  WAIT  ->  SAMPLE 2
# =============================================================================
#
# WHY WE READ THE CLOCK AND DO NOT TRUST `sleep 1`:
# the sampling loop itself takes about a third of a second to walk 253
# processes. So the real gap between reading a process's counter the first time
# and the second time is not 1.000 s but about 1.36 s. Dividing by 1 would
# overstate every percentage by roughly a third -- measured on this machine:
# nominal 1.000 s, actual 1.360 s.
#
# We therefore read /proc/uptime (seconds since boot, the same clock the tick
# counters are driven by) immediately before EACH pass. Because both passes
# walk the processes in the same order at the same speed, the gap experienced
# by every individual process is the same as the gap between those two clock
# readings.
# -----------------------------------------------------------------------------
read -r uptime_before _ < /proc/uptime
sample_before="$(sample_cpu_ticks)"

sleep "$CPU_SAMPLE_INTERVAL"

read -r uptime_after _ < /proc/uptime
sample_after="$(sample_cpu_ticks)"

# awk does the subtraction because these are decimals ("3165.42") and Bash
# arithmetic is integer-only.
elapsed_seconds="$(awk -v after="$uptime_after" -v before="$uptime_before" \
    'BEGIN { printf "%.3f", after - before }')"


# =============================================================================
#  COMPUTE THE DIFFERENCE PER PROCESS
# =============================================================================
#
# declare -A creates an ASSOCIATIVE array -- a lookup table whose keys are
# strings (here, pids) instead of numbers. It lets us ask "what was pid 996's
# counter in the first sample?" without searching the whole list.
# -----------------------------------------------------------------------------
declare -A ticks_before

# `while read ... done <<< "$var"` feeds a variable to a loop with a
# here-string.
# WHY NOT `printf '%s' "$var" | while read ...`: the right-hand side of a pipe
# runs in a SUBSHELL, so every variable the loop sets is destroyed the moment
# the loop ends. This is one of the classic Bash traps and it is silent -- the
# script would simply report an empty list. A here-string keeps the loop in the
# current shell.
while read -r pid ticks; do
    if [[ -n "$pid" ]]; then
        ticks_before["$pid"]="$ticks"
    fi
done <<< "$sample_before"

delta_lines=""
total_processes=0

while read -r pid ticks; do
    if [[ -z "$pid" ]]; then
        continue
    fi
    total_processes=$(( total_processes + 1 ))

    # -v tests whether that array key EXISTS. A process born during our one
    # second of sleep has no "before" value, so there is no difference to
    # compute and we leave it out rather than invent a number.
    if [[ ! -v ticks_before["$pid"] ]]; then
        continue
    fi

    delta=$(( ticks - ticks_before["$pid"] ))

    # Defensive: the kernel reuses pids. If pid 996 died and a brand-new
    # process got the same number, its counter restarts from zero and the
    # difference goes negative. Report 0 rather than a nonsensical percentage.
    if (( delta < 0 )); then
        delta=0
    fi

    # $'\n' is Bash's way of writing a real newline character inside a string.
    delta_lines+="$delta $pid"$'\n'
done <<< "$sample_after"

# Remove the single trailing newline, otherwise sort receives a blank final
# line and it could occupy one of our ten slots.
delta_lines="${delta_lines%$'\n'}"


# =============================================================================
#  RANK AND TAKE THE TOP N
# =============================================================================
#
#   sort -k1,1rn   sort on field 1 only (-k1,1), reverse (r), numeric (n):
#                  biggest CPU difference first.
#   -k2,2n         tie-break on field 2 (the pid) ascending, so that two
#                  processes with identical CPU always come out in the same
#                  order. Without it the output could shuffle between refreshes
#                  of the web page for no visible reason.
#
# WHY awk 'NR <= n' AND NOT `head -n`:
# `head` exits as soon as it has its lines, which closes the pipe and kills
# `sort` with SIGPIPE. Under `set -o pipefail` that makes the whole pipeline
# fail and our error trap would fire -- but only sometimes, depending on
# whether sort had already finished writing. An intermittent failure that
# appears during a live demonstration is the worst kind. awk reads its input to
# the end, so nothing is ever killed early.
# -----------------------------------------------------------------------------
ranked_lines="$(sort -k1,1rn -k2,2n <<< "$delta_lines" | awk -v limit="$TOP_PROCESS_COUNT" 'NR <= limit')"


# =============================================================================
#  BUILD THE JSON ARRAY -- reading the extra files only for the winners
# =============================================================================
#
# The two files below are read for the top N processes only, not for all 253.
# Ranking needs just the CPU counter; the name and the memory figure are only
# needed for the rows we are actually going to display.
#
#   /proc/<pid>/comm   the process name on a single line, with NO surrounding
#                      parentheses -- much simpler than digging field 2 out of
#                      /proc/<pid>/stat. Note the kernel stores this name in a
#                      16-byte buffer, so it is TRUNCATED TO 15 CHARACTERS:
#                      "Isolated Web Content" is stored as "Isolated Web Co".
#                      `ps` and `top` show exactly the same truncation, because
#                      they read exactly the same field. This is a kernel limit
#                      (TASK_COMM_LEN), not a bug in this script.
#
#   /proc/<pid>/statm  memory usage as a COUNT OF PAGES. Field 2 is "resident":
#                      the pages actually held in RAM right now. That is the
#                      same figure `ps` prints as RSS.
#                      CHOSEN OVER /proc/<pid>/status: that file gives VmRSS
#                      already in kB, but it has ~55 lines that must be
#                      searched for the right label. statm is one short line.
# -----------------------------------------------------------------------------
processes_json=""
rank=0

while read -r delta_ticks pid; do
    if [[ -z "$pid" ]]; then
        continue
    fi

    # These processes were alive a moment ago but may have exited since. Skip
    # any that have; returned_count in the output reports how many we really got.
    { read -r process_name < "/proc/$pid/comm"; } 2>/dev/null || continue
    { read -r -a statm_fields < "/proc/$pid/statm"; } 2>/dev/null || continue
    if (( ${#statm_fields[@]} < 2 )); then
        continue
    fi
    resident_pages="${statm_fields[1]}"

    # One awk call produces both numbers.
    #   CPU percent = 100 x (ticks difference / ticks per second) / seconds elapsed
    #   Memory MB   = pages x bytes per page / (1024 x 1024)
    #   %.1f        one decimal place, and a decimal POINT thanks to LC_ALL=C
    #   the e > 0 guard prevents a division by zero producing "inf" or "nan",
    #   neither of which is valid JSON.
    #
    # NOTE ON VALUES ABOVE 100: a process running on several cores at once can
    # legitimately report 150% or 380%. The figure is a percentage of ONE core,
    # which is exactly what top shows by default.
    metrics="$(awk -v ticks="$delta_ticks" -v hz="$clock_ticks_per_second" \
                   -v seconds="$elapsed_seconds" -v pages="$resident_pages" \
                   -v pagesize="$page_size_bytes" \
        'BEGIN {
             printf "%.1f %.1f", \
                    (seconds > 0 ? 100 * (ticks / hz) / seconds : 0), \
                    pages * pagesize / 1048576
         }')"
    read -r cpu_percent memory_mb <<< "$metrics"

    rank=$(( rank + 1 ))

    # A comma goes BETWEEN entries and never after the last one -- a trailing
    # comma is the most common way of writing invalid JSON.
    if [[ -n "$processes_json" ]]; then
        processes_json+=","
    fi

    # printf -v NAME writes into a variable instead of to the screen, with no
    # subshell and no command substitution.
    printf -v entry '\n    {\n      "rank": %s,\n      "pid": %s,\n      "name": "%s",\n      "cpu_percent": %s,\n      "memory_mb": %s\n    }' \
        "$rank" "$pid" "$(json_escape "$process_name")" "$cpu_percent" "$memory_mb"

    processes_json+="$entry"
done <<< "$ranked_lines"

# An empty result is a legitimate answer (it would mean no process survived
# both samples), and "[]" is how JSON spells an empty list.
if [[ -z "$processes_json" ]]; then
    processes_array="[]"
else
    processes_array="[$processes_json
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
# sample_window_seconds is published deliberately: it is the honest measurement
# window (about 1.36, not the 1.0 that was requested), and section 3.1 of the
# report can point at it.
# =============================================================================
cat << EOF
{
  "module": "process",
  "status": "ok",
  "timestamp": $timestamp_epoch,
  "timestamp_human": "$timestamp_human",
  "sample_window_seconds": $elapsed_seconds,
  "total_processes": $total_processes,
  "returned_count": $rank,
  "processes": $processes_array
}
EOF
