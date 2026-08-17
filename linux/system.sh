#!/bin/bash
# =============================================================================
#  Linux Guardian -- linux/system.sh          (Phase 1, module 1 of 4)
#
#  PURPOSE : Measure the core health of this Linux host and print the result as
#            exactly ONE JSON object on standard output. Nothing else is ever
#            printed: no colours, no tables, no progress messages.
#
#  MEASURES: hostname, kernel, CPU usage %, CPU cores, RAM usage %, disk usage %,
#            load average (1/5/15 min), uptime.
#
#  WHY JSON: In Phase 5, Flask runs this script with subprocess and hands its
#            stdout straight to json.loads(). Any stray character -- even a
#            single "Done." -- would raise JSONDecodeError and break the web
#            page. So stdout belongs to the data, and only to the data.
#
#  SAFETY  : 100% READ-ONLY. This script only reads /proc and runs reporting
#            commands. It never starts, stops, kills or modifies anything.
# =============================================================================


# -----------------------------------------------------------------------------
# set -euo pipefail -- the four safety switches of a serious Bash script.
#
#   -e            Exit immediately if any command exits non-zero. Without it,
#                 Bash would happily continue after a failure and we would
#                 print JSON built from empty/garbage variables.
#   -u            Treat the use of an UNSET variable as a fatal error. This
#                 catches typos: $DISK_MOUNTT would silently expand to "" in a
#                 normal shell; here it stops the script instead.
#   -o pipefail   In a pipeline "a | b", Bash normally reports only the exit
#                 status of the LAST command. With pipefail the pipeline fails
#                 if ANY stage failed. Without it, `df /nonexistent | awk ...`
#                 would look successful because awk itself succeeded.
#
# CHOSEN OVER: doing nothing (the Bash default), which hides errors, or
# checking "if [ $? -ne 0 ]" after every single command, which would triple the
# length of the script for the same result.
# -----------------------------------------------------------------------------
set -euo pipefail

# -E is a fifth switch, set separately because the assignment fixes the line
# above. It makes the ERR trap declared further down also fire INSIDE shell
# functions and command substitutions. Plain `set -e` does not inherit traps
# into functions, so without -E a failure inside read_cpu_times() would not be
# reported through our JSON error path.
set -E

# -----------------------------------------------------------------------------
# LC_ALL=C forces the "C" (POSIX) locale for this script and every command it
# runs. `export` is required so that awk, df and date -- which are separate
# programs -- inherit it too.
#
# WHY THIS IS NOT OPTIONAL: in locales such as fr_FR or de_DE, printf writes a
# decimal COMMA. awk would then produce "3,5" instead of "3.5". "3,5" is NOT a
# valid JSON number, and Flask's json.loads() would reject the whole document.
# One exported variable removes an entire class of bug.
# -----------------------------------------------------------------------------
export LC_ALL=C


# -----------------------------------------------------------------------------
# WHERE AM I?  (locating the project so relative paths are never used)
#
#   ${BASH_SOURCE[0]}  Path of THIS script file. Preferred over $0 because $0
#                      becomes "bash" when a script is sourced or run oddly,
#                      while BASH_SOURCE always names the real file.
#   dirname            Strips the filename, leaving the directory part.
#                      "/home/kali/.../linux/system.sh" -> "/home/kali/.../linux"
#   --                 End-of-options marker. It tells dirname/cd that whatever
#                      follows is a path, even if it starts with "-".
#   cd ... && pwd      Turns a possibly relative path ("./linux") into an
#                      absolute one ("/home/kali/Desktop/linux-guardian/linux").
#                      It runs inside $( ) which is a subshell, so this `cd`
#                      does NOT change the directory of the running script.
#
# WHY BOTHER: in Phase 4 systemd starts this script with working directory "/",
# and in Phase 5 Flask starts it from wherever the terminal happened to be.
# A relative path like "config/guardian.conf" would simply not exist there.
# Resolving from the script's own location makes the script position-independent.
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname -- "$SCRIPT_DIR")"


# -----------------------------------------------------------------------------
# THE FAILURE CONTRACT
#
# The rest of Linux Guardian assumes this script ALWAYS prints valid JSON.
# So if something goes wrong we must still print JSON -- not a raw Bash error
# message that would crash the web page. emit_error() is the single exit door
# for every failure.
#
#   printf   Chosen over echo because printf has a fixed, documented format
#            string and does not reinterpret backslashes the way some echo
#            implementations do. For generating an exact text format, printf
#            is the correct tool.
#   %s       Placeholder replaced by "$1", the first argument of the function.
#   exit 1   Non-zero exit status = "I failed", which Flask can also test.
# -----------------------------------------------------------------------------
emit_error() {
    printf '{"module":"system","status":"error","message":"%s"}\n' "$1"
    exit 1
}

# trap '<command>' ERR  registers <command> to run whenever a command fails.
# The quotes must be SINGLE quotes: that delays the expansion of $LINENO until
# the moment the trap actually fires, so the message reports the line that
# really broke. With double quotes it would be frozen at the value of this line.
trap 'emit_error "system.sh failed at line $LINENO"' ERR


# -----------------------------------------------------------------------------
# LOAD THE CONFIGURATION
#
#   [[ -r FILE ]]  Test whether FILE exists AND is readable. [[ ]] is the Bash
#                  test keyword; it is safer than the old [ ] because it does
#                  not need the variable to be quoted to survive spaces.
#   ||             "or else": run emit_error only if the test failed.
#   export         GUARDIAN_ROOT must exist BEFORE sourcing, because
#                  guardian.conf builds LOG_FILE out of it.
#   source FILE    Executes FILE inside the CURRENT shell, so the variables it
#                  defines stay alive here.
#                  CHOSEN OVER running "./guardian.conf": that would start a
#                  CHILD shell, and every variable would disappear when the
#                  child exited. Sourcing is the only way to import settings.
#
# The "# shellcheck source=" comment is not code -- it tells the shellcheck
# linter where the sourced file lives so it can check it too.
# -----------------------------------------------------------------------------
CONFIG_FILE="$PROJECT_ROOT/config/guardian.conf"
[[ -r "$CONFIG_FILE" ]] || emit_error "config file not found or not readable: $CONFIG_FILE"

export GUARDIAN_ROOT="$PROJECT_ROOT"
# shellcheck source=../config/guardian.conf
source "$CONFIG_FILE"

# ${VAR:-default} means "use $VAR, but if it is unset or empty use default".
# This is a safety net: if someone deletes a line from guardian.conf, the script
# still runs with a sane value instead of dying from `set -u`.
DISK_MOUNT="${DISK_MOUNT:-/}"
CPU_SAMPLE_INTERVAL="${CPU_SAMPLE_INTERVAL:-1}"


# =============================================================================
#  METRIC 1 -- CPU USAGE PERCENT
# =============================================================================
#
# THE IDEA: CPU usage is a RATE, so it cannot be read from a single number.
# The kernel file /proc/stat counts, since boot, how many "jiffies" (clock
# ticks) the CPU spent in each state. Its first line looks like:
#
#     cpu  89622 191 43497 1032241 1372 0 13898 0 0 0
#      |     |    |    |      |      |  |   |
#      |   user nice system  idle iowait irq softirq  steal guest guest_nice
#     label
#
# To get a percentage we read those counters twice, one second apart, and ask:
# "of all the ticks that passed during that second, what fraction was NOT idle?"
#
#     busy% = 100 x (total_delta - idle_delta) / total_delta
#
# CHOSEN OVER `top -bn1`: the first sample of top reports the average since
# BOOT, which on a VM that has been up for hours is always a flat, useless
# number. CHOSEN OVER `mpstat`: mpstat comes from the sysstat package, which is
# not installed on a default Kali. /proc/stat is part of the kernel itself, so
# it is always there and there is no dependency to explain or install.
# -----------------------------------------------------------------------------
read_cpu_times() {
    # `local` limits these names to this function so they cannot collide with
    # variables in the main body of the script.
    local user nice system idle iowait irq softirq steal
    local total idle_all

    # read -r  : read one line and split it into the listed variables.
    #   -r     : do NOT treat backslash as an escape character. Always use -r
    #            unless you specifically want escapes; it is the safe default.
    #   _      : the conventional "throwaway" variable name. The first _ eats
    #            the word "cpu"; the last _ eats the leftover guest counters,
    #            which we deliberately ignore (the kernel already counts guest
    #            time inside user and nice, so adding it would double-count).
    #   < /proc/stat : redirect the FILE into read, so read takes the first
    #            line. CHOSEN OVER `head -1 /proc/stat | read ...`, which does
    #            not work in Bash: the right-hand side of a pipe runs in a
    #            subshell and its variables vanish.
    read -r _ user nice system idle iowait irq softirq steal _ < /proc/stat

    # $(( ... )) is Bash arithmetic expansion: integer maths, no external
    # program needed. Total = every tick the CPU accounted for.
    total=$(( user + nice + system + idle + iowait + irq + softirq + steal ))

    # "Doing nothing" is idle plus iowait: during iowait the CPU is genuinely
    # parked waiting for the disk, so counting it as busy would overstate load.
    idle_all=$(( idle + iowait ))

    printf '%s %s\n' "$total" "$idle_all"
}

# --- sample 1 ---------------------------------------------------------------
# NOTE THE TWO-STEP PATTERN, used again for RAM and disk below:
#   step 1: capture into a variable with x="$( ... )"
#   step 2: split that variable with read
# It is written this way ON PURPOSE. In a plain assignment, the exit status of
# the command substitution becomes the exit status of the assignment, so
# `set -e` and the ERR trap can see a failure. If we wrote
# `read a b <<< "$(cmd)"` in one go, read would succeed even when cmd failed,
# and the failure would pass unnoticed.
cpu_sample_1="$(read_cpu_times)"
read -r cpu_total_1 cpu_idle_1 <<< "$cpu_sample_1"

# sleep pauses for the configured number of seconds -- the measurement window.
sleep "$CPU_SAMPLE_INTERVAL"

# --- sample 2 ---------------------------------------------------------------
cpu_sample_2="$(read_cpu_times)"
read -r cpu_total_2 cpu_idle_2 <<< "$cpu_sample_2"

# --- the division ------------------------------------------------------------
# Bash arithmetic is INTEGER ONLY: $(( 3 / 2 )) is 1, not 1.5. To get one
# decimal place we need a tool that understands floating point, so we use awk.
#   -v name=value  passes a shell variable into awk as an awk variable. CHOSEN
#                  OVER embedding "$var" inside the awk program text, which
#                  would let the shell's contents be parsed as awk code.
#   BEGIN { }      runs the block once, before reading any input. We give awk
#                  no input file at all, so BEGIN is the whole program.
#   printf "%.1f"  prints a float rounded to 1 decimal, e.g. 3.5 -> "3.5".
#                  This is a valid JSON number, so the value is emitted unquoted.
#   the if guard   protects against a division by zero, which would print "nan"
#                  or "inf" and produce invalid JSON.
# CHOSEN OVER `bc`: awk is already required elsewhere in this project and is
# installed on every Unix; bc is an extra dependency for the same result.
cpu_usage_percent="$(awk -v t1="$cpu_total_1" -v i1="$cpu_idle_1" \
                         -v t2="$cpu_total_2" -v i2="$cpu_idle_2" \
    'BEGIN {
         total_delta = t2 - t1
         idle_delta  = i2 - i1
         if (total_delta <= 0) { printf "0.0" }
         else { printf "%.1f", 100 * (total_delta - idle_delta) / total_delta }
     }')"

# nproc prints the number of processing units available to this process.
# CHOSEN OVER `grep -c ^processor /proc/cpuinfo`: nproc is one word, it is part
# of GNU coreutils (always present), and it correctly respects CPU affinity.
cpu_cores="$(nproc)"


# =============================================================================
#  METRIC 2 -- RAM USAGE PERCENT
# =============================================================================
#
# /proc/meminfo is the kernel's memory report, in kilobytes:
#     MemTotal:        8097308 kB
#     MemAvailable:    5340176 kB
#
# We use MemAvailable, NOT MemFree. MemFree counts only completely untouched
# memory; Linux deliberately fills the rest with disk cache, which it will hand
# back to any program that asks. Judging by MemFree therefore makes a perfectly
# healthy Linux box look like it is out of RAM. MemAvailable is the kernel's own
# estimate of "memory a new program could actually get", which is what a user
# means by free memory.
#
#     used% = 100 x (MemTotal - MemAvailable) / MemTotal
#
# CHOSEN OVER parsing `free -m`: the column layout of free has changed between
# procps versions (the old "-/+ buffers/cache" line was removed), so a script
# that parses it breaks on a different distro. /proc/meminfo has stable, named
# labels and is guaranteed by the kernel.
# -----------------------------------------------------------------------------
# awk pattern { action }: for every input line matching the pattern, run the
# action. /^MemTotal:/ is a regular expression -- ^ anchors it to the start of
# the line so it cannot match some other label that merely contains the word.
# $2 is the second whitespace-separated field, i.e. the number.
mem_total_kb="$(awk '/^MemTotal:/     { print $2 }' /proc/meminfo)"
mem_avail_kb="$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)"

# One awk call produces all four memory figures at once, space separated.
#   %.1f for the percentage (one decimal), %.0f for whole megabytes.
#   / 1024 converts kilobytes to megabytes.
#   (total > 0 ? A : B) is awk's conditional expression, guarding against a
#   division by zero exactly like the CPU block above.
mem_stats="$(awk -v total="$mem_total_kb" -v avail="$mem_avail_kb" \
    'BEGIN {
         used = total - avail
         printf "%.1f %.0f %.0f %.0f", \
                (total > 0 ? 100 * used / total : 0), \
                total / 1024, used / 1024, avail / 1024
     }')"
read -r mem_usage_percent mem_total_mb mem_used_mb mem_available_mb <<< "$mem_stats"


# =============================================================================
#  METRIC 3 -- DISK USAGE PERCENT
# =============================================================================
#
# df ("disk free") reports usage per mounted filesystem:
#     Filesystem     1024-blocks     Used Available Capacity Mounted on
#     /dev/sda1         82083148 23778148  54089452      31% /
#
#   -P   POSIX output format. THIS FLAG IS THE IMPORTANT ONE: without it, GNU df
#        wraps a long device name (e.g. an LVM path, or /dev/mapper/...) onto a
#        second line, and our "second line" rule would then read the wrong
#        fields. -P guarantees exactly one line per filesystem.
#   -k   Report sizes in fixed 1024-byte blocks.
#        CHOSEN OVER -h ("human readable"): -h prints "78G" or "1.2T", which are
#        STRINGS with a unit letter glued on. We would have to parse and convert
#        them. -k gives a plain number we can do arithmetic on.
#
# awk 'NR == 2' selects record (line) number 2 -- the data line, skipping the
# header. sub(/%$/, "", $5) deletes the "%" sign anchored at the end of field 5,
# turning "31%" into "31" so it can be emitted as a JSON number.
# 1048576 = 1024 x 1024, converting 1K-blocks into gibibytes.
# -----------------------------------------------------------------------------
disk_stats="$(df -P -k "$DISK_MOUNT" | awk 'NR == 2 {
         sub(/%$/, "", $5)
         printf "%s %.1f %.1f %.1f", $5, $2 / 1048576, $3 / 1048576, $4 / 1048576
     }')"
read -r disk_usage_percent disk_total_gb disk_used_gb disk_free_gb <<< "$disk_stats"


# =============================================================================
#  METRIC 4 -- LOAD AVERAGE
# =============================================================================
#
# /proc/loadavg holds five fields:
#     0.76 1.30 1.05 6/788 39920
#      |    |    |    |      |
#      |    |    |    |      last PID created
#      |    |    |    running/total processes
#      1-, 5- and 15-minute load averages
#
# Load average = the average number of processes that were either running or
# waiting to run. It is NOT a percentage: on this 4-core VM, 4.00 means "fully
# busy", so it must always be interpreted against cpu_cores. That is exactly why
# cpu_cores is included in the JSON above.
#
# The trailing _ absorbs fields 4 and 5, which we do not need.
# CHOSEN OVER `uptime` or `cat /proc/loadavg | cut ...`: reading the file
# directly with the `read` builtin starts no external process at all.
# -----------------------------------------------------------------------------
read -r load_1min load_5min load_15min _ < /proc/loadavg


# =============================================================================
#  METRIC 5 -- UPTIME
# =============================================================================
#
# /proc/uptime holds two numbers: seconds since boot, and idle seconds summed
# over all cores. We want the first one.
#     2980.59 10322.42
# -----------------------------------------------------------------------------
read -r uptime_raw _ < /proc/uptime

# ${var%.*} is parameter expansion: "%" removes the SHORTEST match of the
# pattern ".*" from the END of the value. "2980.59" -> "2980".
# We drop the fractional part because a dashboard showing "up 2980.59 seconds"
# is noise, and an integer is easier to format in Phase 5.
# CHOSEN OVER `cut -d. -f1` or `awk -F.`: parameter expansion is built into
# Bash, so it costs no process.
uptime_seconds="${uptime_raw%.*}"

# uptime --pretty produces a human sentence such as "up 49 minutes".
# The long option --pretty is used instead of -p purely for readability: in a
# script that someone else has to read, self-documenting flags are worth the
# extra characters.
uptime_human="$(uptime --pretty)"


# =============================================================================
#  IDENTITY AND TIMESTAMP
# =============================================================================

# hostname prints this machine's network name ("kali").
host_name="$(hostname)"

# uname reports information about the kernel.
#   -r  release, e.g. "6.19.14+kali-amd64"  <- the kernel VERSION
# CHOSEN OVER -a, which prints everything on one line (kernel name, hostname,
# release, build date, architecture). We want one clean field, not a sentence
# we would have to cut apart.
kernel_release="$(uname -r)"

# Two forms of the same instant, because they serve different readers:
#   %s   seconds since 1970-01-01 UTC ("Unix epoch"). A plain integer, ideal for
#        sorting and for calculating "how old is this reading?" in Phase 5.
#   the formatted string is for the human looking at the web page.
timestamp_epoch="$(date +%s)"
timestamp_human="$(date '+%Y-%m-%d %H:%M:%S')"


# =============================================================================
#  OUTPUT -- one JSON object, printed once, at the very end
# =============================================================================
#
# WHY AT THE END: every value is collected first, and only then do we print. If
# a command had failed halfway through, the ERR trap would have printed the
# error JSON and exited BEFORE any of this ran -- so stdout can never contain
# half a document. The "one valid JSON object" promise holds in every case.
#
# `cat << EOF ... EOF` is a here-document: Bash feeds cat everything up to the
# line containing only EOF. Because EOF is unquoted, $variables inside are
# expanded. CHOSEN OVER many echo lines (easy to forget a comma and impossible
# to see the shape of the document) and over one giant printf (18 %s
# placeholders that must line up with 18 arguments in the right order).
#
# QUOTING RULE, the single most important detail in this file:
#   - strings  -> wrapped in double quotes:  "hostname": "kali"
#   - numbers  -> NOT quoted:                "usage_percent": 3.5
# The assignment requires numbers to be real JSON numbers so that Python gets an
# int/float and Jinja2 can compare them against thresholds directly. Every
# unquoted value below was produced by printf "%.1f", printf "%.0f", $(( )) or
# the kernel itself, so each is guaranteed to be a bare number.
# =============================================================================
cat << EOF
{
  "module": "system",
  "status": "ok",
  "timestamp": $timestamp_epoch,
  "timestamp_human": "$timestamp_human",
  "hostname": "$host_name",
  "kernel": "$kernel_release",
  "cpu": {
    "usage_percent": $cpu_usage_percent,
    "cores": $cpu_cores
  },
  "memory": {
    "usage_percent": $mem_usage_percent,
    "total_mb": $mem_total_mb,
    "used_mb": $mem_used_mb,
    "available_mb": $mem_available_mb
  },
  "disk": {
    "mount_point": "$DISK_MOUNT",
    "usage_percent": $disk_usage_percent,
    "total_gb": $disk_total_gb,
    "used_gb": $disk_used_gb,
    "free_gb": $disk_free_gb
  },
  "load_average": {
    "last_1min": $load_1min,
    "last_5min": $load_5min,
    "last_15min": $load_15min
  },
  "uptime": {
    "seconds": $uptime_seconds,
    "human": "$uptime_human"
  }
}
EOF






