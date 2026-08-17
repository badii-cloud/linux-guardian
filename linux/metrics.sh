#!/bin/bash
# =============================================================================
#  Linux Guardian -- linux/metrics.sh                          (Phase 7, 1 of n)
#
#  PURPOSE : Take ONE cheap, complete reading of every number this project may
#            later want to plot, compare against a baseline, or call abnormal --
#            and print it as exactly one JSON object.
#
#  WHY THIS IS NOT A DUPLICATE OF system.sh -- the question a marker will ask.
#
#    system.sh answers "how is the machine RIGHT NOW, for a human reading a web
#    page". To report CPU as a percentage it MUST read /proc/stat twice one
#    second apart, so it takes just over a second to run. network.sh pings the
#    gateway and takes about three. That is perfectly reasonable for a page the
#    user loads by hand.
#
#    metrics.sh answers a different question: "what should I write into the
#    history table this tick". It is built to be run again and again on a timer,
#    so its design rule is the opposite one -- IT MUST NEVER SLEEP AND NEVER
#    WAIT FOR THE NETWORK.
#
#    Measured on this VM, one run at a time:
#        diagnosis.sh (the full Phase 2 sweep)   3253 ms
#        metrics.sh                                52 ms
#    Sixty times cheaper, which is the difference between a sampler you can run
#    every thirty seconds forever and one you cannot.
#
#    The two scripts therefore treat the same kernel files differently, and that
#    difference is the whole point of the file:
#
#  GAUGES vs COUNTERS -- the one idea to understand here.
#
#    A GAUGE is true on its own. "Memory is 21.4% used" means something the
#    instant you read it, the way a fuel gauge does.
#
#    A COUNTER only ever goes up, counting since boot. "The CPU has spent
#    12,760 ticks in user mode" means nothing on its own -- it is an odometer.
#    An odometer becomes a speed only when you subtract two readings and divide
#    by the time between them.
#
#    system.sh does that subtraction internally by sleeping for a second.
#    metrics.sh refuses to sleep, so it publishes the ODOMETER READING RAW and
#    lets the consumer subtract it from the PREVIOUS stored sample. The database
#    already holds the previous row, so the second reading is free -- the one
#    second system.sh spends waiting has already elapsed in the real world.
#
#    This is exactly how every real monitoring system works (Prometheus,
#    collectd, sar): counters are shipped raw, rates are derived at read time.
#    It is also why the output below is split into two named objects instead of
#    one flat list -- a consumer must never average a counter or difference a
#    gauge, and naming the two groups makes that mistake hard to make.
#
#  SAFETY  : 100% READ-ONLY, like every module before Phase 3. It reads /proc,
#            asks systemd and the kernel socket table what they can see, and
#            writes nothing anywhere.
# =============================================================================


# -----------------------------------------------------------------------------
# The four safety switches, identical in every module of this project.
#   -e            stop on the first command that fails
#   -u            stop if an unset variable is used (catches typos)
#   -o pipefail   a pipeline fails if ANY stage failed, not just the last one
# -----------------------------------------------------------------------------
set -euo pipefail

# -E makes the ERR trap below fire inside functions and command substitutions
# too. Plain `set -e` does not inherit traps into functions, so a failure inside
# a helper would escape the JSON error contract without it.
set -E

# LC_ALL=C forces a decimal POINT. In a comma-decimal locale awk would print
# "21,4", which is not a valid JSON number and would break json.loads().
#
# IT MATTERS TWICE IN THIS PARTICULAR SCRIPT: $EPOCHREALTIME (used at the very
# bottom to time ourselves) is formatted by Bash using the LOCALE'S radix
# character, so in fr_FR it would read "1755331200,123456" and the arithmetic
# on it would silently truncate to whole seconds.
export LC_ALL=C

# Bash 5 exposes the current time, with microseconds, as a variable. Reading it
# costs no process at all, which is the point: a stopwatch that itself forks
# `date` twice would be measuring mostly its own overhead.
sample_start="$EPOCHREALTIME"


# -----------------------------------------------------------------------------
# Locate the project from the script's own path, never from the working
# directory -- systemd runs these from "/".
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname -- "$SCRIPT_DIR")"


# -----------------------------------------------------------------------------
# The failure contract: even a crash prints valid JSON, because Flask feeds our
# stdout straight into json.loads(). SINGLE quotes in the trap delay $LINENO
# until the trap actually fires, so it names the line that broke.
# -----------------------------------------------------------------------------
emit_error() {
    printf '{"module":"metrics","status":"error","message":"%s"}\n' "$1"
    exit 1
}
trap 'emit_error "metrics.sh failed at line $LINENO"' ERR


# -----------------------------------------------------------------------------
# json_string -- quote a value for JSON, or emit the literal null when empty.
#
# The only strings this module prints are an interface name and a device name,
# both of which come from the kernel rather than from a user. It is escaped
# anyway: "the kernel would never" is exactly the assumption that ages badly,
# and the cost is two parameter expansions.
#   ${var//old/new}   replace EVERY occurrence (one slash replaces only the
#                     first). Backslashes are escaped FIRST, or the quote pass
#                     would have its own new backslashes doubled afterwards.
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

# ---------------------------------------------------------------------------
# json_number -- print a number unquoted, or the literal null if we have none.
#
# WHY null AND NOT 0. If the interface named in the config does not exist, its
# byte counters are UNKNOWN. Printing 0 would be a lie the consumer cannot
# detect: the next sample would show a gigantic jump from "0" to the real
# figure and the anomaly detector would dutifully report a traffic spike that
# never happened. null says "no reading", and a missing reading can be skipped.
# This is the same principle diagnosis.sh already applies when it records a
# broken module as FAIL instead of quietly dropping its checks.
# ---------------------------------------------------------------------------
json_number() {
    local value="${1:-}"
    if [[ -z "$value" ]]; then
        printf 'null'
        return
    fi
    printf '%s' "$value"
}


# -----------------------------------------------------------------------------
# Load the configuration. Every setting gets a fallback so that a line deleted
# from guardian.conf degrades one reading instead of killing the script under
# `set -u`.
# -----------------------------------------------------------------------------
CONFIG_FILE="$PROJECT_ROOT/config/guardian.conf"
[[ -r "$CONFIG_FILE" ]] || emit_error "config file not found or not readable: $CONFIG_FILE"

export GUARDIAN_ROOT="$PROJECT_ROOT"
# shellcheck source=../config/guardian.conf
source "$CONFIG_FILE"

DISK_MOUNT="${DISK_MOUNT:-/}"
METRICS_INTERFACE="${METRICS_INTERFACE:-}"
METRICS_DISK_DEVICE="${METRICS_DISK_DEVICE:-}"


# =============================================================================
#  STEP 1 -- CPU ODOMETERS, read once, never twice
# =============================================================================
#
# The first line of /proc/stat counts, since boot, how many "jiffies" (kernel
# clock ticks) the CPU has spent in each state:
#
#     cpu  12760 4 5630 126468 433 0 3998 0 0 0
#      |     |   |   |     |     |  |   |
#     label user nice sys idle iowait irq softirq  steal guest guest_nice
#
#   read -r  read one line and split it across the listed variables.
#     -r     do not treat backslash as an escape. Always use -r unless escapes
#            are specifically wanted; it is the safe default.
#     _      the conventional throwaway name. The first _ eats the word "cpu";
#            the last _ eats the guest counters, which are IGNORED ON PURPOSE --
#            the kernel already counts guest time inside user and nice, so
#            adding them would count the same ticks twice.
#     < file redirect the FILE into read, so read consumes its first line.
#            CHOSEN OVER `head -1 /proc/stat | read ...`, which does not work in
#            Bash at all: the right-hand side of a pipe runs in a subshell and
#            every variable it sets disappears when that subshell exits.
#
# THE TWO SUMS BELOW ARE COPIED, DELIBERATELY, FROM system.sh. Both scripts must
# define "total" and "idle" identically, or the percentage derived from these
# counters would not agree with the percentage on the dashboard, and a graph
# that contradicts the number next to it is worse than no graph.
# -----------------------------------------------------------------------------
read -r _ cpu_user cpu_nice cpu_system cpu_idle cpu_iowait cpu_irq cpu_softirq cpu_steal _ < /proc/stat

# $(( )) is Bash arithmetic expansion: integer maths with no external program.
# These are whole tick counts, so integer maths is not a compromise here.
cpu_total_ticks=$(( cpu_user + cpu_nice + cpu_system + cpu_idle + cpu_iowait + cpu_irq + cpu_softirq + cpu_steal ))

# "Doing nothing" is idle PLUS iowait: during iowait the CPU really is parked
# waiting for a disk, so counting it as busy would overstate load.
cpu_idle_ticks=$(( cpu_idle + cpu_iowait ))

# Ticks per second -- the divisor that turns a tick delta into seconds. It is
# 100 on every normal Linux build, but it is a compile-time kernel choice, so it
# is asked for rather than assumed.
#   getconf   queries the C library for a system configuration value. CHOSEN
#             OVER hard-coding 100, and over `grep CONFIG_HZ /boot/config-*`,
#             which reads a file that may not be installed.
clock_ticks_per_second="$(getconf CLK_TCK)"

# nproc prints the number of processing units available. CHOSEN OVER
# `grep -c ^processor /proc/cpuinfo`: nproc is one word, ships in coreutils, and
# respects CPU affinity if this script is ever confined to a subset of cores.
cpu_cores="$(nproc)"

# Three more odometers live further down the same file, on their own lines.
# ONE awk pass collects all three rather than three greps, because each grep
# would be another process reading the same file from the start.
#   $1 == "ctxt"  match on the FIRST FIELD, not with a regex on the whole line.
#                 CHOSEN OVER /ctxt/ because a substring match would also fire
#                 on a line that merely contained those letters.
#   END { }       runs once after the last line, which is where we print.
#   c + 0         forces awk to treat the value as a NUMBER, and yields 0 rather
#                 than an empty field if the kernel did not publish that line.
#                 An empty field here would print two spaces in a row and the
#                 `read` below would misalign every variable after it.
# -----------------------------------------------------------------------------
cpu_extra="$(awk '
    $1 == "ctxt"          { context_switches = $2 }
    $1 == "processes"     { forks            = $2 }
    $1 == "procs_blocked" { blocked          = $2 }
    END { print context_switches + 0, forks + 0, blocked + 0 }
' /proc/stat)"
read -r context_switches processes_forked processes_blocked <<< "$cpu_extra"


# =============================================================================
#  STEP 2 -- MEMORY AND SWAP  (gauges)
# =============================================================================
#
# /proc/meminfo is a "Label: value kB" list. Four labels matter here.
#
# MemAvailable IS THE HONEST ONE, and this is the classic Linux exam question:
# MemFree looks catastrophically low on a healthy machine because Linux fills
# spare RAM with disk cache on purpose -- unused RAM is wasted RAM. MemAvailable
# is the kernel's own estimate of what a new program could actually obtain,
# cache included. Using MemFree would make this VM look 90% full at idle.
#
# SWAP IS REPORTED SEPARATELY AND IT IS NOT A DUPLICATE OF RAM. A machine can
# sit at a comfortable 60% RAM and still be crawling, because it is paging: swap
# usage climbing is the signature of memory pressure, and it is the one number
# that shows the pain rather than the level.
#
# One awk pass produces all three figures. The (x > 0 ? a : b) conditional
# guards the division -- a VM with swap switched off has SwapTotal = 0, and
# dividing by it would print "nan", which is not valid JSON.
# -----------------------------------------------------------------------------
memory_values="$(awk '
    $1 == "MemTotal:"     { mem_total  = $2 }
    $1 == "MemAvailable:" { mem_avail  = $2 }
    $1 == "SwapTotal:"    { swap_total = $2 }
    $1 == "SwapFree:"     { swap_free  = $2 }
    END {
        printf "%.1f %.1f %.0f",
            (mem_total  > 0 ? 100 * (mem_total - mem_avail) / mem_total : 0),
            (swap_total > 0 ? 100 * (swap_total - swap_free) / swap_total : 0),
            swap_total / 1024
    }
' /proc/meminfo)"
read -r memory_used_percent swap_used_percent swap_total_mb <<< "$memory_values"


# =============================================================================
#  STEP 3 -- LOAD AVERAGE AND PROCESS COUNTS  (gauges)
# =============================================================================
#
# /proc/loadavg holds five fields in one line:
#
#     0.58 0.61 0.33 1/829 6570
#      |    |    |    |  |   |
#     1min 5min 15min |  |  last PID created
#                     |  total processes and threads
#                     runnable right now
#
# Reading the file gives all of this for the price of one open(), which is why
# it is preferred here over `uptime` (a process, and its output format differs
# between systems) and over counting entries in /proc (hundreds of stat calls).
# -----------------------------------------------------------------------------
read -r load_1min load_5min load_15min process_ratio _ < /proc/loadavg

# ${var%%/*} strips the longest match of "/anything" from the END;
# ${var##*/} strips the longest match of "anything/" from the FRONT.
# Pure Bash string surgery -- no cut, no awk, no extra process.
processes_running="${process_ratio%%/*}"
processes_total="${process_ratio##*/}"

# LOAD IS ONLY MEANINGFUL PER CORE. A load of 4.00 means "four tasks wanted the
# CPU at once": on this 4-core VM that is exactly full, on a 1-core VM it is a
# fourfold overload. The ratio is what a threshold can be compared against, and
# it is computed here -- not in JavaScript -- so the browser never has to know
# how many cores this machine has.
load_per_core="$(awk -v load_value="$load_1min" -v cores="$cpu_cores" \
    'BEGIN { printf "%.2f", (cores > 0 ? load_value / cores : load_value) }')"

# ZOMBIES: a zombie is a process that has finished but whose parent has not yet
# collected its exit status, so the kernel keeps the entry alive. One or two for
# a moment is normal. A number that climbs and never falls means a parent
# process is broken and is leaking process table entries -- a real fault that no
# CPU or RAM gauge will ever show you, which is why it is sampled separately.
#
#   ps -eo stat=   -e  every process on the system
#                  -o  output only these columns
#                  stat= the process state column, and the trailing "=" sets an
#                        EMPTY HEADER, so ps prints no header line at all.
#   $1 ~ /^Z/      the state field STARTS WITH Z. It is a prefix match, not
#                  equality, because the state carries suffix flags: a zombie
#                  can appear as "Z" or "Z+" (foreground process group).
#   n + 0          prints 0 rather than an empty line when there are none.
#
# CHOSEN OVER `ps -eo stat= | grep -c '^Z'`: grep exits with status 1 when it
# finds nothing, and under `set -e` and pipefail "no zombies" -- the healthy,
# normal case -- would abort the script. awk always exits 0.
processes_zombie="$(ps -eo stat= | awk '$1 ~ /^Z/ { n++ } END { print n + 0 }')"

# OPEN FILE DESCRIPTORS, system-wide. /proc/sys/fs/file-nr holds three numbers:
# allocated, free-but-allocated (always 0 on modern kernels), and the maximum.
# Only the first is taken. THE MAXIMUM IS DELIBERATELY NOT REPORTED: on this
# kernel it is 9223372036854775807, which survives Python's json.loads() as an
# int but loses precision the moment JavaScript touches it, and a number the
# dashboard cannot represent honestly is better left out.
#
# WHY WATCH THIS AT ALL: a program that opens files or sockets and forgets to
# close them will exhaust the table and everything on the machine starts failing
# with "Too many open files" -- while CPU, RAM and disk all look perfectly fine.
read -r open_file_descriptors _ < /proc/sys/fs/file-nr


# =============================================================================
#  STEP 4 -- DISK: one gauge (how full) and two odometers (how busy)
# =============================================================================
#
# FULL AND BUSY ARE DIFFERENT FAILURES, and this project has to be able to tell
# them apart. A disk at 95% is a capacity problem that will not fix itself. A
# disk doing 200 MB/s of writes is a throughput problem that may be a backup job
# finishing in a minute. The gauge answers the first, the counters the second.
# -----------------------------------------------------------------------------

# --- the gauge: percentage used ---------------------------------------------
#   df    reports free space per mounted filesystem
#     -P  POSIX output format -- guarantees ONE LINE PER FILESYSTEM. Without it,
#         df wraps a long device name onto a second line and the field numbers
#         below would silently shift.
#     -k  report in 1K blocks, so the units cannot vary with the environment.
#     --  end of options, so a mount point starting with "-" is treated as a
#         path and not as a flag.
#   NR == 2   skip df's header row and take the filesystem's own line.
#   sub(/%$/, "", $5)  delete the trailing "%" from "47%", leaving a number.
#   $5 + 0    force numeric, so the JSON value is 47 and never "47".
disk_used_percent="$(df -P -k -- "$DISK_MOUNT" | awk 'NR == 2 { sub(/%$/, "", $5); print $5 + 0 }')"

# --- which block device is that filesystem on? ------------------------------
# Empty in the config means "work it out", so a moved or resized VM keeps
# working with no edit.
#   findmnt         queries the kernel's live mount table (part of util-linux,
#                   present on every Debian/Kali install).
#     -n            no header line
#     -o SOURCE     print only the source column -> "/dev/sda1"
#     --target DIR  look up the filesystem that DIR is on
#   CHOSEN OVER parsing /etc/fstab, which describes what SHOULD be mounted
#   rather than what IS, and over `df` again, whose output we would have to
#   re-parse for a value findmnt names directly.
#
# ${var##*/} then strips everything up to the last slash: /dev/sda1 -> sda1,
# because /proc/diskstats names devices the kernel's way, without the /dev/.
if [[ -n "$METRICS_DISK_DEVICE" ]]; then
    disk_device="$METRICS_DISK_DEVICE"
else
    disk_source="$(findmnt -n -o SOURCE --target "$DISK_MOUNT" 2>/dev/null)" || disk_source=""
    disk_device="${disk_source##*/}"
fi

# --- the odometers: sectors in, sectors out, milliseconds busy --------------
# /proc/diskstats gives one line per device:
#
#     8  1 sda1 16051 13375 3469572 16368 5502 6115 195418 1448 0 7220 17817
#     |  |  |     |     |      |       |     |    |     |     |  |   |
#     $1 $2 $3    $4    $5     $6      $7    $8   $9   $10  $11 $12 $13
#                reads merged SECTORS  ms  writes merged SECTORS ms  |  ms doing
#                 done        READ    read  done         WRITTEN     |    I/O
#
# A SECTOR IN THIS FILE IS ALWAYS 512 BYTES. That is a fixed unit of the
# /proc/diskstats interface, not the drive's physical sector size -- a modern 4K
# disk still reports here in 512-byte units. The multiplier is published in the
# output below so nobody has to remember this, and so a consumer converting to
# megabytes cannot pick the wrong constant.
#
# ms_doing_io is the third number and the most useful one: it is how long the
# device had at least one request in flight. Divided by the wall time between
# two samples it gives disk UTILISATION -- the "%util" column of iostat --
# which is what tells you a disk is saturated rather than merely busy.
#
# The empty defaults matter: if the device is not in the file (a LUKS mapper, an
# NFS mount, a name typed wrong in the config) these stay empty and the output
# is JSON null instead of a fabricated zero.
disk_read_sectors=""
disk_write_sectors=""
disk_io_ms=""
if [[ -n "$disk_device" ]]; then
    # $3 == want  -- exact match on the device NAME COLUMN. This is why awk is
    # used instead of `grep " sda1 "`: on a machine with sda1 and sda11, or with
    # a device whose name appears inside another line, a text search matches
    # things the column comparison cannot.
    # exit -- stop at the first match; there is exactly one line per device and
    # reading the remaining hundred lines of a busy machine is wasted work.
    disk_values="$(awk -v want="$disk_device" \
        '$3 == want { print $6, $10, $13; exit }' /proc/diskstats)"
    if [[ -n "$disk_values" ]]; then
        read -r disk_read_sectors disk_write_sectors disk_io_ms <<< "$disk_values"
    fi
fi


# =============================================================================
#  STEP 5 -- NETWORK ODOMETERS
# =============================================================================
#
# Which interface? The same question network.sh answers, answered the same way,
# so the two modules can never disagree about which NIC is "the" NIC.
#
#   ip route show default   prints only the route to 0.0.0.0/0:
#       default via 192.168.138.2 dev eth0 proto dhcp src 192.168.138.128
#   The interface that carries the default route is by definition the one
#   through which this machine reaches the world. CHOSEN OVER hard-coding
#   "eth0", which breaks on a laptop (wlan0) or on a Kali install that uses
#   predictable names (ens33). CHOSEN OVER `ifconfig`, which is deprecated,
#   comes from net-tools, and is not installed by default on modern Kali.
#
#   NR == 1     use only the first default route if several exist.
#   for (i...)  walk the words looking for the literal "dev" and print the word
#               AFTER it -- position-independent, so it still works when the
#               kernel adds or reorders the trailing attributes.
# -----------------------------------------------------------------------------
if [[ -n "$METRICS_INTERFACE" ]]; then
    interface_name="$METRICS_INTERFACE"
else
    # `|| default_route=""` because a machine with no default route is a valid
    # state we want to REPORT, not a crash. Without it, `set -e` would fire.
    default_route="$(ip route show default 2>/dev/null)" || default_route=""
    interface_name="$(awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "dev") print $(i + 1) }' <<< "$default_route")"
fi

net_rx_bytes=""
net_tx_bytes=""
net_rx_packets=""
net_tx_packets=""
net_rx_errors=""
net_tx_errors=""
if [[ -n "$interface_name" ]]; then
    # /proc/net/dev, two header lines then one line per interface:
    #
    #   eth0: 5932016 13988 0 0 0 0 0 0 8602772 12491 0 0 0 0 0 0
    #          bytes  pkts errs drop ...          bytes  pkts errs drop
    #          <------------ receive ----------> <------- transmit ------>
    #
    # Receive occupies EIGHT columns, so transmit bytes is field 2 + 8 = 10.
    #
    # sub(/:/, " ") replaces the colon with a space FIRST. This is not cosmetic:
    # the kernel pads the name to a fixed width, so on an interface with a long
    # name the colon ends up glued to the first number ("enp0s3:5932016") and
    # awk would see one field where we expect two. Detaching the colon makes the
    # parse correct for every interface name length.
    net_values="$(awk -v want="$interface_name" '
        { sub(/:/, " ") }
        $1 == want { print $2, $3, $4, $10, $11, $12; exit }
    ' /proc/net/dev)"
    if [[ -n "$net_values" ]]; then
        read -r net_rx_bytes net_rx_packets net_rx_errors \
                net_tx_bytes net_tx_packets net_tx_errors <<< "$net_values"
    fi
fi


# =============================================================================
#  STEP 6 -- WHAT THE MACHINE IS EXPOSING AND WHO IS ON IT  (security gauges)
# =============================================================================
#
# These three counts are cheap enough to sample every tick and are the numbers a
# security-minded operator watches for CHANGE rather than for level. Nobody
# cares that there are three listening sockets; everybody should care that there
# were three yesterday and there are nine now.
# -----------------------------------------------------------------------------

# LISTENING SOCKETS -- every door this machine is holding open.
#   ss     the modern socket statistics tool, from iproute2.
#     -H   no header line, so every line of output is data
#     -t   TCP
#     -u   UDP
#     -l   listening sockets only
#     -n   numeric: do NOT resolve port numbers to service names. Two reasons:
#          it avoids a lookup in /etc/services on every single line, and a
#          resolver that hangs would hang this sampler.
#   NOTE: no -p. Asking ss for the owning process would be useful, but it needs
#   root to see other users' sockets and would print "users:((...))" noise we
#   are not parsing here. The process attribution belongs in the dedicated
#   security module, where it can be done properly.
#   CHOSEN OVER `netstat -tuln`: netstat is deprecated, ships in net-tools which
#   is not installed on modern Kali, and is measurably slower because it parses
#   /proc/net/* text where ss asks the kernel over netlink.
#
# `|| listening_sockets=0` catches the case where ss is missing or refuses:
# under pipefail a failing first stage fails the whole pipeline.
listening_sockets="$(ss -H -tuln 2>/dev/null | awk 'NF > 0 { n++ } END { print n + 0 }')" || listening_sockets=0

# ESTABLISHED CONNECTIONS -- conversations actually in progress.
#   state established   ss's own filter, applied by the KERNEL. CHOSEN OVER
#                       piping everything to `grep ESTAB`, which would transfer
#                       and then discard every socket on a busy machine.
established_connections="$(ss -H -tn state established 2>/dev/null | awk 'NF > 0 { n++ } END { print n + 0 }')" || established_connections=0

# FAILED SYSTEMD UNITS -- the machine's own list of things that are broken.
# This is a whole-system view, unlike services.sh which checks the named few in
# MONITORED_SERVICES. A unit nobody thought to monitor failing at 3am is exactly
# the event a monitored-list-only design cannot see.
#   list-units --state=failed   ask systemd for its failed units
#     --no-legend   omit the "N loaded units listed" footer
#     --plain       omit the leading status bullet, so column 1 is the unit name
#     --no-pager    never invoke less. Without it, systemctl detects a terminal
#                   during a live demo and blocks forever waiting for a keypress
#                   while Flask's subprocess call times out.
failed_units="$(systemctl list-units --state=failed --no-legend --plain --no-pager 2>/dev/null | awk 'NF > 0 { n++ } END { print n + 0 }')" || failed_units=0

# LOGIN SESSIONS -- who is logged in right now, from the kernel's utmp record.
# Named "sessions" and not "users" on purpose: one person with three terminals
# open is three lines. Counting distinct usernames would hide a second login by
# the same account, which for a security signal is the wrong way to be wrong.
login_sessions="$(who 2>/dev/null | awk 'NF > 0 { n++ } END { print n + 0 }')" || login_sessions=0


# =============================================================================
#  STEP 7 -- TIMESTAMPS AND SELF-MEASUREMENT
# =============================================================================
#
# Two forms of the same instant, because they serve different readers:
#   %s  seconds since 1970-01-01 UTC. A plain integer -- this is the value that
#       becomes the primary key of the history table and the x-axis of a graph,
#       and it is what makes "how long since the previous sample" a subtraction.
#   the formatted string is for the human reading the page.
timestamp_epoch="$(date +%s)"
timestamp_human="$(date '+%Y-%m-%d %H:%M:%S')"

# HOW LONG DID THIS SAMPLE TAKE? Published as data, not as a comment, because
# the whole justification for this module is that it is cheap -- and a claim
# that a script is cheap should be verifiable by reading its output rather than
# by trusting its author. If a future change adds something slow, this number
# grows and the graph shows it.
sample_duration_ms="$(awk -v started="$sample_start" -v ended="$EPOCHREALTIME" \
    'BEGIN { printf "%.1f", (ended - started) * 1000 }')"


# =============================================================================
#  OUTPUT -- one JSON object, printed once, at the very end
# =============================================================================
#
# Nothing is printed until every value is collected. If a command had failed
# earlier, the ERR trap would have printed the error object and exited BEFORE
# reaching this point, so stdout can never contain half a document.
#
# THE SHAPE IS THE CONTRACT:
#   source    what was measured and in what units -- so a consumer converting
#             sectors to megabytes, or ticks to seconds, never has to guess.
#   gauges    values that are true on their own. Average them, plot them, alarm
#             on them.
#   counters  values that only go up. NEVER plot these raw; subtract the
#             previous sample first. Grouping them apart is a warning label.
#
# Quoting rule: strings are quoted, numbers are not. Every unquoted value below
# came from $(( )), from printf "%.1f"/"%.0f"/"%.2f", from awk's "+ 0", or
# straight from the kernel -- so each is a bare number, or the literal null when
# the reading could not be taken.
# =============================================================================
cat << EOF
{
  "module": "metrics",
  "status": "ok",
  "timestamp": $timestamp_epoch,
  "timestamp_human": "$timestamp_human",
  "sample_duration_ms": $sample_duration_ms,
  "source": {
    "interface": $(json_string "$interface_name"),
    "disk_device": $(json_string "$disk_device"),
    "disk_mount": $(json_string "$DISK_MOUNT"),
    "cpu_cores": $cpu_cores,
    "clock_ticks_per_second": $clock_ticks_per_second,
    "sector_bytes": 512
  },
  "gauges": {
    "memory_used_percent": $memory_used_percent,
    "swap_used_percent": $swap_used_percent,
    "swap_total_mb": $swap_total_mb,
    "disk_used_percent": $disk_used_percent,
    "load_1min": $load_1min,
    "load_5min": $load_5min,
    "load_15min": $load_15min,
    "load_per_core": $load_per_core,
    "processes_total": $processes_total,
    "processes_running": $processes_running,
    "processes_blocked": $processes_blocked,
    "processes_zombie": $processes_zombie,
    "open_file_descriptors": $open_file_descriptors,
    "failed_units": $failed_units,
    "listening_sockets": $listening_sockets,
    "established_connections": $established_connections,
    "login_sessions": $login_sessions
  },
  "counters": {
    "cpu_total_ticks": $cpu_total_ticks,
    "cpu_idle_ticks": $cpu_idle_ticks,
    "context_switches": $context_switches,
    "processes_forked": $processes_forked,
    "net_rx_bytes": $(json_number "$net_rx_bytes"),
    "net_tx_bytes": $(json_number "$net_tx_bytes"),
    "net_rx_packets": $(json_number "$net_rx_packets"),
    "net_tx_packets": $(json_number "$net_tx_packets"),
    "net_rx_errors": $(json_number "$net_rx_errors"),
    "net_tx_errors": $(json_number "$net_tx_errors"),
    "disk_read_sectors": $(json_number "$disk_read_sectors"),
    "disk_write_sectors": $(json_number "$disk_write_sectors"),
    "disk_io_ms": $(json_number "$disk_io_ms")
  }
}
EOF
