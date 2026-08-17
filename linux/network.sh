#!/bin/bash
# =============================================================================
#  Linux Guardian -- linux/network.sh         (Phase 1, module 2 of 4)
#
#  PURPOSE : Report this machine's network configuration and whether it can
#            actually reach the gateway, as ONE JSON object on standard output.
#
#  REPORTS : primary interface name, link state, MAC, IPv4 address, netmask,
#            default gateway, DNS servers, and live connectivity (packet loss
#            and latency).
#
#  KEY DESIGN DECISION -- WHAT WE PING
#            The target comes from PING_TARGET in guardian.conf, which is the
#            VMware NAT gateway (192.168.138.2), NOT 8.8.8.8. The whole project
#            must demonstrate correctly with the host laptop offline. The
#            gateway lives inside VMware's virtual network, so it answers with
#            no internet at all; 8.8.8.8 would show a red "DOWN" for a reason
#            that has nothing to do with this Linux VM.
#
#  SAFETY  : 100% READ-ONLY. It reads configuration and sends ICMP echo
#            requests. It never brings an interface up or down, never edits
#            /etc/resolv.conf, never changes a route.
# =============================================================================


# -----------------------------------------------------------------------------
# THE SAFETY SWITCHES -- identical to system.sh, and deliberately so.
# Every module in this project opens with the same six lines, so that when the
# professor asks "what does this script assume?", the answer is the same one
# every time.
#   -e  stop on the first command that fails
#   -u  stop if an unset variable is used (catches typos)
#   -o pipefail  a pipeline fails if ANY stage fails, not just the last
# -----------------------------------------------------------------------------
set -euo pipefail

# -E lets the ERR trap below fire inside functions and command substitutions
# too. Plain `set -e` does not inherit traps into them.
set -E

# Force the C/POSIX locale so printf and awk always write a decimal POINT.
# In a comma-decimal locale, an average latency of 0.214 ms would be printed
# "0,214", which is not a valid JSON number and would break Flask.
export LC_ALL=C


# -----------------------------------------------------------------------------
# LOCATE THE PROJECT (so the script works from any working directory)
#   ${BASH_SOURCE[0]}  the path of THIS file (reliable where $0 is not)
#   dirname            keep the directory, drop the filename
#   --                 "everything after this is a path, not an option"
#   cd .. && pwd       inside $( ) -- a subshell -- so the real script's
#                      directory is NOT changed; we only compute an absolute path
# systemd (Phase 4) starts scripts with the working directory set to "/", so a
# relative path such as config/guardian.conf would not exist there.
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname -- "$SCRIPT_DIR")"


# -----------------------------------------------------------------------------
# THE FAILURE CONTRACT
# Flask feeds this script's stdout straight into json.loads(). So even a crash
# must produce JSON. emit_error is the single exit door for real failures.
# (An unreachable gateway is NOT a failure -- it is a measurement result, and it
# is reported as reachable:false further down. Only a broken script comes here.)
# -----------------------------------------------------------------------------
emit_error() {
    printf '{"module":"network","status":"error","message":"%s"}\n' "$1"
    exit 1
}

# SINGLE quotes are required: they delay $LINENO until the trap actually fires,
# so the message names the line that really broke.
trap 'emit_error "network.sh failed at line $LINENO"' ERR


# -----------------------------------------------------------------------------
# JSON HELPERS
#
# JSON has no idea of "empty". When a value genuinely does not exist -- a VM
# with the virtual cable unplugged has no gateway at all -- the correct JSON is
# the literal `null`, which Python receives as None. Printing "" instead would
# be a lie: it would claim the gateway is the empty string.
#
# These two helpers keep that decision in ONE place instead of repeating an
# if/else at every field in the output block.
#
#   ${1:-}   expands to $1, or to nothing if $1 was not passed. The :- guard is
#            needed because `set -u` would otherwise abort on a missing argument.
#   -n / -z  test that a string is non-empty / empty.
#
# json_string also ESCAPES the two characters that can break out of a JSON
# string. The values it receives here -- interface names, IPv4 and MAC
# addresses -- are constrained by the kernel and cannot actually contain them,
# so this is belt-and-braces rather than strictly necessary. It is written this
# way so that EVERY module in the project has the identical helper: one
# function to explain once, with no "but this one is different" to defend.
#
#   ${var//pattern/replacement}   replace EVERY occurrence.
# ORDER MATTERS: backslashes first. Escaping the quotes first would then double
# the backslashes we had just added.
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
# LOAD THE CONFIGURATION
#   [[ -r FILE ]]  true if FILE exists and is readable
#   source         run the file in THIS shell so its variables survive.
#                  Running ./guardian.conf instead would start a child shell and
#                  every variable would die with it.
#   ${VAR:-value}  fall back to a sane default if a line was deleted from the
#                  config, instead of dying from `set -u`.
# -----------------------------------------------------------------------------
CONFIG_FILE="$PROJECT_ROOT/config/guardian.conf"
[[ -r "$CONFIG_FILE" ]] || emit_error "config file not found or not readable: $CONFIG_FILE"

export GUARDIAN_ROOT="$PROJECT_ROOT"
# shellcheck source=../config/guardian.conf
source "$CONFIG_FILE"

PING_TARGET="${PING_TARGET:-192.168.138.2}"
PING_COUNT="${PING_COUNT:-2}"
PING_TIMEOUT="${PING_TIMEOUT:-2}"


# =============================================================================
#  STEP 1 -- THE DEFAULT ROUTE: gateway + which interface is the primary one
# =============================================================================
#
# `ip route show default` prints only the routes to 0.0.0.0/0 -- the route
# packets take when no more specific route matches. On this VM:
#
#   default via 192.168.138.2 dev eth0 proto dhcp src 192.168.138.128 metric 100
#           ^^^^^^^^^^^^^^^^^     ^^^^
#           the gateway           the interface that reaches it
#
# This single line answers two questions at once: what the gateway is, and
# which of the machine's interfaces is the one that actually matters. That is
# why we start here instead of picking an interface by name: hard-coding "eth0"
# would break on a laptop where the interface is wlan0, or on a Kali install
# that uses the predictable name ens33.
#
# `ip` CHOSEN OVER `route -n` and `ifconfig`: those come from the net-tools
# package, which Debian (and therefore Kali) deprecated years ago in favour of
# iproute2. net-tools is not guaranteed to be installed, and ifconfig cannot
# display several addresses on one interface. `ip` is the current, supported
# tool and it is part of the base system.
# -----------------------------------------------------------------------------
default_route="$(ip route show default)"

# WHY A KEYWORD SEARCH INSTEAD OF COUNTING COLUMNS:
# the fields after "default" vary -- proto, src, metric and onlink appear or
# disappear depending on how the address was obtained. Writing $3 for the
# gateway would be a guess that breaks on a static IP. Instead we walk the
# fields and read the word that FOLLOWS the keyword, which is stable.
#
#   NF          awk's "Number of Fields" on the current line
#   $(i + 1)    the field after field i
#   NR == 1     only the first line (there can be several default routes with
#               different metrics; the first one printed is the preferred one)
#   <<< "$var"  a "here-string": feeds the contents of a variable to a command
#               as its standard input. Chosen over `echo "$var" | awk` because
#               it starts one process instead of two.
#
# If there is no default route at all, awk prints nothing and the variable ends
# up empty -- which json_string later turns into JSON null. That is a real,
# reportable state, not a crash.
gateway_ip="$(awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "via") print $(i + 1) }' <<< "$default_route")"
interface_name="$(awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "dev") print $(i + 1) }' <<< "$default_route")"

# FALLBACK: if the virtual cable is unplugged there is no default route, so the
# loop above found no "dev". We still want to report on the machine's real NIC,
# so we take the first interface that is not the loopback.
#
#   ip -o link show   -o = "oneline": force one record per line. Without it,
#                     each interface spans two indented lines and awk's
#                     line-based model becomes awkward.
#   -F': '            use ": " as the field separator, so for the record
#                     "2: eth0: <BROADCAST,...>" field 2 is exactly "eth0".
#   exit              stop after the first match -- we want one interface.
if [[ -z "$interface_name" ]]; then
    link_list="$(ip -o link show)"
    interface_name="$(awk -F': ' '$2 != "lo" { print $2; exit }' <<< "$link_list")"
fi


# =============================================================================
#  STEP 2 -- INTERFACE DETAILS: link state, MAC, IPv4 address, netmask
# =============================================================================

# Declared empty first. If the interface disappears between step 1 and here,
# every field stays empty and becomes JSON null instead of an undefined
# variable, which `set -u` would treat as a fatal error.
interface_state=""
mac_address=""
ip_address=""
prefix_length=""
netmask=""

# -d tests that the path exists AND is a directory. /sys/class/net/<name>/ is
# the kernel's live view of that interface, so this is also the cheapest
# possible "does this interface exist?" check.
if [[ -n "$interface_name" && -d "/sys/class/net/$interface_name" ]]; then

    # /sys is a virtual filesystem the kernel generates in memory: reading these
    # files asks the driver directly.
    #   operstate -> "up", "down", "unknown"  (RFC 2863 operational state)
    #   address   -> the MAC / hardware address
    # `read -r VAR < file` is a Bash BUILTIN: it starts no external process at
    # all, unlike `cat file` which forks a program to copy 3 bytes.
    read -r interface_state < "/sys/class/net/$interface_name/operstate"
    read -r mac_address     < "/sys/class/net/$interface_name/address"

    # `ip -o -4 addr show dev eth0` prints the addresses of one interface:
    #   2: eth0    inet 192.168.138.128/24 brd 192.168.138.255 scope global ...
    #   -o   one record per line (see above)
    #   -4   IPv4 only. Without it we would also get the IPv6 "inet6" lines and
    #        would have to filter them out. This project reports IPv4 because
    #        that is what the VMware NAT network hands out.
    #   dev  restrict to this one interface
    address_line="$(ip -o -4 addr show dev "$interface_name")"

    # Same keyword-search technique: take the word after "inet".
    # `exit` after the first hit because an interface can hold several
    # addresses; the first is the primary one.
    cidr="$(awk '{ for (i = 1; i <= NF; i++) if ($i == "inet") { print $(i + 1); exit } }' <<< "$address_line")"

    if [[ -n "$cidr" ]]; then
        # $cidr is "192.168.138.128/24" -- CIDR notation: address / how many
        # leading bits of the 32-bit address identify the NETWORK.
        # Bash parameter expansion splits it with no external process:
        #   ${cidr%%/*}  delete the LONGEST match of "/*" from the END  -> address
        #   ${cidr##*/}  delete the LONGEST match of "*/" from the START -> prefix
        ip_address="${cidr%%/*}"
        prefix_length="${cidr##*/}"

        # Convert the prefix length into the familiar dotted netmask.
        # A /24 means "the first 24 bits are ones": 11111111 11111111 11111111 00000000
        # We build that in one arithmetic expansion, $(( )):
        #   1 << (32 - 24)      = 2^8   = 256          (a 1 in bit position 8)
        #   256 - 1             = 255                  (the 8 HOST bits, all ones)
        #   0xFFFFFFFF ^ 255    = flip those off       (^ is bitwise XOR)
        # Then >> shifts each byte down into place and & 255 keeps just that byte.
        # CHOSEN OVER a lookup table of 33 hard-coded netmasks: the arithmetic is
        # three lines, is always right, and shows what a netmask actually IS.
        mask_int=$(( 0xFFFFFFFF ^ ((1 << (32 - prefix_length)) - 1) ))
        netmask="$(( (mask_int >> 24) & 255 )).$(( (mask_int >> 16) & 255 )).$(( (mask_int >> 8) & 255 )).$(( mask_int & 255 ))"
    fi
fi


# =============================================================================
#  STEP 3 -- DNS SERVERS
# =============================================================================
#
# /etc/resolv.conf is the standard file every Linux resolver library reads.
# On this VM NetworkManager writes it from the DHCP lease:
#
#   # Generated by NetworkManager
#   search localdomain
#   nameserver 192.168.138.2
#
# A machine may legitimately list several nameservers, so this must produce a
# JSON ARRAY, not a single string.
#
# CHOSEN OVER `resolvectl status`: that only works when systemd-resolved is the
# active resolver. Kali uses NetworkManager writing resolv.conf directly, so
# resolvectl would fail here. Reading the file works in both designs.
# -----------------------------------------------------------------------------

# ( ) creates an empty Bash ARRAY -- an ordered list, unlike a plain variable.
dns_servers=()

if [[ -r /etc/resolv.conf ]]; then
    # `while read ... done < file` reads the file line by line.
    #   read -r keyword value _   splits each line into: first word, second
    #                             word, and _ swallowing whatever is left.
    #   Lines that are comments ("#") or options ("search") simply do not match
    #   the test below and are skipped -- no grep needed.
    # WHY NOT `grep nameserver`: grep would also match a COMMENTED-OUT line such
    # as "#nameserver 8.8.8.8". Testing that the first word is exactly
    # "nameserver" cannot make that mistake.
    while read -r keyword value _; do
        if [[ "$keyword" == "nameserver" ]]; then
            # += appends one element to the array.
            dns_servers+=("$value")
        fi
    done < /etc/resolv.conf
fi

# Build the JSON array by hand: ["192.168.138.2", "192.168.138.3"]
#   ${!array[@]}   the list of INDEXES of the array (0, 1, 2 ...). The "!" means
#                  "give me the keys, not the values".
#   ${#array[@]}   the NUMBER of elements.
#   +=             append to a string.
# The `if (( index > 0 ))` puts a comma BETWEEN elements but never after the
# last one -- a trailing comma is the most common way of writing invalid JSON.
# An empty array correctly produces "[]", because the loop body never runs.
dns_json="["
for index in "${!dns_servers[@]}"; do
    if (( index > 0 )); then
        dns_json+=", "
    fi
    dns_json+="\"${dns_servers[index]}\""
done
dns_json+="]"

dns_server_count="${#dns_servers[@]}"


# =============================================================================
#  STEP 4 -- CONNECTIVITY TEST
# =============================================================================
#
# ping sends ICMP echo requests and counts the replies.
#
#   -c COUNT    send exactly COUNT packets, then stop. PING_COUNT is 2 rather
#               than 1 so that a single dropped packet does not raise a false
#               "network down" alarm.
#   -W TIMEOUT  seconds to wait for a reply before declaring that packet lost.
#   -n          NUMERIC output only: never do a reverse DNS lookup on the
#               address. THIS FLAG MATTERS MORE THAN IT LOOKS: if DNS is the
#               thing that is broken, a reverse lookup would make ping hang for
#               several seconds and the web page would appear frozen. We are
#               testing the network, so we must not depend on DNS to do it.
#   -q          QUIET: print only the opening line and the final summary,
#               not one line per packet. Less text to parse, fewer ways to
#               misparse it.
#
# WHY NOT -w (deadline): tested on this machine, combining -w with -c makes ping
# ignore the count and keep sending until the deadline -- it transmitted 4
# packets for `-c 2 -w 4`. With -c and -W alone the behaviour is exact and
# bounded: the worst case is (COUNT - 1) x 1 s between packets + TIMEOUT,
# i.e. 3 seconds, measured.
#
# WHY ping AND NOT `curl` / `nc`: ICMP echo needs no service listening on the
# target. A gateway does not run a web server, so curl would report failure on
# a perfectly healthy network. ping tests the network layer itself.
#
# ROOT IS NOT NEEDED: the kernel setting net.ipv4.ping_group_range covers this
# user's group, so ping opens an unprivileged ICMP datagram socket. This is why
# the whole dashboard can run without sudo.
# -----------------------------------------------------------------------------

# ping exits 1 when nothing replies -- and with `set -e` that would kill the
# script. But "the gateway did not answer" is exactly the RESULT we are trying
# to measure, not a bug. So we catch that status deliberately:
#   cmd || variable=$?   the "|| ..." makes the whole line succeed, satisfying
#                        set -e, while $? preserves ping's real exit status.
#   2>&1                 send ping's error messages into the same variable, so
#                        they can never leak onto stdout and corrupt our JSON.
ping_exit_code=0
ping_output="$(ping -n -q -c "$PING_COUNT" -W "$PING_TIMEOUT" "$PING_TARGET" 2>&1)" || ping_exit_code=$?

# The summary we have to read looks like this when it works:
#   2 packets transmitted, 2 received, 0% packet loss, time 1023ms
#   rtt min/avg/max/mdev = 0.180/0.214/0.249/0.034 ms
# and like this when it does not (note: NO rtt line at all):
#   2 packets transmitted, 0 received, 100% packet loss, time 1024ms
#
# The loss percentage is found by SEARCHING for the field ending in "%", not by
# its column number, because ping inserts an extra "+3 errors" field when it
# receives ICMP errors, which shifts everything after it.
#
#   $i ~ /%$/        regular-expression match: field i ends with "%"
#   sub(/%$/, "", x) delete that trailing "%" so the value is a plain number
#   split($4, rtt, "/")  cut "0.180/0.214/0.249/0.034" on "/" into an array;
#                        element 2 is the average
#   END { }          runs once after all lines, so it prints exactly one result
#   uninitialised awk variables are empty, and "%d" prints them as 0
ping_stats="$(awk '
    /packets transmitted/ {
        transmitted = $1
        received    = $4
        for (i = 1; i <= NF; i++) {
            if ($i ~ /%$/) { loss = $i; sub(/%$/, "", loss) }
        }
    }
    /min\/avg\/max/ {
        split($4, rtt, "/")
        average = rtt[2]
    }
    END {
        # If ping never even sent a packet (unknown host, no permission) the
        # honest report is total loss, not 0%.
        if (transmitted == 0) { loss = 100 }
        printf "%d %d %d %s", transmitted, received, loss, (average == "" ? "null" : average)
    }' <<< "$ping_output")"
read -r packets_transmitted packets_received packet_loss_percent average_latency_ms <<< "$ping_stats"

# JSON booleans are the bare words true and false -- NOT the strings "true" and
# "false". Written unquoted in the output block below, so Python receives a real
# bool and Jinja2 can say {% if data.connectivity.reachable %} directly.
#
# We judge reachability on packets RECEIVED rather than on ping's exit status,
# because 1 of 2 packets returning still means the gateway is alive, just lossy.
if (( packets_received > 0 )); then
    connectivity_reachable="true"
else
    connectivity_reachable="false"
fi


# =============================================================================
#  TIMESTAMP
# =============================================================================
#   %s  seconds since 1970-01-01 UTC -- a plain integer, easy to sort and to
#       subtract when Phase 5 asks "how old is this reading?"
# The second form is the one a human reads on the web page.
timestamp_epoch="$(date +%s)"
timestamp_human="$(date '+%Y-%m-%d %H:%M:%S')"


# =============================================================================
#  OUTPUT -- one JSON object, printed once, at the very end
# =============================================================================
#
# Nothing has been printed until this point. Every value was collected first,
# so if anything had failed, the ERR trap would have printed the error object
# and exited BEFORE this block ran. stdout therefore holds either one complete
# valid document or one complete error document -- never half of either.
#
# QUOTING RULES, the detail that decides whether Phase 5 works:
#   strings   -> in double quotes, or `null` when absent  -> json_string
#   numbers   -> bare, or `null` when absent              -> json_number
#   booleans  -> bare true / false
#   arrays    -> [ ... ]  ($dns_json, already assembled above)
# =============================================================================
cat << EOF
{
  "module": "network",
  "status": "ok",
  "timestamp": $timestamp_epoch,
  "timestamp_human": "$timestamp_human",
  "interface": {
    "name": $(json_string "$interface_name"),
    "state": $(json_string "$interface_state"),
    "mac_address": $(json_string "$mac_address"),
    "ip_address": $(json_string "$ip_address"),
    "prefix_length": $(json_number "$prefix_length"),
    "netmask": $(json_string "$netmask")
  },
  "gateway": $(json_string "$gateway_ip"),
  "dns_servers": $dns_json,
  "dns_server_count": $dns_server_count,
  "connectivity": {
    "target": "$PING_TARGET",
    "reachable": $connectivity_reachable,
    "packets_transmitted": $packets_transmitted,
    "packets_received": $packets_received,
    "packet_loss_percent": $packet_loss_percent,
    "avg_latency_ms": $average_latency_ms,
    "ping_exit_code": $ping_exit_code
  }
}
EOF
