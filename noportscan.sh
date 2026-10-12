#!/usr/bin/env bash
# noportscan.sh - ipset + conntrack portscan tarpit.
#
# A source that opens NEW connections to >SCAN_BURST (default 15) distinct
# ports within the hashlimit window is added to the port_scanners ipset and
# all further packets from it are dropped. Also drops classic stealth-scan
# TCP flag combos (NULL/FIN/XMAS/SYNFIN...).
#
# Plays nice with ufw and pre-existing iptables rules:
#   * NOPORTSCAN       - enforcement chain, inserted at the TOP of INPUT so
#                        banned sources are dropped before ufw or any other
#                        rule can accept them.
#   * NOPORTSCAN-COUNT - accounting chain, appended to the END of INPUT so
#                        only traffic no earlier rule claimed (i.e. not
#                        allowed by ufw/iptables) is counted. Legit traffic
#                        to allowed ports can never trip the tarpit.
#   * nothing outside these two chains is flushed or modified.
#
# If ufw is installed, a hook is added to /etc/ufw/after.init so the rules
# are re-applied after 'ufw reload', 'ufw enable' and at boot.
# IPv6 is handled too when ip6tables is available.
#
# Usage:
#   ./noportscan.sh           install/refresh the rules
#   ./noportscan.sh --remove  remove the rules, the ufw hook and the ipsets
#
# Tunables (env): SCAN_BURST, BAN_SECONDS

set -u

CHAIN="NOPORTSCAN"
CCHAIN="NOPORTSCAN-COUNT"
SCANNERS_SET="port_scanners"
PORTS_SET="scanned_ports"
# distinct NEW ports/hour before tarpitting. Raise if legit users on this
# host use many services (mail alone can touch 25/143/465/587/993...).
SCAN_BURST="${SCAN_BURST:-15}"
BAN_SECONDS="${BAN_SECONDS:-600}"
# local/private sources are never counted or tarpitted
# (127/8 intentionally absent - loopback-only, already covered by -i lo)
LOCAL_NETS_V4="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10"
LOCAL_NETS_V6="::1/128 fc00::/7 fe80::/10"
AFTER_INIT="/etc/ufw/after.init"
MARK_BEGIN="# >>> noportscan.sh >>>"
MARK_END="# <<< noportscan.sh <<<"

# Re-exec as root if needed
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo bash "$0" "$@"
    fi
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

pkg_install() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y "$@"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y "$@"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "$@"
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install "$@"
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm "$@"
    elif command -v apk >/dev/null 2>&1; then
        apk add "$@"
    else
        return 1
    fi
}

if ! command -v ipset >/dev/null 2>&1; then
    echo "ipset not found, attempting to install..."
    pkg_install ipset || { echo "Error: could not install ipset." >&2; exit 1; }
fi
if ! command -v iptables >/dev/null 2>&1; then
    echo "iptables not found, attempting to install..."
    pkg_install iptables || { echo "Error: could not install iptables." >&2; exit 1; }
fi

ipt()  { iptables -w "$@"; }
HAVE6=0
if command -v ip6tables >/dev/null 2>&1; then
    HAVE6=1
    ip6t() { ip6tables -w "$@"; }
else
    ip6t() { return 1; }
fi

SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"

# remove every jump from INPUT into chain $2 via tool $1 (ipt/ip6t)
unhook() {
    while "$1" -C INPUT -j "$2" 2>/dev/null; do
        "$1" -D INPUT -j "$2"
    done
}

hook_ufw() {
    [ "${NOPORTSCAN_NO_HOOK:-0}" = "1" ] && return 0
    command -v ufw >/dev/null 2>&1 || return 0
    if [ ! -e "$AFTER_INIT" ]; then
        printf '#!/bin/sh\n' > "$AFTER_INIT" 2>/dev/null || {
            echo "Warning: cannot write $AFTER_INIT; rules won't survive 'ufw reload'." >&2
            return 0
        }
    fi
    chmod +x "$AFTER_INIT" 2>/dev/null
    grep -qF "$MARK_BEGIN" "$AFTER_INIT" 2>/dev/null && return 0
    printf '%s\nNOPORTSCAN_NO_HOOK=1 "%s" >/dev/null 2>&1 || true\n%s\n' \
        "$MARK_BEGIN" "$SCRIPT_PATH" "$MARK_END" >> "$AFTER_INIT"
    echo "ufw detected: re-apply hook added to $AFTER_INIT"
}

unhook_ufw() {
    [ -f "$AFTER_INIT" ] || return 0
    sed -i '/>>> noportscan\.sh >>>/,/<<< noportscan\.sh <<</d' "$AFTER_INIT" 2>/dev/null
}

# ---------------------------------------------------------------- remove mode
if [ "${1:-}" = "--remove" ] || [ "${1:-}" = "--flush" ]; then
    for t in ipt ip6t; do
        unhook "$t" "$CHAIN"
        unhook "$t" "$CCHAIN"
        "$t" -F "$CHAIN"  2>/dev/null
        "$t" -X "$CHAIN"  2>/dev/null
        "$t" -F "$CCHAIN" 2>/dev/null
        "$t" -X "$CCHAIN" 2>/dev/null
    done
    for s in "$SCANNERS_SET" "${SCANNERS_SET}6" "$PORTS_SET" "${PORTS_SET}6"; do
        ipset destroy "$s" 2>/dev/null
    done
    unhook_ufw
    echo "noportscan rules, ufw hook and ipsets removed."
    exit 0
fi

# ---------------------------------------------------------------- ipsets
ipset create "$SCANNERS_SET" hash:ip family inet hashsize 32768 maxelem 65536 timeout "$BAN_SECONDS" -exist
ipset create "$PORTS_SET" hash:ip,port family inet hashsize 32768 maxelem 65536 timeout 60 -exist
if [ "$HAVE6" = "1" ]; then
    ipset create "${SCANNERS_SET}6" hash:ip family inet6 hashsize 32768 maxelem 65536 timeout "$BAN_SECONDS" -exist
    ipset create "${PORTS_SET}6" hash:ip,port family inet6 hashsize 32768 maxelem 65536 timeout 60 -exist
fi

# ---------------------------------------------------------------- chains
# $1=tool (ipt/ip6t)  $2=scanners ipset  $3=local nets to exempt
build_enforce() {
    local T="$1" SSET="$2" NETS="$3"
    "$T" -N "$CHAIN" 2>/dev/null || "$T" -F "$CHAIN"
    # always (re)insert at position 1 so a ufw reload or a previous version
    # of this script can't leave the hook stranded at the bottom of INPUT
    unhook "$T" "$CHAIN"
    "$T" -I INPUT 1 -j "$CHAIN"

    # never tarpit loopback or local/private sources
    "$T" -A "$CHAIN" -i lo -j RETURN
    local net
    for net in $NETS; do
        "$T" -A "$CHAIN" -s "$net" -j RETURN
    done

    # invalid packets
    "$T" -A "$CHAIN" -m conntrack --ctstate INVALID -j DROP

    # stealth-scan TCP flag combos (only meaningful in NEW state)
    local flags
    for flags in "ALL NONE" "ALL ALL" "ALL FIN" "ALL SYN,FIN" "ALL SYN,RST" \
                 "ALL FIN,RST" "ALL FIN,PSH" "ALL FIN,URG" "ALL FIN,PSH,URG" \
                 "ALL ACK,FIN" "ALL ACK,PSH" "ALL ACK,URG"; do
        set -- $flags
        "$T" -A "$CHAIN" -p tcp --tcp-flags "$1" "$2" -m conntrack --ctstate NEW -j DROP
    done

    # known scanners: drop everything, before ufw/iptables can accept it
    "$T" -A "$CHAIN" -m set --match-set "$SSET" src -j DROP
}

# $1=tool  $2=scanners ipset  $3=ports ipset  $4=family tag  $5=local nets
build_count() {
    local T="$1" SSET="$2" PSET="$3" TAG="$4" NETS="$5"
    "$T" -N "$CCHAIN" 2>/dev/null || "$T" -F "$CCHAIN"
    # appended last: only packets not already accepted/rejected by earlier
    # rules (ufw included) are counted as scan attempts
    unhook "$T" "$CCHAIN"
    "$T" -A INPUT -j "$CCHAIN"

    "$T" -A "$CCHAIN" -i lo -j RETURN
    local net
    for net in $NETS; do
        "$T" -A "$CCHAIN" -s "$net" -j RETURN
    done

    local proto
    for proto in tcp udp; do
        # count NEW connections to ports this source has NOT touched yet;
        # >1/hour sustained (burst SCAN_BURST) -> add src to scanners set
        # (SET is a non-terminating target: the packet keeps traversing)
        "$T" -A "$CCHAIN" -p "$proto" -m conntrack --ctstate NEW \
            -m set ! --match-set "$PSET" src,dst \
            -m hashlimit --hashlimit-above 1/hour --hashlimit-burst "$SCAN_BURST" \
            --hashlimit-mode srcip --hashlimit-name "noportscan_${TAG}_${proto}" \
            --hashlimit-htable-expire 10000 \
            -j SET --add-set "$SSET" src --exist

        # remember the (src,dst port) pair so repeat visits don't count
        "$T" -A "$CCHAIN" -p "$proto" -m conntrack --ctstate NEW \
            -j SET --add-set "$PSET" src,dst --exist
    done
}

build_enforce ipt "$SCANNERS_SET" "$LOCAL_NETS_V4"
build_count   ipt "$SCANNERS_SET" "$PORTS_SET" v4 "$LOCAL_NETS_V4"
if [ "$HAVE6" = "1" ]; then
    build_enforce ip6t "${SCANNERS_SET}6" "$LOCAL_NETS_V6"
    build_count   ip6t "${SCANNERS_SET}6" "${PORTS_SET}6" v6 "$LOCAL_NETS_V6"
fi

hook_ufw

echo "Portscan tarpit active."
echo "  - enforcement chain $CHAIN at top of INPUT (before ufw/other rules)"
echo "  - accounting chain $CCHAIN at end of INPUT (only unclaimed traffic counts)"
[ "$HAVE6" = "1" ] && echo "  - IPv6 enabled via ip6tables"
echo "  - >$SCAN_BURST distinct NEW ports/hour -> dropped for ${BAN_SECONDS}s"
echo "  - NULL/FIN/XMAS/SYNFIN flag scans -> dropped"
echo "Run '$0 --remove' to tear down."
