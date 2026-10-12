#!/usr/bin/env bash
# noportscan.sh - ipset + conntrack portscan tarpit.
# A source that opens NEW connections to >SCAN_BURST (default 15) distinct
# ports within the hashlimit window is added to port_scanners and dropped.
# Also drops classic stealth-scan TCP flag combos (NULL/FIN/XMAS/SYNFIN...).
#
# Usage:
#   ./noportscan.sh           install/refresh the rules
#   ./noportscan.sh --remove  remove the rules and destroy the ipsets

set -u

CHAIN="NOPORTSCAN"
SCANNERS_SET="port_scanners"
PORTS_SET="scanned_ports"
# distinct NEW ports/hour before tarpitting. Raise if legit users on this
# host use many services (mail alone can touch 25/143/465/587/993...).
SCAN_BURST="${SCAN_BURST:-15}"
BAN_SECONDS="${BAN_SECONDS:-600}"

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

IPT="iptables -w"

# ---------------------------------------------------------------- remove mode
if [ "${1:-}" = "--remove" ] || [ "${1:-}" = "--flush" ]; then
    $IPT -D INPUT -j "$CHAIN" 2>/dev/null
    $IPT -F "$CHAIN" 2>/dev/null
    $IPT -X "$CHAIN" 2>/dev/null
    ipset destroy "$SCANNERS_SET" 2>/dev/null
    ipset destroy "$PORTS_SET" 2>/dev/null
    echo "noportscan rules and ipsets removed."
    exit 0
fi

# ---------------------------------------------------------------- ipsets
ipset create "$SCANNERS_SET" hash:ip family inet hashsize 32768 maxelem 65536 timeout "$BAN_SECONDS" -exist
ipset create "$PORTS_SET" hash:ip,port family inet hashsize 32768 maxelem 65536 timeout 60 -exist

# ---------------------------------------------------------------- chain
$IPT -N "$CHAIN" 2>/dev/null || $IPT -F "$CHAIN"
# make sure INPUT jumps into our chain exactly once
$IPT -C INPUT -j "$CHAIN" 2>/dev/null || $IPT -A INPUT -j "$CHAIN"

# never tarpit loopback
$IPT -A "$CHAIN" -i lo -j RETURN

# invalid packets
$IPT -A "$CHAIN" -m conntrack --ctstate INVALID -j DROP

# stealth-scan TCP flag combos (only meaningful in NEW state)
for flags in "ALL NONE" "ALL ALL" "ALL FIN" "ALL SYN,FIN" "ALL SYN,RST" \
             "ALL FIN,RST" "ALL FIN,PSH" "ALL FIN,URG" "ALL FIN,PSH,URG" \
             "ALL ACK,FIN" "ALL ACK,PSH" "ALL ACK,URG"; do
    set -- $flags
    $IPT -A "$CHAIN" -p tcp --tcp-flags "$1" "$2" -m conntrack --ctstate NEW -j DROP
done

# count NEW connections to ports this source has NOT touched yet;
# >1/hour sustained (burst 5) -> add source to port_scanners
# (SET is a non-terminating target: the packet keeps traversing the chain)
for proto in tcp udp; do
    $IPT -A "$CHAIN" -p "$proto" -m conntrack --ctstate NEW \
        -m set ! --match-set "$PORTS_SET" src,dst \
        -m hashlimit --hashlimit-above 1/hour --hashlimit-burst "$SCAN_BURST" \
        --hashlimit-mode srcip --hashlimit-name "${CHAIN,,}_${proto}" \
        --hashlimit-htable-expire 10000 \
        -j SET --add-set "$SCANNERS_SET" src --exist
done

# known scanners (including the source just added above): drop everything
$IPT -A "$CHAIN" -m set --match-set "$SCANNERS_SET" src -j DROP

# remember the (src,dst port) pair so repeat visits don't count as scans
for proto in tcp udp; do
    $IPT -A "$CHAIN" -p "$proto" -m conntrack --ctstate NEW \
        -j SET --add-set "$PORTS_SET" src,dst --exist
done

echo "Portscan tarpit active in chain $CHAIN."
echo "  - >$SCAN_BURST distinct NEW ports/hour -> dropped for ${BAN_SECONDS}s"
echo "  - NULL/FIN/XMAS/SYNFIN flag scans -> dropped"
echo "Run '$0 --remove' to tear down."
