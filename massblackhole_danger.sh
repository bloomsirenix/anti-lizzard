#!/usr/bin/env bash
# massblackhole_danger.sh - block EVERY prefix announced by the ASNs in bad_asn.
# WARNING: this installs a huge number of iptables rules and may block
# legitimate providers (the ASN list includes large clouds and ISPs).

set -u

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

if ! command -v iptables >/dev/null 2>&1; then
    pkg_install iptables || { echo "Error: could not install iptables." >&2; exit 1; }
fi
if ! command -v whois >/dev/null 2>&1; then
    pkg_install whois || { echo "Error: could not install whois." >&2; exit 1; }
fi

IPT="iptables -w"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Input file: argument, or bad_asn / bad_asn.txt next to the script or in cwd
input_file="${1:-}"
if [ -z "$input_file" ]; then
    for cand in "$SCRIPT_DIR/bad_asn" "$SCRIPT_DIR/bad_asn.txt" "./bad_asn" "./bad_asn.txt"; do
        [ -f "$cand" ] && input_file="$cand" && break
    done
fi
if [ -z "$input_file" ] || [ ! -f "$input_file" ]; then
    echo "Error: ASN list file not found (looked for bad_asn / bad_asn.txt)." >&2
    exit 1
fi
echo "Using ASN list: $input_file"

# Use ipset when available - vastly faster than thousands of iptables rules
USE_IPSET=0
if command -v ipset >/dev/null 2>&1 || pkg_install ipset; then
    if ipset create massblackhole hash:net family inet hashsize 65536 maxelem 400000 -exist 2>/dev/null; then
        $IPT -C INPUT -m set --match-set massblackhole src -j DROP 2>/dev/null ||
            $IPT -A INPUT -m set --match-set massblackhole src -j DROP
        USE_IPSET=1
        echo "Using ipset 'massblackhole' (fast path)."
    fi
fi
[ "$USE_IPSET" -eq 0 ] && echo "ipset unavailable; falling back to individual iptables rules (slow!)."

get_ip_ranges() {
    whois -h whois.radb.net -- "-i origin $1" 2>/dev/null |
        grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}" | sort -u
}

while IFS= read -r asn; do
    asn="$(echo "${asn%%#*}" | tr -d '[:space:]')"
    case "$asn" in
        "" ) continue ;;
        AS[0-9]* ) ;;
        [0-9]* ) asn="AS$asn" ;;
        * ) echo "Skipping invalid line: $asn"; continue ;;
    esac
    echo "Processing ASN: $asn"
    get_ip_ranges "$asn" | while IFS= read -r ip_range; do
        if [ "$USE_IPSET" -eq 1 ]; then
            ipset add massblackhole "$ip_range" -exist
        else
            $IPT -C INPUT -s "$ip_range" -j DROP 2>/dev/null ||
                $IPT -A INPUT -s "$ip_range" -j DROP
        fi
    done
done < "$input_file"

echo "Ultimate Blackhole script completed."
echo "Note: rules are not persistent across reboots. Use 'ipset save' /"
echo "iptables-persistent or iptables-services to keep them."
