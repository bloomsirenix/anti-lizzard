#!/usr/bin/env bash
# tinyblackhole.sh - drop known-bad IP ranges and IPs via iptables.
# Works on Debian/Ubuntu and other distros (iptables or iptables-nft).

set -u

# Re-exec as root if needed
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo bash "$0" "$@"
    fi
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

# Install a package using whatever package manager exists
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

# Ensure iptables is available
if ! command -v iptables >/dev/null 2>&1; then
    echo "iptables not found, attempting to install..."
    pkg_install iptables || {
        echo "Error: could not install iptables. Install it manually." >&2
        exit 1
    }
fi

# -w: wait for the xtables lock instead of failing when the firewall is busy
IPT="iptables -w"
# -C is not supported by very old iptables; fall back to always-appending
if $IPT -C INPUT -s 127.0.0.1 -j DROP 2>/dev/null; then
    $IPT -D INPUT -s 127.0.0.1 -j DROP
    HAVE_CHECK=1
else
    HAVE_CHECK=0
fi

drop() {
    # drop <cidr>
    if [ "$HAVE_CHECK" -eq 1 ]; then
        $IPT -C INPUT  -s "$1" -j DROP 2>/dev/null || $IPT -A INPUT  -s "$1" -j DROP
        $IPT -C OUTPUT -d "$1" -j DROP 2>/dev/null || $IPT -A OUTPUT -d "$1" -j DROP
    else
        $IPT -A INPUT  -s "$1" -j DROP
        $IPT -A OUTPUT -d "$1" -j DROP
    fi
}

# Define IP ranges to block
IP_RANGES="5.136.0.0/13 95.24.0.0/13 176.208.0.0/13 178.64.0.0/13 10.0.0.0/12 172.16.0.0/12 192.168.0.0/16 45.93.20.0/24 62.122.184.0/24 62.233.50.0/24 85.209.11.0/24 87.247.158.0/23 5.116.81.51 91.213.138.0/24 91.240.118.0/24 91.241.19.0/24 152.89.196.0/24 152.89.198.0/24 176.111.174.0/24 185.11.61.0/24 185.81.68.0/24 185.122.204.0/24 185.198.69.0/24 185.234.216.0/24 188.119.66.0/24 194.26.135.0/24 195.226.194.0/24 109.205.211.0/24 79.124.62.0/24"

# Additional IPs to block
IPS_TO_BLOCK=(
    101.35.56.189
    102.220.23.35
    104.250.50.111
    111.229.125.161
    113.125.180.33
    114.132.54.160
    120.48.122.45
    120.89.98.71
    121.138.128.233
    121.4.89.191
    14.99.254.18
    161.132.38.125
    175.178.120.91
    177.43.233.9
    180.184.51.141
    183.98.51.177
    201.184.43.91
    211.168.48.165
    31.216.62.97
    34.86.20.159
    36.67.197.52
    43.134.202.235
    43.153.213.247
    43.153.48.160
    43.153.57.158
    62.234.119.96
    65.181.73.155
    79.104.0.82
)

# Optionally merge in extra IPs from the repo lists if present
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for f in "know baddies.txt" full_noughtylist.txt; do
    if [ -f "$SCRIPT_DIR/$f" ]; then
        while IFS= read -r line; do
            line="${line%%#*}"
            line="$(echo "$line" | tr -d '[:space:]')"
            [ -n "$line" ] && IPS_TO_BLOCK+=("$line")
        done < "$SCRIPT_DIR/$f"
    fi
done

for IP_RANGE in $IP_RANGES; do
    drop "$IP_RANGE"
done

for IP in "${IPS_TO_BLOCK[@]}"; do
    drop "$IP"
done

echo "Firewalls configured to block specified IP ranges and individual IPs using iptables."
echo "Note: these rules are not persistent. Install iptables-persistent (Debian) or"
echo "iptables-services (Fedora/RHEL) to survive reboots."
