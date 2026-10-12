#!/usr/bin/env bash
# tinyblackhole.sh - drop known-bad IP ranges and IPs.
# Prefers ufw when available (rules then persist across reboots
# automatically); falls back to raw iptables otherwise.
# Leftover rules from the old iptables-only version are removed
# automatically when ufw is active.

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

# Prefer ufw when available (its rules persist across reboots by itself)
USE_UFW=0
UFW_ACTIVE=0
if ! command -v ufw >/dev/null 2>&1; then
    pkg_install ufw >/dev/null 2>&1 || true
fi
if command -v ufw >/dev/null 2>&1; then
    USE_UFW=1
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        UFW_ACTIVE=1
    else
        echo "Warning: ufw is installed but not active - rules are recorded"
        echo "but won't be enforced until 'ufw enable'."
    fi
fi

# iptables is still needed for the fallback path and for cleaning up rules
# left by the old iptables-only version
if ! command -v iptables >/dev/null 2>&1; then
    if [ "$USE_UFW" -eq 0 ]; then
        echo "iptables not found, attempting to install..."
        pkg_install iptables || {
            echo "Error: could not install iptables. Install it manually." >&2
            exit 1
        }
    fi
fi

IPT="iptables -w"
HAVE_CHECK=0
if command -v iptables >/dev/null 2>&1 && $IPT -C INPUT -s 127.0.0.1 -j DROP 2>/dev/null; then
    $IPT -D INPUT -s 127.0.0.1 -j DROP
    HAVE_CHECK=1
fi

ip2int() {
    local IFS=.
    read -r a b c d <<< "$1"
    echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

# does CIDR $1 overlap any local/private range?
overlaps_local() {
    local ip=${1%/*} mask=${1#*/}
    [ "$mask" = "$ip" ] && mask=32
    local i m net ni nm
    i=$(ip2int "$ip")
    m=$(( (0xFFFFFFFF << (32 - mask)) & 0xFFFFFFFF ))
    for net in $LOCAL_NETS; do
        ni=$(ip2int "${net%/*}")
        nm=$(( (0xFFFFFFFF << (32 - ${net#*/})) & 0xFFFFFFFF ))
        if [ $(( i & nm )) -eq $(( ni & nm )) ] || [ $(( ni & m )) -eq $(( i & m )) ]; then
            return 0
        fi
    done
    return 1
}

# delete every deny/drop rule covering local nets (old versions blocked
# private ranges!), then install top-priority allows so nothing can
# re-block them. Runs AFTER the block loop so the allows sit on top.
whitelist_locals() {
    local net
    for net in $OLD_BLOCKS $LOCAL_NETS; do
        if [ "$USE_UFW" -eq 1 ]; then
            ufw delete deny from "$net" to any >/dev/null 2>&1
            ufw delete deny out to "$net" >/dev/null 2>&1
        fi
        if command -v iptables >/dev/null 2>&1; then
            while $IPT -C INPUT  -s "$net" -j DROP 2>/dev/null; do
                $IPT -D INPUT  -s "$net" -j DROP
            done
            while $IPT -C OUTPUT -d "$net" -j DROP 2>/dev/null; do
                $IPT -D OUTPUT -d "$net" -j DROP
            done
        fi
    done
    for net in $LOCAL_NETS; do
        if [ "$USE_UFW" -eq 1 ]; then
            ufw insert 1 allow from "$net" to any >/dev/null
            ufw insert 1 allow out to "$net" >/dev/null
        else
            $IPT -C INPUT  -s "$net" -j ACCEPT 2>/dev/null || $IPT -I INPUT 1  -s "$net" -j ACCEPT
            $IPT -C OUTPUT -d "$net" -j ACCEPT 2>/dev/null || $IPT -I OUTPUT 1 -d "$net" -j ACCEPT
        fi
    done
}

drop() {
    # drop <cidr>
    if overlaps_local "$1"; then
        echo "Skipping local/private address $1"
        return 0
    fi
    if [ "$USE_UFW" -eq 1 ]; then
        # insert at position 1 so the deny wins over earlier 'allow' rules
        ufw insert 1 deny from "$1" to any >/dev/null
        ufw insert 1 deny out to "$1" >/dev/null
        # migrate rules installed by the old iptables-only version
        if [ "$UFW_ACTIVE" -eq 1 ] && command -v iptables >/dev/null 2>&1; then
            while $IPT -C INPUT  -s "$1" -j DROP 2>/dev/null; do
                $IPT -D INPUT  -s "$1" -j DROP
            done
            while $IPT -C OUTPUT -d "$1" -j DROP 2>/dev/null; do
                $IPT -D OUTPUT -d "$1" -j DROP
            done
        fi
    elif [ "$HAVE_CHECK" -eq 1 ]; then
        $IPT -C INPUT  -s "$1" -j DROP 2>/dev/null || $IPT -A INPUT  -s "$1" -j DROP
        $IPT -C OUTPUT -d "$1" -j DROP 2>/dev/null || $IPT -A OUTPUT -d "$1" -j DROP
    else
        $IPT -A INPUT  -s "$1" -j DROP
        $IPT -A OUTPUT -d "$1" -j DROP
    fi
}

# local/private space must never be blocked (10/8 loopback-CGNAT etc.)
LOCAL_NETS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10"
# bogus private-range blocks installed by previous versions - always scrub
OLD_BLOCKS="10.0.0.0/12 172.16.0.0/12 192.168.0.0/16"

# Define IP ranges to block
IP_RANGES="5.136.0.0/13 95.24.0.0/13 176.208.0.0/13 178.64.0.0/13 45.93.20.0/24 62.122.184.0/24 62.233.50.0/24 85.209.11.0/24 87.247.158.0/23 5.116.81.51 91.213.138.0/24 91.240.118.0/24 91.241.19.0/24 152.89.196.0/24 152.89.198.0/24 176.111.174.0/24 185.11.61.0/24 185.81.68.0/24 185.122.204.0/24 185.198.69.0/24 185.234.216.0/24 188.119.66.0/24 194.26.135.0/24 195.226.194.0/24 109.205.211.0/24 79.124.62.0/24"

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

# unblock + whitelist all local/private space LAST, so the allows sit on top
whitelist_locals

if [ "$USE_UFW" -eq 1 ]; then
    echo "Firewalls configured to block specified IP ranges and IPs using ufw."
    echo "ufw rules are persistent across reboots automatically."
else
    echo "Firewalls configured to block specified IP ranges and individual IPs using iptables."
    echo "Note: these rules are not persistent. Install iptables-persistent (Debian) or"
    echo "iptables-services (Fedora/RHEL) to survive reboots."
fi
