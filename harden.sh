#!/usr/bin/env bash
# harden.sh - general-purpose inbound hardening via iptables.
# Inserts a HARDEN chain at the TOP of INPUT so its drops run before ufw
# or any other accept rules; does NOT change default policies, so it
# cannot lock you out. Safe to re-run (idempotent), and safely upgrades
# the old appended-at-the-bottom format.
#
# ufw can't express these rules (conntrack/recent/hashlimit), so when ufw
# is installed a hook is added to /etc/ufw/after.init to re-apply them
# after 'ufw reload', 'ufw enable' and at boot.
#
# Usage:
#   ./harden.sh            install/refresh firewall rules
#   ./harden.sh --sysctl   also install kernel (sysctl) hardening, persistent
#   ./harden.sh --remove   remove the firewall rules
#                          (sysctl file is kept; delete /etc/sysctl.d/99-anti-lizzard.conf
#                           and run 'sysctl --system' to revert)

set -u

CHAIN="HARDEN"
SYSCTL_FILE="/etc/sysctl.d/99-anti-lizzard.conf"
AFTER_INIT="/etc/ufw/after.init"
MARK_BEGIN="# >>> harden.sh >>>"
MARK_END="# <<< harden.sh <<<"

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

IPT="iptables -w"
SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"

# remove every jump from INPUT into $CHAIN (cleans up the old appended
# format as well as any duplicates)
unhook() {
    while $IPT -C INPUT -j "$CHAIN" 2>/dev/null; do
        $IPT -D INPUT -j "$CHAIN"
    done
}

hook_ufw() {
    [ "${HARDEN_NO_HOOK:-0}" = "1" ] && return 0
    command -v ufw >/dev/null 2>&1 || return 0
    if [ ! -e "$AFTER_INIT" ]; then
        printf '#!/bin/sh\n' > "$AFTER_INIT" 2>/dev/null || {
            echo "Warning: cannot write $AFTER_INIT; rules won't survive 'ufw reload'." >&2
            return 0
        }
    fi
    chmod +x "$AFTER_INIT" 2>/dev/null
    grep -qF "$MARK_BEGIN" "$AFTER_INIT" 2>/dev/null && return 0
    printf '%s\nHARDEN_NO_HOOK=1 "%s" >/dev/null 2>&1 || true\n%s\n' \
        "$MARK_BEGIN" "$SCRIPT_PATH" "$MARK_END" >> "$AFTER_INIT"
    echo "ufw detected: re-apply hook added to $AFTER_INIT"
}

unhook_ufw() {
    [ -f "$AFTER_INIT" ] || return 0
    sed -i '/>>> harden\.sh >>>/,/<<< harden\.sh <<</d' "$AFTER_INIT" 2>/dev/null
}

# ---------------------------------------------------------------- remove mode
if [ "${1:-}" = "--remove" ] || [ "${1:-}" = "--flush" ]; then
    unhook
    $IPT -F "$CHAIN" 2>/dev/null
    $IPT -X "$CHAIN" 2>/dev/null
    unhook_ufw
    echo "$CHAIN rules removed."
    echo "Note: $SYSCTL_FILE (if installed) is left in place - remove it"
    echo "and run 'sysctl --system' to revert kernel hardening."
    exit 0
fi

# ---------------------------------------------------------------- firewall rules
$IPT -N "$CHAIN" 2>/dev/null || $IPT -F "$CHAIN"
# (re)insert at position 1: drops must run before ufw and other accept
# rules, and this transparently migrates the old appended format
unhook
$IPT -I INPUT 1 -j "$CHAIN"

# loopback is trusted
$IPT -A "$CHAIN" -i lo -j RETURN
# local/private sources are never hardened against
# (127.0.0.0/8 intentionally absent - loopback-only, still a martian off lo)
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10; do
    $IPT -A "$CHAIN" -s "$net" -j RETURN
done
# fast-path for traffic already part of a legit session
$IPT -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
# garbage
$IPT -A "$CHAIN" -m conntrack --ctstate INVALID -j DROP

# martian / spoofed sources that can never be legit on a real interface
# (169.254.0.0/16 intentionally absent - link-local is legit LAN traffic)
for net in 0.0.0.0/8 127.0.0.0/8 224.0.0.0/4 240.0.0.0/5; do
    $IPT -A "$CHAIN" ! -i lo -s "$net" -j DROP
done

# TCP connections must start with SYN (kills all stealth scans at once)
$IPT -A "$CHAIN" -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# SSH brute-force throttle: >4 NEW connections per 60s per source -> drop
$IPT -A "$CHAIN" -p tcp --dport 22 -m conntrack --ctstate NEW \
    -m recent --set --name SSHPROT --rsource
$IPT -A "$CHAIN" -p tcp --dport 22 -m conntrack --ctstate NEW \
    -m recent --update --seconds 60 --hitcount 4 --name SSHPROT --rsource -j DROP

# SYN flood: >30 SYN/s sustained per source (burst 60) -> drop
$IPT -A "$CHAIN" -p tcp --syn \
    -m hashlimit --hashlimit-above 30/second --hashlimit-burst 60 \
    --hashlimit-mode srcip --hashlimit-name synflood \
    --hashlimit-htable-expire 300000 -j DROP

# ping flood: >5 echo-requests/s sustained per source -> drop
$IPT -A "$CHAIN" -p icmp --icmp-type echo-request \
    -m hashlimit --hashlimit-above 5/second --hashlimit-burst 10 \
    --hashlimit-mode srcip --hashlimit-name pingflood \
    --hashlimit-htable-expire 300000 -j DROP

hook_ufw

echo "$CHAIN rules installed."

# ---------------------------------------------------------------- sysctl mode
if [ "${1:-}" = "--sysctl" ]; then
    cat > "$SYSCTL_FILE" <<'EOF'
# anti-lizzard kernel hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF
    sysctl --system >/dev/null 2>&1 || sysctl -p "$SYSCTL_FILE"
    echo "Kernel hardening written to $SYSCTL_FILE and applied."
    echo "(ip_forward intentionally untouched - hypervisors/routers need it.)"
fi

echo "Note: firewall rules are not persistent across reboots. Install"
echo "iptables-persistent (Debian) or iptables-services (Fedora/RHEL) to keep them."
