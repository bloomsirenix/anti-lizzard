#!/usr/bin/env bash
# massblackhole_danger.sh - block EVERY prefix announced by the ASNs in bad_asn.
# WARNING: this installs a huge number of rules and may block legitimate
# providers (the ASN list includes large clouds and ISPs).
#
# Uses an ipset (fast path). The match rule is inserted at the TOP of INPUT
# so the blackhole wins over ufw and other accept rules - ufw can't express
# ipset matching via its CLI. Old-format rules left by previous versions
# (ipset match appended to INPUT, or individual '-A INPUT -s <cidr> -j DROP')
# are removed automatically during the run.
#
# If ufw is installed, a hook is added to /etc/ufw/after.init so the match
# rule is re-attached (and the set restored from $SAVED_SET) after
# 'ufw reload', 'ufw enable' and at boot.
#
# Fallbacks when ipset is unavailable:
#   ufw present -> 'ufw insert 1 deny from <cidr>' (slow, thousands of rules!)
#   otherwise   -> individual iptables INPUT drops (slow!)
#
# Usage:
#   ./massblackhole_danger.sh [asn_list_file]   install/refresh blocks
#   ./massblackhole_danger.sh --remove          remove rules, hook and ipset
#   ./massblackhole_danger.sh --rehook          re-attach match + restore set
#                                               (used by the ufw hook)

set -u

SET="massblackhole"
SAVED_SET="/etc/massblackhole.ipset"
AFTER_INIT="/etc/ufw/after.init"
MARK_BEGIN="# >>> massblackhole_danger.sh >>>"
MARK_END="# <<< massblackhole_danger.sh <<<"

MODE="install"
INPUT_ARG=""
case "${1:-}" in
    --remove|--flush) MODE="remove" ;;
    --rehook)         MODE="rehook" ;;
    *)                INPUT_ARG="${1:-}" ;;
esac

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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"

# drop every copy of the ipset match rule from INPUT (old versions appended
# it at the bottom where ufw could shadow it)
unhook_match() {
    while $IPT -C INPUT -m set --match-set "$SET" src -j DROP 2>/dev/null; do
        $IPT -D INPUT -m set --match-set "$SET" src -j DROP
    done
}

# attach the match rule at position 1: before ufw's hooks, so the
# blackhole overrides any accept rule
attach_match() {
    unhook_match
    $IPT -I INPUT 1 -m set --match-set "$SET" src -j DROP
}

hook_ufw() {
    [ "${MBLK_NO_HOOK:-0}" = "1" ] && return 0
    command -v ufw >/dev/null 2>&1 || return 0
    if [ ! -e "$AFTER_INIT" ]; then
        printf '#!/bin/sh\n' > "$AFTER_INIT" 2>/dev/null || {
            echo "Warning: cannot write $AFTER_INIT; rules won't survive 'ufw reload'." >&2
            return 0
        }
    fi
    chmod +x "$AFTER_INIT" 2>/dev/null
    grep -qF "$MARK_BEGIN" "$AFTER_INIT" 2>/dev/null && return 0
    printf '%s\nMBLK_NO_HOOK=1 "%s" --rehook >/dev/null 2>&1 || true\n%s\n' \
        "$MARK_BEGIN" "$SCRIPT_PATH" "$MARK_END" >> "$AFTER_INIT"
    echo "ufw detected: re-apply hook added to $AFTER_INIT"
}

unhook_ufw() {
    [ -f "$AFTER_INIT" ] || return 0
    sed -i '/>>> massblackhole_danger\.sh >>>/,/<<< massblackhole_danger\.sh <<</d' "$AFTER_INIT" 2>/dev/null
}

# remove a leftover old-format rule for a prefix, if present
legacy_cleanup() {
    $IPT -D INPUT -s "$1" -j DROP 2>/dev/null
}

# local/private space must never be blackholed
LOCAL_NETS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10"

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
        # overlap iff either network contains the other's base address
        if [ $(( i & nm )) -eq $(( ni & nm )) ] || [ $(( ni & m )) -eq $(( i & m )) ]; then
            return 0
        fi
    done
    return 1
}

# belt and suspenders: ACCEPT local sources at the very top of INPUT
# (above the blackhole match rule) and purge them from the set
whitelist_locals() {
    local net
    for net in $LOCAL_NETS; do
        $IPT -C INPUT -s "$net" -j ACCEPT 2>/dev/null || $IPT -I INPUT 1 -s "$net" -j ACCEPT
        ipset del "$SET" "$net" -exist 2>/dev/null
    done
}

# ---------------------------------------------------------------- remove mode
if [ "$MODE" = "remove" ]; then
    unhook_match
    ipset destroy "$SET" 2>/dev/null
    unhook_ufw
    rm -f "$SAVED_SET"
    echo "massblackhole match rule, ufw hook and ipset removed."
    echo "Note: individual 'ufw deny' / iptables rules from the slow fallback"
    echo "paths (if ever used) are left in place."
    exit 0
fi

# ---------------------------------------------------------------- rehook mode
# cheap re-attach used by /etc/ufw/after.init: no whois lookups
if [ "$MODE" = "rehook" ]; then
    if command -v ipset >/dev/null 2>&1; then
        ipset create "$SET" hash:net family inet hashsize 65536 maxelem 400000 -exist 2>/dev/null || exit 0
        [ -f "$SAVED_SET" ] && ipset restore -exist < "$SAVED_SET" 2>/dev/null
        attach_match
        whitelist_locals
    fi
    exit 0
fi

# ---------------------------------------------------------------- install
if ! command -v whois >/dev/null 2>&1; then
    pkg_install whois || { echo "Error: could not install whois." >&2; exit 1; }
fi

# Input file: argument, or bad_asn / bad_asn.txt next to the script or in cwd
input_file="$INPUT_ARG"
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

# Backend: ipset (fast) > ufw > raw iptables
USE_IPSET=0
USE_UFW=0
if command -v ipset >/dev/null 2>&1 || pkg_install ipset; then
    if ipset create "$SET" hash:net family inet hashsize 65536 maxelem 400000 -exist 2>/dev/null; then
        attach_match
        USE_IPSET=1
        echo "Using ipset '$SET' hooked at top of INPUT (fast path, beats ufw accepts)."
    fi
fi
if [ "$USE_IPSET" -eq 0 ]; then
    if command -v ufw >/dev/null 2>&1 || pkg_install ufw; then
        USE_UFW=1
        echo "ipset unavailable; using 'ufw deny' (slow with this many prefixes!)."
        # whitelist local nets above everything so denies can never catch them
        for net in $LOCAL_NETS; do
            ufw insert 1 allow from "$net" to any >/dev/null
        done
    else
        echo "ipset and ufw unavailable; falling back to individual iptables rules (slow!)."
    fi
fi
[ "$USE_UFW" -eq 0 ] && whitelist_locals

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
        if overlaps_local "$ip_range"; then
            echo "  skipping local/private range $ip_range"
            continue
        fi
        if [ "$USE_IPSET" -eq 1 ]; then
            ipset add "$SET" "$ip_range" -exist
            legacy_cleanup "$ip_range"
        elif [ "$USE_UFW" -eq 1 ]; then
            # insert 1: deny must come before earlier 'allow' rules
            ufw insert 1 deny from "$ip_range" to any >/dev/null
            legacy_cleanup "$ip_range"
        else
            $IPT -C INPUT -s "$ip_range" -j DROP 2>/dev/null ||
                $IPT -A INPUT -s "$ip_range" -j DROP
        fi
    done
done < "$input_file"

if [ "$USE_IPSET" -eq 1 ]; then
    # snapshot the set so the ufw after.init hook can restore it after reboot
    ipset save "$SET" > "$SAVED_SET" 2>/dev/null
    hook_ufw
fi

echo "Ultimate Blackhole script completed."
if [ "$USE_IPSET" -eq 1 ]; then
    echo "The ipset match sits at the top of INPUT; set contents saved to"
    echo "$SAVED_SET for the ufw re-apply hook."
else
    echo "Note: rules are not persistent across reboots unless ufw handled"
    echo "them (ufw persists its own rules)."
fi
