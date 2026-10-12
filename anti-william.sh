#!/usr/bin/env bash

# Script to deny and drop IPs using UFW (or iptables as fallback), with geolocation check
# Logs actions to a file and notes Virginia, USA IPs

# Log file for actions
LOG_FILE="/var/log/ip_block.log"
# API for geolocation
GEO_API="http://ip-api.com/json"
# List of IPs to process (extracted from your input)
IP_LIST=(
    "45.135.194.4"
    "188.68.201.76"
    "218.92.0.140"
    "203.125.118.248"
    "103.186.1.197"
    "218.92.0.211"
    "193.200.78.34"
    "118.122.147.195"
    "80.94.95.115"
    "80.94.95.116"
    "206.168.34.70"
    "116.101.227.141"
    "41.73.244.116"
    "123.25.60.109"
    "218.92.0.201"
    "218.92.0.252"
    "45.140.17.26"
    "93.122.249.246"
    "104.248.235.219"
    "218.156.176.223"
    "146.70.86.124"
    "185.156.73.233"
    "185.156.73.234"
    "143.244.134.97"
    "43.252.229.139"
    "92.118.39.65"
    "189.112.0.11"
    "194.0.234.19"
    "198.235.24.244"
)

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

ensure_cmd() {
    # ensure_cmd <command> <package>
    command -v "$1" >/dev/null 2>&1 && return 0
    echo "$1 not found, attempting to install $2..."
    pkg_install "$2" && command -v "$1" >/dev/null 2>&1
}

ensure_cmd curl curl || { echo "Error: curl is required." >&2; exit 1; }
ensure_cmd jq jq || { echo "Error: jq is required." >&2; exit 1; }

# Pick a firewall backend: ufw where available (Debian/Ubuntu), else iptables
BACKEND=""
if command -v ufw >/dev/null 2>&1; then
    BACKEND="ufw"
elif ensure_cmd ufw ufw; then
    BACKEND="ufw"
elif command -v iptables >/dev/null 2>&1 || ensure_cmd iptables iptables; then
    BACKEND="iptables"
    echo "ufw unavailable; using iptables backend."
else
    echo "Error: no firewall backend (ufw or iptables) available." >&2
    exit 1
fi

# Ensure log file exists
touch "$LOG_FILE" || {
    echo "Cannot write to log file $LOG_FILE. Check permissions." >&2
    exit 1
}

# Function to log messages
log_message() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" >> "$LOG_FILE"
}

# Function to validate IP address format
is_valid_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to get geolocation
get_geolocation() {
    local ip=$1
    local response
    response=$(curl -s --retry 3 --retry-delay 2 "$GEO_API/$ip")
    if [ $? -ne 0 ]; then
        echo "Unknown (API request failed)"
        return 1
    fi
    local status
    status=$(echo "$response" | jq -r '.status')
    if [ "$status" != "success" ]; then
        echo "Unknown (API response invalid)"
        return 1
    fi
    local country region city
    country=$(echo "$response" | jq -r '.country')
    region=$(echo "$response" | jq -r '.regionName')
    city=$(echo "$response" | jq -r '.city')
    echo "$city, $region, $country"
    return 0
}

# Function to block IP
block_ip() {
    local ip=$1
    if [ "$BACKEND" = "ufw" ]; then
        if ufw status | grep -q "$ip"; then
            log_message "IP $ip is already blocked."
            echo "IP $ip is already blocked."
            return 0
        fi
        if ufw deny from "$ip" to any; then
            log_message "Blocked IP $ip with UFW."
            echo "Blocked IP $ip."
        else
            log_message "Failed to block IP $ip with UFW."
            echo "Failed to block IP $ip."
            return 1
        fi
    else
        if iptables -w -C INPUT -s "$ip" -j DROP 2>/dev/null; then
            log_message "IP $ip is already blocked."
            echo "IP $ip is already blocked."
            return 0
        fi
        if iptables -w -A INPUT -s "$ip" -j DROP && iptables -w -A OUTPUT -d "$ip" -j DROP; then
            log_message "Blocked IP $ip with iptables."
            echo "Blocked IP $ip."
        else
            log_message "Failed to block IP $ip with iptables."
            echo "Failed to block IP $ip."
            return 1
        fi
    fi
}

# Main loop to process IPs
for ip in "${IP_LIST[@]}"; do
    if ! is_valid_ip "$ip"; then
        log_message "Invalid IP address: $ip"
        echo "Skipping invalid IP: $ip"
        continue
    fi

    echo "Processing IP: $ip"
    # Get geolocation
    location=$(get_geolocation "$ip")
    if [ $? -eq 0 ]; then
        log_message "IP $ip geolocation: $location"
        echo "IP $ip location: $location"
        # Check if location is Virginia, USA
        if [[ "$location" == *"Virginia"* && "$location" == *"United States"* ]]; then
            log_message "IP $ip is from Virginia, USA."
            echo "IP $ip is from Virginia, USA."
        fi
    else
        log_message "IP $ip geolocation failed: $location"
        echo "IP $ip location: $location"
    fi

    # Block the IP regardless of location
    block_ip "$ip"

    # Sleep to respect API rate limits
    sleep 2
done

# Reload firewall to ensure rules are applied
if [ "$BACKEND" = "ufw" ]; then
    ufw reload
    log_message "UFW rules reloaded."
    echo "UFW rules reloaded."
fi

echo "Processing complete. Check $LOG_FILE for details."
