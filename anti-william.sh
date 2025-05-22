#!/bin/bash

# Script to deny and drop IPs using UFW, with geolocation check
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

# Check if script is run with sudo
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (use sudo)."
    exit 1
fi

# Check if ufw is installed
if ! command -v ufw &> /dev/null; then
    echo "UFW is not installed. Please install it first."
    exit 1
fi

# Check if curl is installed
if ! command -v curl &> /dev/null; then
    echo "curl is not installed. Please install it first."
    exit 1
fi

# Ensure log file exists
touch "$LOG_FILE" || {
    echo "Cannot write to log file $LOG_FILE. Check permissions."
    exit 1
}

# Function to log messages
log_message() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
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
    local status=$(echo "$response" | jq -r '.status')
    if [ "$status" != "success" ]; then
        echo "Unknown (API response invalid)"
        return 1
    fi
    local country=$(echo "$response" | jq -r '.country')
    local region=$(echo "$response" | jq -r '.regionName')
    local city=$(echo "$response" | jq -r '.city')
    echo "$city, $region, $country"
    return 0
}

# Function to block IP with UFW
block_ip() {
    local ip=$1
    # Check if IP is already blocked
    if ufw status | grep -q "$ip"; then
        log_message "IP $ip is already blocked."
        echo "IP $ip is already blocked."
        return 0
    fi
    # Deny incoming from IP
    ufw deny from "$ip" to any
    if [ $? -eq 0 ]; then
        log_message "Blocked IP $ip with UFW."
        echo "Blocked IP $ip."
    else
        log_message "Failed to block IP $ip with UFW."
        echo "Failed to block IP $ip."
        return 1
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

# Reload UFW to ensure rules are applied
ufw reload
log_message "UFW rules reloaded."
echo "UFW rules reloaded."

echo "Processing complete. Check $LOG_FILE for details."
