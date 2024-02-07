#!/bin/bash

# Check if iptables is installed
if ! command -v iptables &> /dev/null; then
    echo "Error: iptables is not installed. Please install iptables."
    exit 1
fi

# Function to get IP ranges for a given ASN
get_ip_ranges() {
    asn="$1"
    whois -h whois.radb.net -- "-i origin $asn" | grep -Eo "([0-9.]+){4}/[0-9]+"
}

# Function to drop IP ranges using iptables
drop_ip_ranges() {
    while IFS= read -r ip_range; do
        sudo iptables -A INPUT -s "$ip_range" -j DROP
        echo "Dropped IP range: $ip_range"
    done
}

# Main script
input_file="bad_asn.txt"

# Check if the input file exists
if [ ! -f "$input_file" ]; then
    echo "Error: File $input_file not found."
    exit 1
fi

# Loop through each ASN in the file
while IFS= read -r asn; do
    echo "Processing ASN: $asn"
    
    # Get IP ranges for the current ASN
    ip_ranges=$(get_ip_ranges "$asn")
    
    # Drop the IP ranges using iptables
    echo "$ip_ranges" | drop_ip_ranges

done < "$input_file"

echo "Ultimate Blackhole script completed."
