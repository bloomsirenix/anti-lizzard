#!/bin/bash

# Define IP ranges to block
IP_RANGES="5.136.0.0/13 95.24.0.0/13 176.208.0.0/13 178.64.0.0/13 10.0.0.0/12 172.16.0.0/12 192.168.0.0/16"

# Block IP ranges using iptables
for IP_RANGE in $IP_RANGES; do
    iptables -A INPUT -s $IP_RANGE -j DROP
    iptables -A OUTPUT -d $IP_RANGE -j DROP
done

echo "Firewalls configured to block specified IP ranges."
