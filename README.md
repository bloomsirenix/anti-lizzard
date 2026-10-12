# anti-lizzard
## scripts to keep botnets out of the system
### under normal circumstances please ONLY run the following files
tinyblackhole.bat (windows)
tinyblackhole.sh (linux) 

#### these block most botnets if you want to be 100% sure you may run the _danger ones note these MIGHT block your web access like there that strong
# note to update the repo when you can I add on the fly also THE BAT FILE REQUIRES ADMINISTRATOR TO BLACKHOLE THE IPS!
scripts and there purpose
tieblackhole - blocks most botnets of lizzardsquad 
blknrkr-ufw_danger.sh blocks(requires UFW(apt install ufw) all of north korea
massblackhole_danger.sh blocks all ASNS in bad_asn WARNNING: might brick your WIFI or overloads the FW like its THAT much IPs
bad_asn = crime/bulletproof ASNs only (spamhaus ASN-DROP + documented abusers). commonabused_cspasns.txt = compliant providers (google/msft/isps/legit hosts) that get abused - NOT mass-blocked, but their abusive IPs are still in the IP lists
noportscan.sh - portscan tarpit: drops hosts that touch >15 distinct ports/hour for 10 min (tune with SCAN_BURST/BAN_SECONDS env vars) + stealth-scan flag drops. ./noportscan.sh --remove to undo
harden.sh - general inbound hardening: invalid/martian/non-SYN drops, SSH brute-force throttle, SYN+ping flood limits. ./harden.sh --sysctl for persistent kernel hardening, ./harden.sh --remove to undo

all scripts work on debian/ubuntu + other distros (apt/dnf/yum/zypper/pacman/apk), auto-install deps, and fall back to iptables when ufw is missing. firewall rules do NOT survive reboot - install iptables-persistent or iptables-services to keep them
