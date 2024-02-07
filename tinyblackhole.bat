@echo off
setlocal enabledelayedexpansion

REM Define IP ranges to block
set IP_RANGES=5.136.0.0/13 95.24.0.0/13 176.208.0.0/13 178.64.0.0/13 10.0.0.0/12 172.16.0.0/12 192.168.0.0/16 45.93.20.0/24 62.122.184.0/24 62.233.50.0/24 85.209.11.0/24 87.247.158.0/23 91.213.138.0/24 91.240.118.0/24 91.241.19.0/24 152.89.196.0/24 152.89.198.0/24 176.111.174.0/24 185.11.61.0/24 185.81.68.0/24 185.122.204.0/24 185.198.69.0/24 185.234.216.0/24 188.119.66.0/24 194.26.135.0/24 195.226.194.0/24

REM Block IP ranges using Windows Firewall
for %%i in (%IP_RANGES%) do (
    netsh advfirewall firewall add rule name="Block %%i" dir=in interface=any action=block remoteip=%%i
    netsh advfirewall firewall add rule name="Block %%i" dir=out interface=any action=block remoteip=%%i
)

echo Firewalls configured to block specified IP ranges using Windows Firewall.
