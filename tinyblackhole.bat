@echo off
setlocal enabledelayedexpansion

REM Define IP ranges to block
set IP_RANGES=5.136.0.0/13 95.24.0.0/13 176.208.0.0/13 178.64.0.0/13 10.0.0.0/12 172.16.0.0/12 192.168.0.0/16

REM Block IP ranges using Windows Firewall
for %%i in (%IP_RANGES%) do (
    netsh advfirewall firewall add rule name="Block %%i" dir=in interface=any action=block remoteip=%%i
    netsh advfirewall firewall add rule name="Block %%i" dir=out interface=any action=block remoteip=%%i
)

echo Firewalls configured to block specified IP ranges.
