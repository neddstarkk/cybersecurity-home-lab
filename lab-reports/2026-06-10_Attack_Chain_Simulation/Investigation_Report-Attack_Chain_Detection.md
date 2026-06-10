# Investigation Report - Attack Chain Detection

## Date
10 June 2026
Baseline Time: 4:38 PM. 16:38 in 24 hour clock

## Lab Environment Description
Windows 11 VM with sysmon and Splunk Universal Forwarder Installed. Atomic Red Team operational, tested and ready to execute
Ubuntu VM with Splunk running and receiving logs
Virtualbox environment containing both Windows and Ubuntu VM with an internal network joining the two

## Objective
To simulate a 3-stage attack chain and generate telemetry which will be utilized in creation of detection rules within SPL and Sigma.

## MITRE ATT&CK Techniques Covered
- T1059.001
- T1053.005
- T1003.001