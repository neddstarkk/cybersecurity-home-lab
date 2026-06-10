# Investigation Report - Attack Chain Detection

## Date
10 June 2026
Baseline Time: 16:38 PM.

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

## Simulation

### T1059.001 - PowerShell Command Execution
- Command: Invoke-AtomicTest T1059.001 -TestNumbers 19
- Timestamp: 18:07
- ATT&CK Technique: T1059.001

### T1053.005 - Scheduled Task Local
- Command: Invoke-AtomicTest T1053.005 -TestNumbers 2
- Timestamp: 18:08
- ATT&CK Technique: T1053.005
- Cleanup: Invoke-AtomicTest T1053.005 -TestNumbers 2 -Cleanup

### T1003.001 - Dump LSASS.exe Memory using comsvcs.dll
- Command: Invoke-AtomicTest T1003.001 -TestNumbers 2
- Timestamp: 18:
- ATT&CK Technique: T1003.001
- Cleanup: Invoke-AtomicTest T1003.001 -TestNumbers 2 -Cleanup