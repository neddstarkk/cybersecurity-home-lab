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

## Findings

### Hunt for PowerShell execution evidence

The first technique I simulated was T1059.001. Sysmon captures process creation as Event ID 1, which records the image path, command-line arguments, and the parent process that spawned it.

**SPL QUERY**

```index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\powershell.exe" | table _time Image CommandLine ParentImage User | sort -_time```

Here I am hunting for eventcode 1, image powershell.exe. What this would look for is sysmon process create events only. Event code 1 signifies that a new process has been created. The table command selects the five most useful fields for investigation. CommandLine shows exactly what the attacker typed. ParentImage reveals what process launched powershell.exe

Command executed: "powershell.exe" &amp; {C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full}

Parent Image = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Timestamp: 2026-06-10 16:53:58.847

### Hunt for Scheduled Task creation evidence

The second technique (T1053.005) used schtasks.exe to create a persistence mechanism. Sysmon Event ID 1 also captures this because creating a scheduled task launches the schtasks.exe process.

**SPL QUERY**

```index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\schtasks.exe" CommandLine="*Create*" | table _time Image CommandLine ParentImage User | sort -_time```

`Image="*\\schtasks.exe"` filters to events where the Scheduled Tasks utility ran. ```CommandLine="*Create*"``` narrows further to only task-creation actions, filtering out task queries or deletions.

The CommandLine field is especially valuable here because it contains the task name, the scheduled time, and the command the task would execute.

TimeStamp: 2026-06-10 17:00:52.420
CommandLine: SCHTASKS /Create /SC ONCE /TN SPAWN /TR C:\windows\system32\cmd.exe /ST 20:10
ParentImage: C:\Windows\system32\cmd.exe

## Hunt for LSASS credential dumping evidence

The final technique (T1003.001) accessed LSASS process memory to dump credentials. Unlike the first two hunts, this one uses Sysmon Event ID 10 (Process Access) instead of Event ID 1. Event ID 10 captures when one process opens a handle to another process.

**SPL QUERY**

```index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\lsass.exe" | table _time SourceImage TargetImage GrantedAccess CallTrace | sort -_time```

`EventCode=10` filters to Sysmon Process Access events. ```TargetImage="*\\lsass.exe"``` matches any process that opened a handle to LSASS (the Local Security Authority Subsystem Service that stores credentials in memory).

The key detection fields here are GrantedAccess (a hex value indicating the level of access requested) and CallTrace (the chain of DLLs involved in the access call). Together these reveal whether the access was a legitimate system operation or a credential dump.

TimeStamp: 2026-06-10 17:03:23.273
SourceImage: C:\Windows\System32\rundll32.exe
GrantedAccess: 0x1fffff
CallTrace: indicates dbgcore.dll

Why are GrantedAccess and CallTrace so important?

Many legitimate system processes access LSASS. The GrantedAccess value tells you how much access was requested. Values like 0x1fffff (full access) or 0x1438 are far more permissive than normal system operations require.

The CallTrace showing dbgcore.dll or dbghelp.dll indicates a memory-dumping operation was used. Legitimate services rarely involve debug DLLs when touching LSASS.

