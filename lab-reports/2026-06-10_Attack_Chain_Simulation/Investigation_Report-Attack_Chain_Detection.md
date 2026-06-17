# Investigation Report - Attack Chain Detection

## Executive Summary
I simulated 3 attacks - suspicious powershell execution, scheduled task creation, and LSASS credential dumping. For each of them I found the malicious commands executing these attacks, and the associated arguments, and associated DLLs that assist in the attack. I created 3 detection rules for each corresponding attack technique verifying the alert firing on incoming telemetry.

## Environment
Ubuntu VM running Splunk, Windows VM with Sysmon and Atomic Red Team installed, internal network connecting the two VMs in VirtualBox

## Attack Simulation
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
- Timestamp: 18:10
- ATT&CK Technique: T1003.001
- Cleanup: Invoke-AtomicTest T1003.001 -TestNumbers 2 -Cleanup

## Detection Development

### ATT&CK T1059.001 - Suspicious Powershell Execution

**Rule Name**: Suspicious Powershell Execution
**MITRE ATT&CK Technique**: T1059.001
**SPL Query**: 

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-nop*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*" OR CommandLine="*Invoke-*")
| stats count min(_time) as firstTime max(_time) as lastTime by Image CommandLine ParentImage User Computer
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S")
| eval lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
| sort -lastTime
```

**Detection Logic Rationale**: ```EventCode=1``` indicates process creation with the Image parameter identifying the binary/executable that was used in the process. I added inclusions to this command such as -enc. This rule fires only when PowerShell is launched with flags commonly associated with malicious activity. It looks for encoded commands (-enc), no-profile execution (-nop), in-memory execution (IEX), download cradles (DownloadString), and invoke patterns (Invoke-).

The stats command groups results by key fields so I can see each unique combination of command line, parent process, and user. The eval strftime lines convert timestamps into human-readable format for analysts.

**Known False Positives**: Legitimate admin scripts and configuration management tools like SCCM may trigger detections. 
**Recommended Response**: Investigate ParentImage and correlate with change management records. 

### ATT&CK T1053.005 - Scheduled Task Creation

**Rule Name**: Scheduled Task Creation
**MITRE ATT&CK Technique**: T1053.005
**SPL Query**:

```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\schtasks.exe" CommandLine="*/Create*"
| stats count min(_time) as firstTime max(_time) as lastTime by Image CommandLine ParentImage User Computer
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S")
| eval lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
| sort -lastTime
```



**Detection Logic Rationale**: Same as before, ```EventCode=1``` indicates process creation with the executable in Image parameter. This rule fires whenever schtasks.exe runs with the /Create flag. Any new scheduled task created via the command line generates an alert. This gives your SOC team visibility into persistence attempts.

The grouping by ParentImage is important because it reveals what process spawned the task creation. A scheduled task created by powershell.exe is far more suspicious than one created by a legitimate installer.

**Known False Positives**: software installers and Windows Update routinely creates tasks. 
**Recommended Response**: Investigate whether the parent process and task command are expected. 

### ATT&CK T1003.001 - LSASS Credential Dumping

**Rule Name**: LSASS Credential Dumping
**MITRE ATT&CK Technique**: T1003.001
**SPL Query**:

```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1038","0x1438","0x143a","0x1fffff") CallTrace IN ("*dbgcore.dll*","*dbghelp.dll*","*ntdll.dll*","*kernelbase.dll*")
NOT SourceImage IN ("*\\svchost.exe","*\\csrss.exe","*\\wininit.exe","*\\lsass.exe")
| stats count min(_time) as firstTime max(_time) as lastTime by SourceImage TargetImage GrantedAccess CallTrace User Computer
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S")
| eval lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
| sort -lastTime
```

**Detection Rationale**: This rule will rely upon ```EventCode=10``` which signifies Process Access, triggering whenever a process opens another process. This rule layers multiple detection signals together. The GrantedAccess values (0x1038, 0x1438, 0x143a, 0x1fffff) represent memory access permissions that credential dumping tools request.

The CallTrace filter checks for DLLs involved in memory dumping operations (dbgcore.dll, dbghelp.dll). The NOT SourceImage clause excludes known legitimate system processes like svchost.exe and csrss.exe that routinely access LSASS for normal operations.

**Known False Positives**: Antivirus and security scanning tools may access LSASS.
**Recommended Response**: Correlate SourceImage with your approved security tooling list.

## Findings and Analysis
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

## Recommendations
- Deploy all three detection rules as real-time alerts in Splunk with appropriate throttling (e.g. once per host per hour)
- Integrate alerts with a SOAR platform or ticketing system for automated triage
- Schedule weekly tuning reviews to adjust false positive filters based on environment baselines
- Layer these detections with additional data sources (Windows Security Event Log, EDR telemetry) for higher-fidelity alerting
- Create a response playbook for each detection: what an analyst should investigate, which systems to isolate, and escalation criteria

## Telemetry Mapping Table
| ATT&CK Technique | Sysmon Event ID | Key Fields | Malicious Indicator Values | Potential Evasion |
|---|---|---|---|---|
| T1059.001 | 1 | Image, CommandLine, ParentImage | -enc, -nop, IEX, DownloadString, Invoke- | Obfuscation, renamed binary |
| T1053.005 | 1 | Image, CommandLine | schtasks.exe /Create | COM-based task creation, WMI |
| T1003.001 | 10 | TargetImage, GrantedAccess, CallTrace | 0x1038/0x1438/0x1fffff, dbgcore.dll/dbghelp.dll | Different access masks, direct syscalls |

## Sigma Rule Notes

- Portability: A single Sigma rule can be converted to SPL, KQL, Lucene, and other query languages. If your organisation migrates SIEMs, detection logic does not need to be rewritten.
- Sharing: The SigmaHQ repository contains thousands of community-contributed rules. Teams can import vetted detections instead of writing every rule from scratch.
- Automation: CI/CD pipelines can automatically convert Sigma rules and deploy them to multiple SIEMs simultaneously, keeping detection coverage consistent across environments.