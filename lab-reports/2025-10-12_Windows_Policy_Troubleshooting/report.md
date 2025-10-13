# Lab Report: Troubleshooting Persistent Windows Audit Policy Reversion

**Date:** 2025-10-12
**Analyst:** [Your Name]

---

### ## 1. Symptom 🐛
Windows security audit policies, specifically for "Logon" and "Filtering Platform Packet Drop," were reverting to a "Not Configured" state shortly after being set via the Local Group Policy Editor (`gpedit.msc`). This prevented the Wazuh SIEM from receiving critical security events like failed logins and port scans.

---

### ## 2. Investigation & Analysis
- **Initial Action:** Policies were set correctly in `gpedit.msc` and `gpupdate /force` was run.
- **SIEM Observation:** The Wazuh dashboard generated an alert (Event ID 4719) indicating that the "System audit policy was changed."
- **Evidence Analysis:** The alert details revealed the change was initiated by the **`LOCAL SYSTEM`** account (`S-1-5-18`), meaning an automated OS process was responsible for reverting the policies.
- **Hypothesis:** A core Windows service, such as Microsoft Defender or a policy refresh mechanism, was enforcing a baseline configuration from a cached or corrupted source.
- **External Research:** An obscure Stack Overflow thread suggested that a corrupted policy cache file could cause this exact behavior.



---

### ## 3. Root Cause 💡
The root cause was identified as a corrupted or conflicting policy cache file located at **`C:\Windows\system32\grouppolicy\machine\microsoft\windows nt\audit\audit.csv`**. This file was forcing the system to re-apply an old, empty policy configuration during its refresh cycle, overriding any manual changes made in `gpedit.msc`.

---

### ## 4. Solution & Verification 🏆
1.  The `audit.csv` file was deleted from the specified directory.
2.  The system was restarted to allow Windows to rebuild a clean policy state.
3.  The required audit policies were re-applied using `gpedit.msc` and `gpupdate /force`.
4.  **Verification:** The fix was confirmed in two ways:
    - The policies remained persistent after several minutes and a system restart.
    - A failed login attempt on the Windows VM successfully generated the expected **"Authentication failed"** alert in the Wazuh dashboard, proving the entire logging pipeline was now functional.

---

### ## 5. Key Takeaways
- A SIEM is not just for detecting external attackers; it is a critical tool for diagnosing internal system misconfigurations.
- Windows configuration can be affected by obscure cached files that are not immediately obvious.
- Structured troubleshooting (Symptom -> Hypothesis -> Evidence -> Solution) is essential for solving non-trivial technical issues.