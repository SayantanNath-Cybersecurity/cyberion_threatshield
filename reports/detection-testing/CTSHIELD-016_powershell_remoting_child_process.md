# CTSHIELD-016 Detection Test Report

## Detection

- **Rule:** CTSHIELD-016
- **Title:** PowerShell Remoting Child Process
- **Rule file:** `detections/sigma/CTSHIELD-016_powershell_remoting_child_process.yml`
- **ATT&CK Technique:** T1021.006 - Windows Remote Management
- **Tactic:** Lateral Movement
- **Status:** Experimental
- **Severity:** Medium

## Dataset

- **Dataset:** EVTX-ATT&CK-SAMPLES
- **Source file:** `Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx`
- **Log type:** Sysmon
- **Event ID:** 1

## Detection Logic

The rule detects Sysmon process creation where:

- `EventID = 1`
- `ParentImage` ends with `\wsmprovhost.exe`

`wsmprovhost.exe` is the Windows PowerShell Remoting host process used in Windows Remote Management activity.

## Test Result

**PASS**

Observed result:

```text
CTSHIELD-016 matched 1 PowerShell Remoting child process event(s).
1 passed in 0.06s
