# CTSHIELD-016 Tuning Pass

## Detection

- **Rule:** CTSHIELD-016
- **Title:** PowerShell Remoting Child Process
- **Rule file:** `detections/sigma/CTSHIELD-016_powershell_remoting_child_process.yml`
- **Status:** Experimental
- **Severity:** Medium
- **ATT&CK Technique:** T1021.006 - Windows Remote Management

## Dataset

- **Dataset:** EVTX-ATT&CK-SAMPLES
- **Source file:** `Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx`
- **Log type:** Sysmon
- **Event ID:** 1

## Initial Detection Logic

The initial detection identifies Sysmon Event ID `1` process creation events where:

```text
ParentImage ends with \wsmprovhost.exe
