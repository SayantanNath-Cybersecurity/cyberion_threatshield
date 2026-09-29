# CTSHIELD-019 Detection Test Report

## Detection

- **Rule:** CTSHIELD-019
- **Title:** Network Logon Followed by WMI Provider Host Execution
- **Rule file:** `detections/sigma/ctshield-019_wmi_authentication_execution_correlation.yml`
- **ATT&CK Technique:** T1047 - Windows Management Instrumentation
- **Status:** Experimental
- **Severity:** Medium

## Dataset

- **Dataset:** EVTX-ATT&CK-SAMPLES
- **Source file:** `Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx`
- **Dataset commit:** `4ceed2f4706daf601c212a8f91c113dd85349a2c`

## Correlation Logic

The rule correlates:

1. Windows Security Event ID `4624` with `LogonType = 3`
2. Subsequent process creation Event ID `4688`
3. `NewProcessName` ending with `\WmiPrvSE.exe`
4. Same `ComputerName`
5. Maximum correlation window of `5m`

## Test Result

**PASS**

Observed result:

```text
CTSHIELD-019 matched a network logon followed by WmiPrvSE.exe on the same host after 0:00:13.609514.
1 passed in 0.09s
