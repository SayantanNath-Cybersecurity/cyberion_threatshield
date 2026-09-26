# CTSHIELD-003 Detection Test

## Detection

- **Rule ID:** CTSHIELD-003
- **Rule:** WMI Provider Host Process Creation
- **ATT&CK Technique:** T1047 - Windows Management Instrumentation
- **Tactic:** Execution
- **Severity:** Medium
- **Status:** Experimental

## Test Dataset

- **Dataset:** EVTX-ATTACK-SAMPLES
- **Sample:** `Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx`
- **Dataset Commit:** `4ceed2f4706daf601c212a8f91c113dd85349a2c`

## Detection Logic Tested

The detection selects Windows process-creation telemetry matching:

- `EventID = 4688`
- `NewProcessName` ending with `\WmiPrvSE.exe`

The Sigma rule uses the generic `process_creation` logsource.

## Test Method

The selected EVTX file was parsed using the `python-evtx` library.

Each Event ID `4688` record was parsed from XML and evaluated against the detection selection represented by CTSHIELD-003.

## Test Result

**PASS**

Observed result:

```text
CTSHIELD-003 matched 1 WmiPrvSE.exe process creation event(s).
