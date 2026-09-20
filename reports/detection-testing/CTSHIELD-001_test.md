# CTSHIELD-001 Detection Test

## Detection

- **Rule ID:** CTSHIELD-001
- **Rule:** Windows Security Event Log Cleared
- **ATT&CK Technique:** T1685.005 - Clear Windows Event Logs
- **Severity:** High
- **Status:** Experimental

## Test Dataset

- **Dataset:** EVTX-ATTACK-SAMPLES
- **Sample:** `Defense Evasion/DE_1102_security_log_cleared.evtx`
- **Dataset Commit:** `4ceed2f4706daf601c212a8f91c113dd85349a2c`

## Detection Logic Tested

The detection selects:

- `EventID = 1102`
- `Channel = Security`

## Test Method

The selected EVTX file was parsed using the `python-evtx` library.

Each event was parsed from XML and evaluated against the selection represented by CTSHIELD-001.

## Test Result

**PASS**

Observed result:

```text
CTSHIELD-001 matched 1 event(s).
