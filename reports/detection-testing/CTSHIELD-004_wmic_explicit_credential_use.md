# CTSHIELD-004 Detection Test Evidence

## Detection

- Rule: CTSHIELD-004
- Title: WMIC Explicit Credential Use
- Rule file: `detections/sigma/CTSHIELD-004_wmic_explicit_credential_use.yml`
- ATT&CK technique: T1047 - Windows Management Instrumentation
- Status: Experimental
- Severity: Medium

## Dataset

- Dataset: EVTX-ATT&CK-SAMPLES
- Source repository: `https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES`
- Dataset commit: `4ceed2f4706daf601c212a8f91c113dd85349a2c`
- Test file: `Lateral Movement/LM_WMIC_4648_rpcss.evtx`

## Detection Logic

The rule detects Windows Security Event ID 4648 where:

- `ProcessName` ends with `\WMIC.exe`
- `TargetUserName` exists

This identifies explicit credential use performed through WMIC.

## Observed Telemetry

The test dataset contains two matching Event ID 4648 records.

Observed values include:

- `SubjectUserName`: `user01`
- `TargetUserName`: `administrator`
- `ProcessName`: `C:\Windows\System32\wbem\WMIC.exe`
- `ProcessId`: `0x0000044c`
- `TargetServerName`: `WIN-77LTAPHIQ1R.example.corp`

The same dataset also contains Event ID 4688 showing creation of:

`C:\Windows\System32\wbem\WMIC.exe`

with:

`NewProcessId = 0x0000044c`

This provides supporting process context for the explicit credential-use events.

## Test Method

The detection was tested by parsing the actual EVTX telemetry with `python-evtx`.

The test checks for:

1. Event ID `4648`
2. `ProcessName` equal to `C:\Windows\System32\wbem\WMIC.exe`
3. `TargetUserName` equal to `administrator`

## Test Result

```text
CTSHIELD-004 matched 2 WMIC explicit credential use event(s).
1 passed
