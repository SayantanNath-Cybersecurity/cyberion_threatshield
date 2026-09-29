# CTSHIELD-017 Tuning Pass

## Detection

- Rule: CTSHIELD-017
- Title: Chrome Interactive Authentication Activity
- Rule file: `detections/sigma/CTSHIELD-017_chrome_interactive_authentication.yml`
- Status: Experimental
- Severity: Low

## Dataset

- Dataset: EVTX-ATT&CK-SAMPLES
- Source file: `Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx`
- Log channel: Security
- Event IDs: 4624 and 4625

## Initial Detection Logic

The initial detection identifies interactive authentication activity where:

- `LogonType = 2`
- `LogonProcessName = Chrome`
- `ProcessName` ends with `\chrome.exe`

The initial logic intentionally includes both successful and failed authentication events.

## Observed False-Positive Scenario

The selected telemetry contained three Chrome interactive authentication events:

- One Event ID `4625`, representing a failed interactive authentication.
- Two Event ID `4624` records, representing successful interactive authentication.

The successful authentication records were normal authentication activity and did not represent the failed-authentication condition that the investigation required.

These two successful events therefore created unnecessary detection noise for a detection intended to identify authentication failures.

## Tuning Change

The tuned detection adds:

```text
EventID = 4625
