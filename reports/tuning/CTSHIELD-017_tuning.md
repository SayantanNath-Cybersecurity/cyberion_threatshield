# CTSHIELD-017 Tuning Experiment

## Status

**Retired from final detection library**

CTSHIELD-017 was evaluated as a detection-engineering experiment but was not retained in the final 19-rule Sigma library.

The experiment remains documented because it provides evidence of a tuning decision made during detection development.

## Detection

- **Rule:** CTSHIELD-017
- **Title:** Chrome Interactive Authentication Activity
- **Original rule file:** `detections/sigma/CTSHIELD-017_chrome_interactive_authentication.yml`
- **Status:** Retired
- **Severity:** Low

## Dataset

- **Dataset:** EVTX-ATT&CK-SAMPLES
- **Source file:** `Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx`
- **Log channel:** Security
- **Event IDs:** 4624 and 4625

## Initial Detection Logic

The initial detection identified interactive authentication activity where:

- `LogonType = 2`
- `LogonProcessName = Chrome`
- `ProcessName` ends with `\chrome.exe`

The initial logic intentionally included both successful and failed authentication events.

## Observed False-Positive Scenario

The selected telemetry contained three Chrome interactive authentication events:

- One Event ID `4625`, representing a failed interactive authentication.
- Two Event ID `4624` records, representing successful interactive authentication.

The successful authentication records were normal authentication activity and did not represent the failed-authentication condition being investigated.

These successful events therefore created unnecessary detection noise.

## Tuning Change

The experiment evaluated adding:

```text
EventID = 4625
