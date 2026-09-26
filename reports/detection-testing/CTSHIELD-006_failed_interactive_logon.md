# CTSHIELD-006 Detection Test Report

## Detection

- Rule: CTSHIELD-006
- Title: Failed Interactive Logon
- Rule file: `detections/sigma/CTSHIELD-006_failed_interactive_logon.yml`
- Status: Experimental
- Severity: Low

## Dataset

- Dataset: EVTX-ATTACK-SAMPLES
- Source file: `Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx`
- Log channel: Security
- Event ID: 4625

## Detection Logic

The rule detects:

- Event ID `4625`
- Logon Type `2`

Event ID 4625 represents a failed logon attempt. Logon Type 2 represents an interactive logon.

## Observed Evidence

The test dataset contained one matching event.

Observed fields included:

- Event ID: `4625`
- TargetUserName: `IEUser`
- LogonType: `2`
- Failure status: `0xc000006d`
- SubStatus: `0xc000006a`
- LogonProcessName: `Chrome`
- AuthenticationPackageName: `Negotiate`
- ProcessName: `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`
- Computer: `MSEDGEWIN10`

The observed event demonstrates that the detection logic matches the expected failed interactive logon telemetry.

## Test Method

The test was executed using the project detection test:

`tests/detections/test_ctshield_006.py`

Command:

`python -m pytest -q tests/detections/test_ctshield_006.py -s`

Result:

`CTSHIELD-006 matched 1 failed interactive logon event(s).`

`1 passed in 0.08s`

## False Positive Considerations

Potential benign causes include:

- Users entering an incorrect password
- Local applications attempting authentication with invalid credentials
- User account configuration or credential synchronization problems

The observed event alone does not establish malicious activity.

## ATT&CK Mapping

The Sigma rule currently uses the `attack.credential-access` tactic tag.

An exact ATT&CK technique mapping has not been assigned to this rule based solely on the observed failed interactive logon event.

## Test Conclusion

CTSHIELD-006 successfully matched the expected Event ID 4625 interactive logon failure in the selected public telemetry.

The detection is therefore validated against an actual dataset event.

The result does not by itself establish an attack or malicious intent.
