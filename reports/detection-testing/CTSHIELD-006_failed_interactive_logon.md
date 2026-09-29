k# CTSHIELD-006 Detection Test Report

## Detection

- **Rule:** CTSHIELD-006
- **Title:** Failed Interactive Logon
- **Rule file:** `detections/sigma/CTSHIELD-006_failed_interactive_logon.yml`
- **ATT&CK Technique:** T1110.001 - Password Guessing
- **Tactic:** Credential Access
- **Status:** Experimental
- **Severity:** Low

## Dataset

- **Dataset:** EVTX-ATT&CK-SAMPLES
- **Source file:** `Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx`
- **Log channel:** Security
- **Event ID:** 4625

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

The test was executed using:

`tests/detections/test_ctshield_006.py`

Command:

`python -m pytest -q tests/detections/test_ctshield_006.py -s`

Result:

```text
CTSHIELD-006 matched 1 failed interactive logon event(s).
1 passed in 0.08s
