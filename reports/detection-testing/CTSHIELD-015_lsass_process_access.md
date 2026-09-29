# CTSHIELD-015 Detection Test Report

## Detection

- **Rule:** CTSHIELD-015
- **Title:** Mimikatz Process Access to LSASS
- **Rule file:** `detections/sigma/CTSHIELD-015_lsass_process_access.yml`
- **ATT&CK Technique:** T1003.001 - LSASS Memory
- **Tactic:** Credential Access
- **Status:** Experimental
- **Severity:** High

## Dataset

- **Dataset:** EVTX-ATTACK-SAMPLES
- **Source file:** `Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx`
- **Log channel:** Microsoft-Windows-Sysmon/Operational
- **Detection event:** Event ID 10

## Detection Logic

The rule detects Sysmon Event ID `10`, Process Access, where:

- `SourceImage` ends with `\mimikatz.exe`
- `TargetImage` ends with `\lsass.exe`

The detection focuses on the observed Mimikatz-to-LSASS process access pattern rather than detecting every process access event involving LSASS.

## Observed Evidence

The selected EVTX file contained one Event ID `10` event matching the detection.

Observed values included:

- `SourceProcessId`: `3588`
- `SourceImage`: `C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe`
- `TargetProcessId`: `476`
- `TargetImage`: `C:\Windows\system32\lsass.exe`
- `GrantedAccess`: `0x00001010`

The `CallTrace` field also contained multiple references to `mimikatz.exe`.

The observed telemetry is consistent with Mimikatz accessing the LSASS process for credential-related activity. The telemetry itself does not establish the intent of the operator.

## Test Method

The automated test is located at:

`tests/detections/test_ctshield_015.py`

Command:

`python -m pytest -q tests/detections/test_ctshield_015.py -s`

Result:

```text
CTSHIELD-015 matched 1 Mimikatz-to-LSASS process access event(s).
1 passed in 0.05s
