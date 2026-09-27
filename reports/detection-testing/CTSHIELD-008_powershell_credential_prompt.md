# CTSHIELD-008 Detection Test Report

## Detection

- Rule: CTSHIELD-008
- Title: PowerShell Credential Prompt and Credential Extraction
- Rule file: `detections/sigma/CTSHIELD-008_powershell_credential_prompt.yml`
- Status: Experimental
- Severity: High

## Dataset

- Dataset: EVTX-ATT&CK-SAMPLES
- Source file: `Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.evtx`
- Event ID: 4104
- Log type: PowerShell Script Block Logging

## Detection Logic

The rule detects Event ID `4104` when the `ScriptBlockText` field contains both:

- `PromptForCredential`
- `GetNetworkCredential().password`

These indicators identify PowerShell script activity that prompts for Windows credentials and accesses the resulting credential password.

## Observed Evidence

The selected EVTX file contained two Event ID 4104 records.

One event contained the credential-prompting behavior targeted by the rule.

Observed script content included:

- `PromptForCredential`
- `GetNetworkCredential().password`
- `PrincipalContext`
- `ValidateCredentials`
- Collection of the resulting username, domain, and password values

The matching event therefore contains the specific credential-prompting and credential-extraction indicators targeted by CTSHIELD-008.

## Test Method

The test was executed using:

`tests/detections/test_ctshield_008.py`

Command:

`python -m pytest -q tests/detections/test_ctshield_008.py -s`

Result:

`CTSHIELD-008 matched 1 PowerShell credential-prompting event(s).`

`1 passed in 0.05s`

## False Positive Considerations

Potential benign causes include:

- Legitimate PowerShell scripts that prompt users for credentials
- Administrative automation involving credential validation
- Security or identity management tooling using PowerShell credential APIs

The observed event provides telemetry consistent with credential-prompting activity but does not by itself establish malicious intent.

## ATT&CK Mapping

- Technique: T1059.001
- Technique name: PowerShell
- Tactic: Execution

The detection is mapped to PowerShell execution based on the Event ID 4104 Script Block Logging telemetry.

## Test Conclusion

CTSHIELD-008 successfully matched one PowerShell credential-prompting event in the selected public EVTX telemetry.

The Sigma rule passed validation and the corresponding automated test passed against the actual dataset.

The detection provides a focused signal for PowerShell script blocks that combine credential prompting with password extraction.
