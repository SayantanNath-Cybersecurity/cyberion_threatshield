# CTSHIELD-014 Detection Test Report

## Detection

- Rule: CTSHIELD-014
- Title: Windows Computer Account Creation
- Rule file: `detections/sigma/CTSHIELD-014_computer_account_creation.yml`
- Status: Experimental
- Severity: Medium

## Dataset

- Dataset: EVTX-ATT&CK-SAMPLES
- Source file: `Defense Evasion/DE_Fake_ComputerAccount_4720.evtx`
- Log channel: Security
- Detection event: Event ID 4720

## Detection Logic

The rule detects Windows Security Event ID `4720` where both `TargetUserName` and `SamAccountName` contain the dollar-sign computer-account naming pattern.

This focuses the detection on computer-account creation rather than all account-creation events.

## Observed Evidence

The selected EVTX file contained two Event ID `4720` events matching the detection.

Observed values included:

- `TargetUserName`: `$`
- `SamAccountName`: `$`
- `TargetDomainName`: `3B`
- `SubjectUserName`: `01566S-WIN16-IR$`
- `SubjectUserSid`: `S-1-5-18`
- `PrimaryGroupId`: `513`
- `NewUacValue`: `0x15`

The two account-creation events occurred approximately 54 seconds apart.

The observed telemetry demonstrates computer-account creation activity. The event itself does not independently establish malicious intent.

## Test Method

The automated test is located at:

`tests/detections/test_ctshield_014.py`

Command:

`python -m pytest -q tests/detections/test_ctshield_014.py -s`

Result:

`CTSHIELD-014 matched 2 computer account creation event(s).`

`1 passed in 0.06s`

## Sigma Validation

The rule was validated using Sigma CLI.

Result:

`Found 0 errors, 0 condition errors and 0 issues.`

## False Positive Considerations

Potential benign causes include:

- Legitimate domain computer joins
- Authorized workstation or server provisioning
- Domain administration and infrastructure management
- Automated machine-account provisioning

Investigation should consider the creating account, domain, target computer identity, timing, authentication activity, subsequent group membership changes, and related directory-service activity.

## ATT&CK Mapping

- Technique: T1136.002
- Technique name: Create Account: Domain Account
- Tactic: Persistence

## Test Conclusion

CTSHIELD-014 successfully matched two computer-account creation events in the selected public EVTX telemetry.

The Sigma rule passed validation and the corresponding automated test passed against the actual dataset.

The detection provides a focused signal for investigating newly created computer accounts in Windows domain telemetry.
