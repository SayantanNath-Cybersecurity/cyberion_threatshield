# CTSHIELD-009 Detection Test Report

## Detection

- Rule: CTSHIELD-009
- Title: Windows Test Signing Enabled
- Rule file: `detections/sigma/CTSHIELD-009_test_signing_enabled.yml`
- Status: Experimental
- Severity: High

## Dataset

- Dataset: EVTX-ATT&CK-SAMPLES
- Source file: `Defense Evasion/DE_KernelDebug_and_TestSigning_ON_Security_4826.evtx`
- Log channel: Security
- Event ID: 4826

## Detection Logic

The rule detects Windows Security Event ID `4826` when:

- `TestSigning` is `%%1842`

The selected telemetry contains six Event ID 4826 records. Five records contain `TestSigning: %%1843`, while one record contains `TestSigning: %%1842`.

The rule therefore focuses specifically on the observed test-signing-enabled state.

## Observed Evidence

The matching event contained:

- Event ID: `4826`
- SubjectUserSid: `S-1-5-18`
- SubjectUserName: `-`
- SubjectDomainName: `-`
- TestSigning: `%%1842`
- KernelDebug: `%%1842`
- FlightSigning: `%%1843`
- DisableIntegrityChecks: `%%1843`

The dataset therefore contains one event matching the detection condition.

## Test Method

The test was executed using:

`tests/detections/test_ctshield_009.py`

Command:

`python -m pytest -q tests/detections/test_ctshield_009.py -s`

Result:

`CTSHIELD-009 matched 1 test-signing-enabled event(s).`

`1 passed in 0.07s`

## False Positive Considerations

Potential benign causes include:

- Authorized driver development or testing environments
- Legitimate kernel or driver troubleshooting
- Approved security research environments

The observed event indicates a test-signing configuration state but does not by itself establish malicious intent.

## ATT&CK Mapping

- Technique: T1553.006
- Technique name: Code Signing Policy Modification
- Tactic: Defense Impairment

The detection is mapped to T1553.006 based on the observed Windows test-signing configuration state.

## Test Conclusion

CTSHIELD-009 successfully matched one test-signing-enabled Event ID 4826 record in the selected public EVTX telemetry.

The Sigma rule passed validation and the corresponding automated test passed against the actual dataset.

The detection provides a focused signal for Windows test-signing configuration changes that may warrant investigation.
