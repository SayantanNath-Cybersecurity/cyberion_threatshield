# CTSHIELD-010 Detection Test Report

## Detection

- Rule: CTSHIELD-010
- Title: Suspicious Browser Credential Store File Access
- Rule file: `detections/sigma/CTSHIELD-010_browser_credential_store_access.yml`
- Status: Experimental
- Severity: High

## Dataset

- Dataset: EVTX-ATT&CK-SAMPLES
- Source file: `Credential Access/CA_chrome_firefox_opera_4663.evtx`
- Log channel: Security
- Event ID: 4663

## Detection Logic

The rule detects Windows Security Event ID `4663` file-access events where the accessed object path contains browser credential-store locations associated with:

- Opera
- Firefox
- Google Chrome

The detection also requires `ObjectType: File`.

## Observed Evidence

The selected EVTX file contained four matching Event ID 4663 records.

Observed credential-store paths included:

- `C:\Users\IEUser\AppData\Roaming\Opera Software\Opera Stable\Login Data`
- `C:\Users\IEUser\AppData\Roaming\Mozilla\Firefox\Profiles\kushu3sd.default\key4.db`
- `C:\Users\IEUser\AppData\Roaming\Mozilla\Firefox\Profiles\kushu3sd.default\logins.json`
- `C:\Users\IEUser\AppData\Local\Google\Chrome\User Data\Default\Login Data`

The matching events also showed:

- ObjectType: `File`
- AccessMask: `0x00000001`
- ProcessName: `C:\Users\Defau1t\wsus.exe`

The observed telemetry demonstrates that the detection identifies file-access events involving browser credential-store locations.

## Test Method

The test was executed using:

`tests/detections/test_ctshield_010.py`

Command:

`python -m pytest -q tests/detections/test_ctshield_010.py -s`

Result:

`CTSHIELD-010 matched 4 browser credential-store access event(s).`

`1 passed in 0.07s`

## False Positive Considerations

Potential benign causes include:

- Legitimate browser processes accessing their own credential databases
- Browser profile maintenance or backup software
- Authorized forensic or security tooling

The observed file-access events alone do not establish malicious credential theft.

## ATT&CK Mapping

- Technique: T1555.003
- Technique name: Credentials from Web Browsers
- Tactic: Credential Access

The detection is mapped to browser credential access based on the observed access to Chrome, Firefox, and Opera credential-store files.

## Test Conclusion

CTSHIELD-010 successfully matched four browser credential-store access events in the selected public EVTX telemetry.

The Sigma rule passed validation and the corresponding automated test passed against the actual dataset.

The detection provides a focused signal for file access involving browser credential stores, with process context available for subsequent investigation.
