# CTSHIELD-011 Detection Test Report

## Detection

- Rule: CTSHIELD-011
- Title: Plink Network Connection Indicative of Protocol Tunneling
- Rule file: `detections/sigma/CTSHIELD-011_plink_network_tunneling.yml`
- Status: Experimental
- Severity: High

## Dataset

- Dataset: EVTX-ATT&CK-SAMPLES
- Source file: `Command and Control/DE_RDP_Tunnel_5156.evtx`
- Log channel: Security
- Event ID: 5156

## Detection Logic

The rule detects Windows Security Event ID `5156` network connection events where the `Application` field identifies `plink.exe`.

Plink is a command-line SSH client that can be used for network tunneling and port forwarding.

The detection focuses on the executable identity rather than a fixed destination address or port, allowing the rule to identify Plink network connections across different tunneling configurations.

## Observed Evidence

The selected EVTX file contained three Event ID 5156 events matching `plink.exe`.

Observed network activity included:

- Source address: `10.0.2.17`
- Destination address: `10.0.2.18`
- Destination port: `80`
- Protocol: `6`

The same telemetry also contained a Plink connection involving:

- Source address: `127.0.0.1`
- Destination address: `127.0.0.2`
- Destination port: `3389`
- Protocol: `6`

The associated process creation telemetry identified:

`C:\Users\user01\Desktop\plink.exe`

The observed network activity is consistent with Plink being used as part of a tunneling or port-forwarding workflow.

## Test Method

The automated test is located at:

`tests/detections/test_ctshield_011.py`

Command:

`python -m pytest -q tests/detections/test_ctshield_011.py -s`

Result:

`CTSHIELD-011 matched 3 plink.exe network connection event(s).`

`1 passed in 0.51s`

## Sigma Validation

The rule was validated using Sigma CLI.

Result:

`Found 0 errors, 0 condition errors and 0 issues.`

## False Positive Considerations

Potential benign causes include:

- Authorized administrators using Plink for SSH tunneling
- Approved remote administration or troubleshooting
- Security testing and penetration testing activity
- Legitimate port forwarding performed by authorized users

The presence of `plink.exe` alone does not establish malicious activity. Investigation should consider the user, destination, ports, command-line context where available, and surrounding authentication or process telemetry.

## ATT&CK Mapping

- Technique: T1572
- Technique name: Protocol Tunneling
- Tactic: Command and Control

The mapping is based on the use of Plink network connections in telemetry associated with tunneling and port-forwarding behavior.

## Test Conclusion

CTSHIELD-011 successfully matched three `plink.exe` network connection events in the selected public EVTX telemetry.

The Sigma rule passed validation and the corresponding automated test passed against the actual dataset.

The detection provides a focused network telemetry signal for subsequent investigation of potential protocol tunneling activity.
