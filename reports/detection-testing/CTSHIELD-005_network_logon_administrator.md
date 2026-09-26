# CTSHIELD-005 Detection Test Evidence

## Detection

- Rule: CTSHIELD-005
- Title: Network Logon to Administrator Account
- Rule file: `detections/sigma/CTSHIELD-005_network_logon_administrator.yml`
- ATT&CK technique: T1078 - Valid Accounts
- Status: Experimental
- Severity: Medium

## Dataset

- Dataset: EVTX-ATT&CK-SAMPLES
- Source repository: `https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES`
- Dataset commit: `4ceed2f4706daf601c212a8f91c113dd85349a2c`
- Test file: `Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx`

## Detection Logic

The rule detects Windows Security Event ID 4624 where:

- `LogonType` equals `3`
- `TargetUserName` equals `Administrator`

Logon Type 3 represents a network logon in the observed Windows Security telemetry.

## Observed Telemetry

The test dataset contains three matching Event ID 4624 records.

Observed characteristics include:

- `TargetUserName`: `Administrator`
- `LogonType`: `3`
- `IpAddress`: `10.0.2.17`
- `LogonProcessName`: `Kerberos` or `NtLmSsp`
- `AuthenticationPackageName`: `Kerberos` or `NTLM`

The dataset also contains other Event ID 4624 records, including machine-account authentication and a network logon for `user01`.

## Test Method

The test parses the actual EVTX telemetry using `python-evtx`.

For each Event ID 4624 record, the test extracts the EventData fields and checks for:

1. `LogonType = 3`
2. `TargetUserName = Administrator`

## Test Result

```text
CTSHIELD-005 matched 3 Administrator network logon event(s).
1 passed in 0.10s
