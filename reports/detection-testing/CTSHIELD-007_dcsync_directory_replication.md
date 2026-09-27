# CTSHIELD-007 Detection Test Report

## Detection

- Rule: CTSHIELD-007
- Title: Directory Replication Access Indicative of DCSync
- Rule file: `detections/sigma/CTSHIELD-007_dcsync_directory_replication.yml`
- Status: Experimental
- Severity: High

## Dataset

- Dataset: EVTX-ATT&CK-SAMPLES
- Source file: `Credential Access/CA_DCSync_4662.evtx`
- Log channel: Security
- Event ID: 4662

## Detection Logic

The rule detects Windows Security Event ID `4662` when the event contains:

- `ObjectServer: DS`
- `AccessMask: 0x00000100`
- A replication-related extended-right GUID in the `Properties` field

The replication-related GUIDs used by the detection are:

- `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}`
- `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}`

## Observed Evidence

The selected EVTX file contained three Event ID 4662 records matching the detection logic.

Common observed fields included:

- Event ID: `4662`
- SubjectUserName: `Administrator`
- SubjectDomainName: `insecurebank`
- ObjectServer: `DS`
- OperationType: `Object Access`
- AccessMask: `0x00000100`
- AccessList: `%%7688`

The `Properties` field contained replication-related GUIDs across the observed events:

- `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}`
- `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}`

The observed telemetry therefore provides direct evidence that the detection logic matches the selected DCSync-related directory service access records.

## Test Method

The test was executed using:

`tests/detections/test_ctshield_007.py`

Command:

`python -m pytest -q tests/detections/test_ctshield_007.py -s`

Result:

`CTSHIELD-007 matched 3 DCSync directory replication access event(s).`

`1 passed in 0.07s`

## False Positive Considerations

Potential benign causes include:

- Legitimate directory replication activity
- Authorized domain controller operations
- Identity or directory management software requesting directory replication permissions
- Authorized administrative activity involving directory services

The presence of matching Event ID 4662 telemetry does not by itself establish malicious intent.

## ATT&CK Mapping

- Technique: T1003.006
- Technique name: DCSync
- Tactic: Credential Access

The detection is mapped to the DCSync technique through the replication-related directory service access telemetry observed in the dataset.

## Test Conclusion

CTSHIELD-007 successfully matched three DCSync-related directory replication access events in the selected public EVTX telemetry.

The Sigma rule passed validation and the corresponding automated test passed against the actual dataset.

The observed events provide telemetry consistent with directory replication access associated with DCSync, but the events alone do not establish malicious intent.
