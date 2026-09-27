# CTSHIELD-013 Detection Test Report

## Detection

- Rule: CTSHIELD-013
- Title: Suspicious Windows Service Creation Using Unexpected Executable
- Rule file: `detections/sigma/CTSHIELD-013_suspicious_service_creation.yml`
- Status: Experimental
- Severity: High

## Dataset

- Dataset: EVTX-ATT&CK-SAMPLES
- Source file: `Lateral Movement/LM_Remote_Service02_7045.evtx`
- Log channel: System
- Provider: Service Control Manager
- Detection event: Event ID 7045

## Detection Logic

The rule detects Windows Service Control Manager Event ID `7045` where the newly created service uses either `cmd.exe` or `calc.exe` as its image path.

The detection is intentionally narrower than detecting every service creation event. It focuses on executable values observed in the selected telemetry that are unexpected for a normal Windows service configuration.

## Observed Evidence

The selected EVTX file contained three Event ID `7045` events matching the detection.

Observed service configurations included:

- Service `spoolfool` using `cmd.exe`
- Service `spoolsv` using `cmd.exe`
- Service `remotesvc` using `calc.exe`

The matching events also showed:

- ServiceType: `user mode service`
- StartType: `auto start`
- AccountName: `LocalSystem`

The combination of automatic service startup, LocalSystem execution, and unexpected executable paths provides a focused signal for investigating potentially unauthorized service creation.

The telemetry alone does not independently establish malicious intent.

## Test Method

The automated test is located at:

`tests/detections/test_ctshield_013.py`

Command:

`python -m pytest -q tests/detections/test_ctshield_013.py -s`

Result:

`CTSHIELD-013 matched 3 suspicious service creation event(s).`

`1 passed in 0.05s`

## Sigma Validation

The rule was validated using Sigma CLI.

Result:

`Found 0 errors, 0 condition errors and 0 issues.`

## False Positive Considerations

Potential benign causes include:

- Authorized security testing
- Administrative troubleshooting using temporary service configurations
- Software installation or maintenance activity using unexpected service executables

Investigation should consider the service name, executable path, service account, startup configuration, creating process, authentication activity, and surrounding process telemetry.

## ATT&CK Mapping

- Technique: T1543.003
- Technique name: Create or Modify System Process: Windows Service
- Tactics: Persistence, Privilege Escalation

## Test Conclusion

CTSHIELD-013 successfully matched three suspicious service creation events in the selected public EVTX telemetry.

The Sigma rule passed validation and the corresponding automated test passed against the actual dataset.

The detection provides a focused signal for investigating Windows service creation involving unexpected executable paths.
