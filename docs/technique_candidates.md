# ATT&CK Technique Candidates

## Purpose

This document records candidate MITRE ATT&CK techniques for detection engineering based on telemetry observed in the selected EVTX-ATT&CK-SAMPLES dataset.

Candidates will be validated against:

1. Actual event telemetry
2. Available fields
3. ATT&CK technique definitions
4. Detection feasibility
5. Availability of test evidence

## Candidate Techniques

| Candidate | Telemetry | Event ID | Validation Status |
|---|---|---:|---|
| Clear Windows Event Logs | Windows Security | 1102 | Validated - T1685.005 |
| Logon activity | Windows Security | 4624/4625 | Pending |
| Directory-service access | Windows Security | 4662 | Pending |
| Object access | Windows Security | 4663 | Pending |
| Network connection | Windows Security | 5156 | Pending |
| Process creation | Sysmon | 1 | Pending |
| Network connection | Sysmon | 3 | Pending |
| Process termination | Sysmon | 5 | Pending |

## Selection Criteria

A technique should only be selected for detection development when:

- Relevant telemetry exists in the dataset.
- Required fields can be extracted reliably.
- The behavior can be expressed using Sigma detection logic.
- Test evidence can be collected from actual telemetry.
- False-positive considerations can be documented.
- The ATT&CK mapping can be supported by the technique definition and observed behavior.
