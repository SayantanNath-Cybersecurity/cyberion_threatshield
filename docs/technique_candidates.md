# ATT&CK Technique Candidates and Assessment Basis

## Purpose

This document records the MITRE ATT&CK techniques considered during detection engineering and the evidence basis used to assess them.

Technique selection is based on:

1. Actual telemetry observed in the selected EVTX-ATTACK-SAMPLES dataset.
2. Available event fields.
3. Detection feasibility.
4. Availability of reproducible test evidence.
5. Ability to map the behavior to a specific ATT&CK technique.
6. False-positive considerations.

The final coverage matrix distinguishes techniques with tested detection coverage from techniques assessed but not covered by a final detection.

## Data Sources Used

The primary telemetry source is:

`EVTX-ATTACK-SAMPLES`

Upstream dataset commit:

`4ceed2f4706daf601c212a8f91c113dd85349a2c`

Observed telemetry includes Windows Security and Sysmon event data.

## Final Detection-Mapped Techniques

| Technique ID | Technique | Supporting Rule(s) | Assessment |
|---|---|---|---|
| T1685.005 | Clear Windows Event Logs | CTSHIELD-001 | Covered |
| T1110.001 | Password Guessing | CTSHIELD-002, CTSHIELD-006 | Covered |
| T1047 | Windows Management Instrumentation | CTSHIELD-003, CTSHIELD-004, CTSHIELD-019 | Covered |
| T1078.001 | Default Accounts | CTSHIELD-005 | Covered |
| T1003.006 | DCSync | CTSHIELD-007 | Covered |
| T1059.001 | PowerShell | CTSHIELD-008 | Covered |
| T1553.006 | Code Signing Policy Modification | CTSHIELD-009 | Covered |
| T1555.003 | Credentials from Web Browsers | CTSHIELD-010 | Covered |
| T1572 | Protocol Tunneling | CTSHIELD-011 | Covered |
| T1053.005 | Scheduled Task/Job: Scheduled Task | CTSHIELD-012 | Covered |
| T1543.003 | Windows Service | CTSHIELD-013 | Covered |
| T1136.002 | Create Account: Domain Account | CTSHIELD-014 | Covered |
| T1003.001 | LSASS Memory | CTSHIELD-015 | Covered |
| T1021.006 | Windows Remote Management | CTSHIELD-016 | Covered |
| T1110.003 | Password Spraying | CTSHIELD-018 | Covered |
| T1078 | Valid Accounts | CTSHIELD-020 | Covered |

## Additional Techniques Assessed

The following techniques are included in the coverage assessment even where the final library does not claim direct detection coverage.

| Technique ID | Technique | Assessment | Reason |
|---|---|---|---|
| T1021.001 | Remote Services: Remote Desktop Protocol | Not Covered | No final rule in the library provides tested RDP-specific detection coverage. |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Not Covered | No final rule provides tested SMB/Admin Share-specific coverage. |
| T1059.003 | Windows Command Shell | Not Covered | The final library does not contain a dedicated tested command-shell detection. |
| T1505.003 | Server Software Component: Web Shell | Partially Covered | Incident investigation evidence includes IIS/web-server credential activity, but no final detection is mapped directly to T1505.003. |

## Assessment Summary

The project assesses at least 20 ATT&CK techniques through the final coverage matrix.

The assessment intentionally separates:

- **Covered:** A final detection rule is mapped to the technique and has test evidence.
- **Partially Covered:** Related telemetry or investigation evidence exists, but the final detection library does not provide direct technique-specific coverage.
- **Not Covered:** The technique was considered but no final tested detection claims coverage.

A technique is not marked Covered solely because related telemetry exists. Coverage claims require a traceable final detection rule and test evidence.
