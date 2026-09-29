# MITRE ATT&CK Coverage Matrix

## Assessment Scope

This matrix records the ATT&CK techniques assessed during the Cyberion ThreatShield detection-engineering engagement.

Coverage status is evidence-based:

- **Covered:** A final Sigma detection is mapped to the technique and tested against actual telemetry.
- **Partially Covered:** Related telemetry or investigation evidence exists, but no final detection directly claims the technique.
- **Not Covered:** The technique was assessed but no final detection provides tested coverage.

The primary dataset is EVTX-ATTACK-SAMPLES at upstream commit:

`4ceed2f4706daf601c212a8f91c113dd85349a2c`

## Coverage Matrix

| Tactic | Technique ID | Technique | Status | Supporting Evidence |
|---|---|---|---|---|
| Credential Access | T1110.001 | Password Guessing | Covered | CTSHIELD-002, CTSHIELD-006 |
| Credential Access | T1110.003 | Password Spraying | Covered | CTSHIELD-018 |
| Credential Access | T1078 | Valid Accounts | Covered | CTSHIELD-020 |
| Credential Access | T1078.001 | Default Accounts | Covered | CTSHIELD-005 |
| Credential Access | T1003.001 | LSASS Memory | Covered | CTSHIELD-015 |
| Credential Access | T1003.006 | DCSync | Covered | CTSHIELD-007 |
| Credential Access | T1555.003 | Credentials from Web Browsers | Covered | CTSHIELD-010 |
| Execution | T1047 | Windows Management Instrumentation | Covered | CTSHIELD-003, CTSHIELD-004, CTSHIELD-019 |
| Execution | T1059.001 | PowerShell | Covered | CTSHIELD-008 |
| Execution | T1053.005 | Scheduled Task/Job: Scheduled Task | Covered | CTSHIELD-012 |
| Persistence | T1543.003 | Windows Service | Covered | CTSHIELD-013 |
| Persistence | T1136.002 | Create Account: Domain Account | Covered | CTSHIELD-014 |
| Defense Evasion | T1685.005 | Clear Windows Event Logs | Covered | CTSHIELD-001 |
| Defense Evasion | T1553.006 | Code Signing Policy Modification | Covered | CTSHIELD-009 |
| Command and Control | T1572 | Protocol Tunneling | Covered | CTSHIELD-011 |
| Lateral Movement | T1021.006 | Windows Remote Management | Covered | CTSHIELD-016 |
| Lateral Movement | T1021.001 | Remote Services: RDP | Not Covered | No final RDP-specific detection |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Not Covered | No final SMB/Admin Share-specific detection |
| Execution | T1059.003 | Windows Command Shell | Not Covered | No final command-shell-specific detection |
| Persistence | T1505.003 | Server Software Component: Web Shell | Partially Covered | Related IIS/web-server investigation evidence; no direct final detection |

## Coverage by Tactic

### Credential Access

Covered techniques include:

- T1110.001
- T1110.003
- T1078
- T1078.001
- T1003.001
- T1003.006
- T1555.003

### Execution

Covered techniques include:

- T1047
- T1059.001
- T1053.005

T1059.003 remains not covered.

### Persistence

Covered techniques include:

- T1543.003
- T1136.002

T1505.003 is assessed as partially covered.

### Defense Evasion

Covered techniques include:

- T1685.005
- T1553.006

### Lateral Movement

T1021.006 is covered.

T1021.001 and T1021.002 remain not covered.

### Command and Control

T1572 is covered.

## Correlation Coverage

The final library contains three correlation-style detections:

| Rule | Correlation | ATT&CK |
|---|---|---|
| CTSHIELD-018 | Same source address targeting multiple accounts within 5 minutes | T1110.003 |
| CTSHIELD-019 | Network logon followed by WmiPrvSE execution on same host | T1047 |
| CTSHIELD-020 | IIS explicit credential use followed by successful network logon | T1078 |

These rules add temporal or multi-event context beyond individual atomic log records.

## Coverage Interpretation

The matrix is not intended to imply complete ATT&CK coverage.

It identifies where the project has tested detection content and where meaningful gaps remain.

The strongest coverage claims are limited to techniques with:

1. A final Sigma rule.
2. A specific ATT&CK technique mapping.
3. Actual dataset evidence.
4. Reproducible automated test evidence.
5. Documented false-positive considerations.
