# Cyberion ThreatShield Data Dictionary

**Version:** 0.1  
**Status:** Initial telemetry inventory  
**Dataset:** EVTX-ATTACK-SAMPLES  
**Primary format:** Windows EVTX  
**Analysis environment:** Kali GNU/Linux

---

## 1. Purpose

This document records the telemetry structures and fields observed during initial analysis of the EVTX-ATTACK-SAMPLES dataset.

Fields are documented only after being observed in actual EVTX records.

---

## 2. Telemetry Source Types

Initial analysis has identified two primary telemetry source types:

1. Windows Security Event Log
2. Microsoft Sysmon Operational Event Log

---

## 3. Windows Security Event Log

### Common System Fields

Observed across sampled Windows Security events:

| Field | Description |
|---|---|
| Provider | Event provider name |
| EventID | Windows event identifier |
| Version | Event schema version |
| Level | Event severity level |
| Task | Event task identifier |
| Opcode | Event opcode |
| Keywords | Event keyword mask |
| TimeCreated | Event timestamp |
| EventRecordID | Event record identifier |
| Channel | Windows event channel |
| Computer | Host associated with the event |
| Execution.ProcessID | Process associated with event generation |
| Execution.ThreadID | Thread associated with event generation |

---

## 4. Windows Security Event ID 1102

### Observed Purpose

Security event log clearing.

### Observed Fields

| Field | Example / Description |
|---|---|
| SubjectUserSid | SID of the user associated with the action |
| SubjectUserName | Username associated with the action |
| SubjectDomainName | User domain |
| SubjectLogonId | Associated logon identifier |

### Detection Relevance

Event ID 1102 can provide telemetry for security event log clearing activity.

---

## 5. Windows Security Event ID 4624

### Observed Purpose

Successful logon activity.

### Observed Fields

| Field | Description |
|---|---|
| SubjectUserSid | SID of initiating security principal |
| SubjectUserName | Initiating username |
| SubjectDomainName | Initiating domain |
| SubjectLogonId | Initiating logon identifier |
| TargetUserSid | Target account SID |
| TargetUserName | Target account |
| TargetDomainName | Target account domain |
| TargetLogonId | Target logon identifier |
| LogonType | Windows logon type |
| LogonProcessName | Logon process |
| AuthenticationPackageName | Authentication package |
| WorkstationName | Associated workstation |
| LogonGuid | Logon GUID |
| ProcessId | Associated process ID |
| ProcessName | Associated process |
| IpAddress | Source IP when available |
| IpPort | Source port when available |
| ImpersonationLevel | Impersonation level |
| RestrictedAdminMode | Restricted administrator mode state |
| TargetOutboundUserName | Outbound username |
| TargetOutboundDomainName | Outbound domain |
| VirtualAccount | Virtual account indicator |
| TargetLinkedLogonId | Linked logon identifier |
| ElevatedToken | Elevated token indicator |

---

## 6. Windows Security Event ID 4625

### Observed Purpose

Failed logon activity.

### Observed Fields

| Field | Description |
|---|---|
| SubjectUserSid | SID of initiating security principal |
| SubjectUserName | Initiating username |
| SubjectDomainName | Initiating domain |
| SubjectLogonId | Initiating logon identifier |
| TargetUserSid | Target account SID |
| TargetUserName | Target account |
| TargetDomainName | Target account domain |
| Status | Logon failure status |
| FailureReason | Failure reason |
| SubStatus | Detailed failure status |
| LogonType | Windows logon type |
| LogonProcessName | Logon process |
| AuthenticationPackageName | Authentication package |
| WorkstationName | Associated workstation |
| ProcessId | Associated process ID |
| ProcessName | Associated process |
| IpAddress | Source IP when available |
| IpPort | Source port when available |

---

## 7. Windows Security Event ID 4662

### Observed Purpose

Directory Service object access telemetry.

### Observed Fields

| Field | Description |
|---|---|
| SubjectUserSid | User SID |
| SubjectUserName | Username |
| SubjectDomainName | User domain |
| SubjectLogonId | Logon identifier |
| ObjectServer | Object server |
| ObjectType | Object type |
| ObjectName | Object name |
| OperationType | Operation type |
| HandleId | Object handle |
| AccessList | Access rights |
| AccessMask | Access mask |
| Properties | Accessed properties |
| AdditionalInfo | Additional information |
| AdditionalInfo2 | Additional information |

### Detection Relevance

Event ID 4662 can provide telemetry relevant to directory-service access investigations.

---

## 8. Windows Security Event ID 4663

### Observed Purpose

Object access telemetry.

### Observed Fields

| Field | Description |
|---|---|
| SubjectUserSid | User SID |
| SubjectUserName | Username |
| SubjectDomainName | User domain |
| SubjectLogonId | Logon identifier |
| ObjectServer | Object server |
| ObjectType | Object type |
| ObjectName | Object accessed |
| HandleId | Object handle |
| AccessList | Access rights |
| AccessMask | Access mask |
| ProcessId | Associated process |
| ProcessName | Associated process name |

---

## 9. Windows Security Event ID 5156

### Observed Purpose

Windows Filtering Platform network connection telemetry.

### Observed Fields

| Field | Description |
|---|---|
| ProcessID | Associated process ID |
| Application | Application path |
| Direction | Network direction |
| SourceAddress | Source address |
| SourcePort | Source port |
| DestAddress | Destination address |
| DestPort | Destination port |
| Protocol | Network protocol |
| FilterRTID | Filter runtime identifier |
| LayerName | Filtering layer |
| LayerRTID | Layer runtime identifier |
| RemoteUserID | Remote user SID |
| RemoteMachineID | Remote machine SID |

---

## 10. Microsoft Sysmon Operational Log

### Sysmon Event ID 1

### Observed Purpose

Process creation telemetry.

### Observed Fields

| Field | Description |
|---|---|
| RuleName | Sysmon rule name |
| UtcTime | Event timestamp |
| ProcessGuid | Process GUID |
| ProcessId | Process identifier |
| Image | Process executable |
| FileVersion | File version when available |
| Description | File description |
| Product | Product name |
| Company | File company |
| CommandLine | Process command line |
| CurrentDirectory | Process working directory |
| User | Process user |
| LogonGuid | Associated logon GUID |
| LogonId | Associated logon identifier |
| TerminalSessionId | Terminal session identifier |
| IntegrityLevel | Process integrity level |
| Hashes | File hashes |
| ParentProcessGuid | Parent process GUID |
| ParentProcessId | Parent process identifier |
| ParentImage | Parent executable |
| ParentCommandLine | Parent command line |

---

## 11. Microsoft Sysmon Event ID 3

### Observed Purpose

Network connection telemetry.

### Observed Fields

| Field | Description |
|---|---|
| RuleName | Sysmon rule name |
| UtcTime | Event timestamp |
| ProcessGuid | Process GUID |
| ProcessId | Process identifier |
| Image | Process executable |
| User | Process user |
| Protocol | Network protocol |
| Initiated | Connection initiation state |
| SourceIsIpv6 | IPv6 indicator |
| SourceIp | Source IP |
| SourceHostname | Source hostname |
| SourcePort | Source port |
| SourcePortName | Source service name |
| DestinationIsIpv6 | IPv6 indicator |
| DestinationIp | Destination IP |
| DestinationHostname | Destination hostname |
| DestinationPort | Destination port |
| DestinationPortName | Destination service name |

---

## 12. Initial Detection Opportunities

Based on observed telemetry, the following areas have been identified for further detection engineering:

- Security event log clearing
- Authentication anomalies
- Directory Service access
- Object access
- Suspicious process creation
- Suspicious command-line execution
- Suspicious network connections
- Process-to-network correlation

These are candidate areas for subsequent ATT&CK mapping and Sigma engineering. They are not yet validated detection rules.

---

## 13. Evidence Sources

The initial field inventory was derived from direct inspection of EVTX records within:

`data/raw/evtx-attack-samples/`

Sampled telemetry includes:

- Windows Security Event ID 1102
- Windows Security Event IDs 4624 and 4625
- Windows Security Event ID 4662
- Windows Security Event ID 4663
- Windows Security Event ID 5156
- Sysmon Event ID 1
- Sysmon Event ID 3
- Sysmon Event ID 5

---

## 14. Data Handling Principle

Raw EVTX files under `data/raw/` must remain unchanged.

Any extracted, normalized, converted, or derived data must be stored under `data/processed/`.

This preserves traceability between detection results and the original telemetry evidence.
