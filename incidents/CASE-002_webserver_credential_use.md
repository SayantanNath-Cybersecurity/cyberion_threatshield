# CASE-002: Web Server Credential Use Activity

## Case Overview

- **Case ID:** CASE-002
- **Dataset:** EVTX-ATTACK-SAMPLES
- **Sample:** `Privilege Escalation/Runas_4624_4648_Webshell_CreateProcessAsUserA.evtx`
- **Dataset Commit:** `4ceed2f4706daf601c212a8f91c113dd85349a2c`
- **Primary ATT&CK Technique:** T1505.003 - Server Software Component: Web Shell
- **Associated Technique:** T1078 - Valid Accounts
- **Case Classification:** True Positive
- **Investigation Status:** Closed

## Detection / Investigation Trigger

The selected telemetry records explicit credential use and a subsequent successful logon associated with the IIS worker process `w3wp.exe`.

The investigation was initiated to determine whether the observed authentication activity represented web-server-mediated account use consistent with the attack sample scenario.

## Evidence Sources

The investigation used Windows Security Event Log telemetry from the selected EVTX sample.

Relevant events:

- Event ID `4648` - explicit credential use
- Event ID `4624` - successful logon

Both events reference the IIS worker process:

`C:\Windows\System32\inetsrv\w3wp.exe`

## Timeline

### Event 1: Explicit Credential Use

Windows Security Event ID `4648` was recorded at:

`2020-09-15 18:04:39.987053+00:00`

Observed fields:

- SubjectUserName: `svc01`
- SubjectDomainName: `MSEDGEWIN10`
- TargetUserName: `IEUser`
- TargetDomainName: `MSEDGEWIN10`
- TargetServerName: `localhost`
- ProcessName: `C:\Windows\System32\inetsrv\w3wp.exe`
- IpAddress: `-`
- IpPort: `-`

The event indicates that the `svc01` security context explicitly used credentials associated with the `IEUser` account through the IIS worker process.

### Event 2: Successful Logon

Windows Security Event ID `4624` was recorded at:

`2020-09-15 18:04:39.987123+00:00`

Observed fields:

- SubjectUserName: `svc01`
- SubjectDomainName: `MSEDGEWIN10`
- TargetUserName: `IEUser`
- TargetDomainName: `MSEDGEWIN10`
- LogonType: `3`
- LogonProcessName: `Advapi`
- AuthenticationPackageName: `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`
- ProcessName: `C:\Windows\System32\inetsrv\w3wp.exe`
- IpAddress: `-`
- IpPort: `-`
- ElevatedToken: `%%1842`
- VirtualAccount: `%%1843`

The Event ID `4624` occurred approximately 70 microseconds after the Event ID `4648`.

## Event Relationship

The observed sequence is:

`w3wp.exe`

↓

`Event 4648: explicit credential use`

↓

`TargetUserName: IEUser`

↓

`Event 4624: successful LogonType 3`

Both events reference the same IIS worker process and the same subject and target accounts.

This provides a direct relationship between explicit credential use and the subsequent successful logon recorded in the Windows Security telemetry.

## Investigation Findings

The investigation established the following:

1. IIS worker process `w3wp.exe` was associated with Event ID `4648`.
2. The subject account was `svc01`.
3. The target account was `IEUser`.
4. The target server was `localhost`.
5. A successful Event ID `4624` followed the explicit credential-use event.
6. The successful logon used LogonType `3`.
7. The successful logon was also associated with `w3wp.exe`.
8. The two events occurred approximately 70 microseconds apart.

These observations establish web-server-associated explicit credential use followed by successful authentication activity.

## Root Cause Analysis

The available telemetry indicates that the IIS worker process `w3wp.exe` was involved in explicit credential use for the `IEUser` account and a subsequent successful logon.

The sample filename identifies the scenario as involving a webshell and `CreateProcessAsUserA`, but the available Event ID `4648` and `4624` records alone do not prove the installation of a web shell or reveal the exact web request, script, command, or file that initiated the activity.

Therefore, the investigation attributes the observed authentication sequence to activity mediated by the IIS worker process while avoiding unsupported claims about the exact webshell implementation.

## MITRE ATT&CK Mapping

### T1505.003 - Server Software Component: Web Shell

The selected attack sample is associated with web-server-based execution activity.

The observed telemetry shows IIS `w3wp.exe` participating in explicit credential use and successful authentication. This is relevant to investigation of web-shell activity, although the available Security events do not independently prove web-shell installation.

### T1078 - Valid Accounts

The telemetry shows explicit use of the `IEUser` account followed by a successful logon.

The logs demonstrate use of an existing account, but they do not establish whether the credentials were compromised or otherwise abused by an adversary.

Therefore, T1078 is recorded as an associated investigative mapping rather than proof of malicious credential compromise.

## Impact Assessment

The confirmed impact in the available telemetry is successful account authentication associated with the IIS worker process.

The sample does not provide sufficient evidence to establish:

- Data theft
- Persistence beyond the observed activity
- Additional host compromise
- Lateral movement
- Destructive activity
- Successful execution of a specific attacker command

The investigation therefore limits the confirmed impact to the observed authentication and process-associated activity.

## Response Considerations

For a live environment, an analyst investigating comparable activity should:

1. Identify the IIS application and site associated with `w3wp.exe`.
2. Review IIS access logs around the event timestamp.
3. Search for web requests associated with the affected application.
4. Review file creation and modification activity in web directories.
5. Review process creation telemetry generated by `w3wp.exe`.
6. Validate whether `IEUser` was authorized for the observed operation.
7. Review credential use involving `svc01` and `IEUser`.
8. Search for the same account and IIS process relationship on other hosts.
9. Preserve IIS, Windows Security, and endpoint telemetry before remediation.
10. If unauthorized web-server activity is confirmed, isolate the affected service or host according to incident response procedures.

## Closure Classification

**True Positive**

The classification refers to the confirmed authentication activity represented in the attack sample.

The investigation confirms:

- Explicit credential use through `w3wp.exe`.
- Targeting of the `IEUser` account.
- A subsequent successful LogonType `3` authentication.
- Matching IIS process context across Events `4648` and `4624`.

The classification does not independently establish that a real-world adversary compromised the credentials or that the webshell was installed solely from these events.

## Detection Gap

The current detection library contains detections for:

- Windows Security Event ID `1102`
- Kerberos pre-authentication failure Event ID `4771`

It does not currently contain a dedicated detection for web-server-associated explicit credential use.

This investigation identifies an opportunity for a correlation-style detection combining:

- Event ID `4648`
- Event ID `4624`
- `ProcessName = C:\Windows\System32\inetsrv\w3wp.exe`
- Matching subject and target accounts
- A short temporal relationship between the events

Such a detection could provide stronger context than either event considered independently.

## Evidence Limitations

The selected sample contains a limited set of Windows Security events.

The available telemetry does not establish:

- The exact web request that initiated the activity.
- The webshell filename or contents.
- Whether a webshell was newly installed.
- The exact command executed through the web application.
- Whether the `IEUser` credentials were compromised.
- The identity of an operator.
- Whether other systems were affected.

These limitations are recorded to prevent unsupported conclusions.

## Reproducibility

The raw EVTX dataset is maintained outside the Git repository.

Dataset provenance:

`4ceed2f4706daf601c212a8f91c113dd85349a2c`

Sample:

`Privilege Escalation/Runas_4624_4648_Webshell_CreateProcessAsUserA.evtx`

The investigation can be reproduced by parsing the selected EVTX file and reviewing Event IDs `4648` and `4624`, with particular attention to:

- `svc01`
- `IEUser`
- `MSEDGEWIN10`
- `localhost`
- `w3wp.exe`
- LogonType `3`
- Event timestamps
