# IOC-RESEARCH-001: Telemetry-Derived Indicators

## Purpose

This document records indicators and observable artifacts identified during the threat hunting and incident investigation activities performed against the EVTX-ATTACK-SAMPLES dataset.

The purpose is to document:

- Observed indicators
- The telemetry in which each indicator appeared
- Associated investigative context
- Potential operational use
- Limitations and false-positive considerations

The indicators are derived from observed telemetry and are not assumed to represent globally malicious infrastructure.

## Dataset Provenance

- **Dataset:** EVTX-ATTACK-SAMPLES
- **Dataset Commit:** `4ceed2f4706daf601c212a8f91c113dd85349a2c`

The raw dataset is maintained outside the Git repository.

---

# Indicator Summary

| Indicator | Type | Observed In | Context | Operational Value |
|---|---|---|---|---|
| `10.0.2.17` | Private IP address | WMI investigation | Source of network logon activity | Medium in local environment |
| `172.16.66.1` | Private IP address | Kerberos hunt | Source of repeated Event ID 4771 failures | Medium in local environment |
| `Administrator` | Account | WMI investigation | Target of successful network logon | Contextual |
| `backdoor` | Account | Kerberos hunt | Target of Event ID 4771 failure | Contextual, higher investigative interest |
| `svc01` | Account | Web-server investigation | Subject of explicit credential use | Contextual |
| `IEUser` | Account | Web-server investigation | Target account in Events 4648/4624 | Contextual |
| `w3wp.exe` | Process | Web-server investigation | IIS worker process associated with credential use | High contextual value |
| `WmiPrvSE.exe` | Process | WMI investigation | WMI Provider Host associated with child process creation | High contextual value |
| `calc.exe` | Process | WMI investigation | Child process of WmiPrvSE.exe | Medium contextual value |
| `0x0000000000000ae8` | Process ID | WMI investigation | WmiPrvSE.exe process identifier | Short-lived correlation value |
| `0x0000000000000424` | Process ID | WMI investigation | calc.exe process identifier | Short-lived correlation value |

---

# 1. 10.0.2.17

## Indicator

`10.0.2.17`

## Type

Private IPv4 address.

## Observed Context

The address was observed as the source IP in successful Windows Security Event ID `4624` network logon events in the WMI investigation.

Observed account:

`Administrator`

Observed logon type:

`3`

Observed authentication package:

`Kerberos`

The same source address was associated with additional authentication activity in the selected sample.

## Operationalization

An analyst could search Windows Security telemetry for:

- Event ID `4624`
- Source IP `10.0.2.17`
- LogonType `3`

Additional searches could include:

- Event ID `4688`
- WMI Provider Host activity
- Other authentication events involving the same source

## Limitations

`10.0.2.17` is an RFC1918 private address.

It is not a globally routable indicator and should not be treated as malicious infrastructure outside the environment represented by the dataset.

Its value is primarily for:

- Internal correlation
- Hunt filtering
- Timeline reconstruction
- Identifying related events in the same dataset or environment

---

# 2. 172.16.66.1

## Indicator

`172.16.66.1`

## Type

Private IPv4 address.

## Observed Context

The address appeared as the source IP in two Windows Security Event ID `4771` Kerberos pre-authentication failure events.

The events targeted different accounts:

- `Administrator`
- `backdoor`

Both events recorded:

`Status: 0x00000018`

The events occurred within a very short interval.

## Operationalization

An analyst could search for:

- Event ID `4771`
- Source IP `172.16.66.1`
- Status `0x00000018`

Additional correlation could examine:

- Number of target accounts
- Authentication failure frequency
- Time window
- Successful authentication following failures
- Other authentication events from the same source

## Limitations

`172.16.66.1` is a private IPv4 address.

It should not be treated as globally malicious infrastructure.

Its primary value is identifying related authentication activity within the environment represented by the dataset.

---

# 3. Administrator

## Indicator

`Administrator`

## Type

Account name.

## Observed Context

The account appeared in the WMI investigation as the target of successful Event ID `4624` network logon activity.

Observed characteristics:

- LogonType: `3`
- Authentication package: `Kerberos`
- Source IP: `10.0.2.17`

## Operationalization

Search for:

- Event ID `4624`
- TargetUserName `Administrator`
- LogonType `3`
- Source addresses associated with the account

Additional correlation should consider:

- Unusual source hosts
- Authentication timing
- Process creation following authentication
- Privileged activity

## Limitations

`Administrator` is a common legitimate Windows account name.

The username alone is not an IOC.

Its investigative value comes from its relationship with the surrounding authentication and process telemetry.

---

# 4. backdoor

## Indicator

`backdoor`

## Type

Account name.

## Observed Context

The account appeared as the target of a Windows Security Event ID `4771` Kerberos pre-authentication failure.

Observed fields:

- Status: `0x00000018`
- PreAuthType: `2`
- Source IP: `172.16.66.1`
- Source port: `55968`

The same source also generated a Kerberos pre-authentication failure against `Administrator`.

## Operationalization

Search for:

- Event ID `4771`
- TargetUserName `backdoor`
- Source IP `172.16.66.1`
- Status `0x00000018`

The account should also be correlated with:

- Event ID `4624`
- Event ID `4625`
- Other authentication events
- Account creation or modification events where available

## Limitations

The account name itself does not establish malicious activity.

Its investigative importance comes from its occurrence in the authentication-failure sequence involving another account from the same source address.

---

# 5. svc01

## Indicator

`svc01`

## Type

Account name.

## Observed Context

The account appeared as the subject of Windows Security Event ID `4648`.

The event recorded explicit credential use targeting:

`IEUser`

The associated process was:

`C:\Windows\System32\inetsrv\w3wp.exe`

## Operationalization

Search for:

- Event ID `4648`
- SubjectUserName `svc01`
- TargetUserName `IEUser`
- ProcessName `w3wp.exe`

Correlate with subsequent Event ID `4624` activity.

## Limitations

The account may represent a legitimate service account.

The account name should therefore be treated as contextual evidence rather than a standalone malicious IOC.

---

# 6. IEUser

## Indicator

`IEUser`

## Type

Account name.

## Observed Context

The account appeared as the target of both:

- Event ID `4648`
- Event ID `4624`

The activity was associated with:

`C:\Windows\System32\inetsrv\w3wp.exe`

The target server recorded in Event ID `4648` was:

`localhost`

## Operationalization

Search for:

- Event ID `4648`
- Event ID `4624`
- TargetUserName `IEUser`
- ProcessName `w3wp.exe`

Correlation with IIS access logs would provide additional investigative context in a live environment.

## Limitations

`IEUser` is an account name and not an inherently malicious indicator.

Its significance depends on the surrounding authentication and process context.

---

# 7. w3wp.exe

## Indicator

`C:\Windows\System32\inetsrv\w3wp.exe`

## Type

Process path.

## Observed Context

The IIS worker process was associated with:

- Event ID `4648`
- Event ID `4624`

Both events involved:

- Subject account: `svc01`
- Target account: `IEUser`

The Event ID `4648` represented explicit credential use.

The Event ID `4624` represented successful LogonType `3` authentication.

## Operationalization

This process path can be used as a correlation field rather than a standalone IOC.

An analyst could search for:

- Event ID `4648`
- ProcessName containing `w3wp.exe`
- Event ID `4624`
- Matching subject and target accounts
- Closely related timestamps

Process creation telemetry should also be reviewed for child processes originating from IIS worker processes.

## Investigative Value

The process path has relatively high contextual value because legitimate IIS activity can be distinguished from unusual authentication or process relationships.

## Limitations

`w3wp.exe` is a legitimate Microsoft IIS process.

Its presence alone does not indicate compromise.

---

# 8. WmiPrvSE.exe

## Indicator

`C:\Windows\System32\wbem\WmiPrvSE.exe`

## Type

Process path.

## Observed Context

The process appeared in Event ID `4688` process creation telemetry.

Observed process ID:

`0x0000000000000ae8`

A subsequent Event ID `4688` recorded `calc.exe` with:

`Parent ProcessId: 0x0000000000000ae8`

This establishes the observed process relationship:

`WmiPrvSE.exe → calc.exe`

## Operationalization

An analyst could search process creation telemetry for:

- `WmiPrvSE.exe`
- Child processes created by WmiPrvSE.exe
- Unusual child process paths
- Command-line data if available

Additional correlation can include network authentication events preceding the process activity.

## Investigative Value

WmiPrvSE.exe is a useful contextual pivot when investigating WMI execution.

## Limitations

WmiPrvSE.exe is a legitimate Windows process.

The process itself is not malicious.

Its investigative value comes from unusual parent-child relationships, associated authentication activity, and other telemetry.

---

# 9. calc.exe

## Indicator

`C:\Windows\System32\calc.exe`

## Type

Process path.

## Observed Context

The process was created in Event ID `4688`.

Observed process ID:

`0x0000000000000424`

Parent Process ID:

`0x0000000000000ae8`

The parent process ID corresponds to the previously observed `WmiPrvSE.exe`.

## Operationalization

Search for process creation events where:

- NewProcessName is `calc.exe`
- Parent process is `WmiPrvSE.exe`

Additional context should include:

- Source authentication
- User or logon session
- Process command line
- Host
- Timestamp

## Investigative Value

A standard calculator process launched by WMI can provide a useful behavioral pivot during investigation.

## Limitations

`calc.exe` is a legitimate Windows application.

The process path alone is not malicious.

---

# 10. Process ID 0x0ae8

## Indicator

`0x0000000000000ae8`

## Type

Process identifier.

## Observed Context

The identifier was recorded as the NewProcessId for:

`WmiPrvSE.exe`

It was subsequently recorded as the Parent ProcessId for:

`calc.exe`

## Operationalization

Use the process ID only to correlate events within the relevant process lifetime and host.

## Limitations

Process IDs are temporary identifiers.

The same value may be reused by another process after the original process terminates.

It should therefore never be treated as a persistent IOC.

---

# 11. Process ID 0x0424

## Indicator

`0x0000000000000424`

## Type

Process identifier.

## Observed Context

The identifier was recorded as the NewProcessId for:

`calc.exe`

Its parent process was:

`0x0000000000000ae8`

corresponding to `WmiPrvSE.exe`.

## Operationalization

Use the identifier only for timeline and process-tree reconstruction within the relevant host and event sequence.

## Limitations

Process IDs are temporary and host-specific.

They are not persistent threat indicators.

---

# IOC Operationalization Strategy

The indicators should be used primarily for correlation rather than simple blocklisting.

## Authentication Hunting

Search for:

- Source IP
- Target account
- Event ID
- Logon type
- Authentication package
- Timestamp

Example investigative relationships:

`10.0.2.17 → Administrator → 4624 → LogonType 3`

`172.16.66.1 → multiple target accounts → 4771 → Status 0x00000018`

## Process Hunting

Search for:

- `WmiPrvSE.exe`
- `w3wp.exe`
- Child processes
- Parent-child relationships
- Process creation timestamps

Example relationship:

`WmiPrvSE.exe → calc.exe`

## Web-Server Investigation

Search for:

- `w3wp.exe`
- Event ID `4648`
- Event ID `4624`
- Subject account
- Target account
- Closely related timestamps

Example relationship:

`w3wp.exe → 4648 svc01 → IEUser → 4624`

## Correlation Priority

The following combinations provide stronger investigative context than individual indicators:

1. `10.0.2.17` + `Administrator` + Event ID `4624` + LogonType `3`
2. `172.16.66.1` + multiple target accounts + Event ID `4771`
3. `WmiPrvSE.exe` + child `calc.exe`
4. `w3wp.exe` + Event ID `4648` + Event ID `4624`
5. `svc01` + `IEUser` + `w3wp.exe`

---

# False-Positive Considerations

The following indicators require contextual validation:

- `Administrator`
- `svc01`
- `IEUser`
- `w3wp.exe`
- `WmiPrvSE.exe`
- `calc.exe`
- Private IP addresses

These values may occur during legitimate administration, authentication, application activity, or system operations.

Detection and investigation logic should therefore prioritize relationships between indicators rather than treating individual values as automatically malicious.

---

# Intelligence Limitations

No public-routable IP address, domain, URL, file hash, or cryptographic artifact was identified in the telemetry reviewed for this IOC research document.

The indicators documented here are primarily host, account, process, and private-network artifacts.

Their operational value is therefore strongest within the environment represented by the dataset.

The indicators should not be promoted to global blocklists without additional external intelligence and environmental validation.

---

# Reproducibility

The indicators were derived from the following investigated samples:

### WMI Investigation

`Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx`

Relevant events:

- `4624`
- `4688`

### Kerberos Investigation

`Credential Access/kerberos_pwd_spray_4771.evtx`

Relevant event:

- `4771`

### Web-Server Investigation

`Privilege Escalation/Runas_4624_4648_Webshell_CreateProcessAsUserA.evtx`

Relevant events:

- `4648`
- `4624`

Dataset commit:

`4ceed2f4706daf601c212a8f91c113dd85349a2c`

All indicators in this document are derived from the observed telemetry described above.
