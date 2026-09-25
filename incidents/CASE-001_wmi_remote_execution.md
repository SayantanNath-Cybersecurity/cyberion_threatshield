# CASE-001: WMI Remote Execution Activity

## Case Overview

- **Case ID:** CASE-001
- **Source:** HUNT-001
- **Dataset:** EVTX-ATTACK-SAMPLES
- **Sample:** `Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx`
- **Dataset Commit:** `4ceed2f4706daf601c212a8f91c113dd85349a2c`
- **Primary ATT&CK Technique:** T1047 - Windows Management Instrumentation
- **Case Classification:** True Positive
- **Investigation Status:** Closed

## Detection / Investigation Trigger

HUNT-001 identified telemetry consistent with WMI-based execution on the target Windows host.

The investigation was initiated because the selected telemetry contained network authentication activity followed by creation of `WmiPrvSE.exe` and a child `calc.exe` process.

## Evidence Sources

The investigation used Windows Security Event Log telemetry from the selected EVTX sample.

Relevant events:

- Event ID `4624` - successful network logon
- Event ID `4688` - process creation

## Timeline

### Event 1: Network Authentication

A Windows Security Event ID `4624` recorded a successful network logon involving the `Administrator` account.

Observed fields:

- TargetUserName: `Administrator`
- LogonType: `3`
- AuthenticationPackageName: `Kerberos`
- IpAddress: `10.0.2.17`

Additional successful network authentication activity involving the same source address was also observed.

### Event 2: WMI Provider Host Creation

A Windows Security Event ID `4688` recorded creation of:

`C:\Windows\System32\wbem\WmiPrvSE.exe`

Observed fields:

- NewProcessId: `0x0000000000000ae8`
- Parent ProcessId: `0x0000000000000248`
- SubjectUserName: `WIN-77LTAPHIQ1R$`

### Event 3: Child Process Creation

A subsequent Windows Security Event ID `4688` recorded creation of:

`C:\Windows\System32\calc.exe`

Observed fields:

- NewProcessId: `0x0000000000000424`
- Parent ProcessId: `0x0000000000000ae8`
- SubjectUserName: `WIN-77LTAPHIQ1R$`

The parent process ID `0x0ae8` matches the NewProcessId of the previously observed `WmiPrvSE.exe`.

## Process Relationship

The observed process chain is:

`WmiPrvSE.exe`

↓

`calc.exe`

This establishes that the `calc.exe` process was created by the WMI Provider Host process in the selected telemetry.

## Investigation Findings

The investigation established the following:

1. Successful network authentication involving the `Administrator` account was observed.
2. The authentication originated from `10.0.2.17`.
3. `WmiPrvSE.exe` was created on the target host.
4. `calc.exe` was subsequently created as a child of `WmiPrvSE.exe`.
5. The process relationship was established using the matching process identifiers recorded in the Event ID `4688` telemetry.

These observations are consistent with WMI execution activity.

## Root Cause Analysis

The available telemetry indicates that WMI was used to create a process on the target system.

The dataset does not provide sufficient evidence to identify the exact originating command, executable source, operator identity, or initial access mechanism.

Therefore, the investigation attributes the observed execution mechanism to WMI but does not infer an unsupported root cause beyond the available telemetry.

## MITRE ATT&CK Mapping

### T1047 - Windows Management Instrumentation

The observed `WmiPrvSE.exe` activity and child process creation provide evidence consistent with Windows Management Instrumentation execution.

The technique is associated with the execution stage of the observed activity.

## Impact Assessment

The telemetry demonstrates process execution through WMI on the target host.

The observed child process was:

`C:\Windows\System32\calc.exe`

No evidence in this sample establishes data theft, persistence, destructive activity, or additional compromise beyond the observed execution activity.

The confirmed impact is therefore limited to execution activity demonstrated by the available telemetry.

## Response Considerations

For a live environment, an analyst investigating comparable activity should:

1. Identify the source host associated with the network authentication.
2. Validate whether the `Administrator` account was authorized to perform remote administration.
3. Review additional process creation events around the same time.
4. Review WMI operational telemetry if available.
5. Review authentication activity involving the source system.
6. Determine whether additional hosts received WMI activity from the same source.
7. Contain the source account or host if unauthorized activity is confirmed.
8. Preserve relevant logs and endpoint evidence before remediation.

## Closure Classification

**True Positive**

The classification is based on the presence of corroborating telemetry showing:

- Network authentication activity involving the `Administrator` account.
- WMI Provider Host process creation.
- A child process created by `WmiPrvSE.exe`.

The classification refers to the observed WMI execution activity in the attack sample. It does not independently establish malicious intent by an unknown real-world operator.

## Detection Gap

The investigation identified a coverage gap for WMI execution.

The current detection library does not contain a dedicated T1047 detection.

A future detection could correlate network logon activity with WMI Provider Host process creation and suspicious child-process execution.

## Evidence Limitations

The selected sample contains only a limited set of Windows Security events.

The available telemetry does not establish:

- The originating WMI command.
- The exact remote execution command line.
- The original source process that initiated WMI.
- The operator identity.
- Whether the activity persisted beyond the observed process execution.
- Whether additional systems were affected.

These limitations are recorded to prevent unsupported conclusions.

## Reproducibility

The raw EVTX dataset is maintained outside the Git repository.

Dataset provenance:

`4ceed2f4706daf601c212a8f91c113dd85349a2c`

Sample:

`Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx`

The investigation can be reproduced by parsing the selected EVTX file and reviewing Event IDs `4624` and `4688`, with particular attention to:

- `Administrator`
- `10.0.2.17`
- `WmiPrvSE.exe`
- `calc.exe`
- `NewProcessId`
- `ProcessId`
