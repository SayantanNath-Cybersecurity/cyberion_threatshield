# HUNT-001: Windows Management Instrumentation Remote Execution

## Hunt Objective

Investigate whether the selected Windows telemetry contains evidence consistent with Windows Management Instrumentation (WMI) execution.

## Hypothesis

A remote WMI execution activity occurred against the target Windows host, resulting in network authentication followed by WMI Provider Host activity and creation of a child process.

## ATT&CK Technique

- **Technique:** T1047 - Windows Management Instrumentation
- **Tactic:** Execution

## Dataset

- **Dataset:** EVTX-ATTACK-SAMPLES
- **Sample:** `Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx`
- **Dataset Commit:** `4ceed2f4706daf601c212a8f91c113dd85349a2c`

## Analysis Method

The EVTX sample was parsed using the `python-evtx` library.

The analysis examined:

- Windows Security Event ID 4624 for successful network logons
- Source IP addresses associated with network authentication
- Target accounts
- Windows Security Event ID 4688 for process creation
- `NewProcessName`
- `NewProcessId`
- Parent `ProcessId` relationships

The analysis focused on identifying a sequence connecting remote authentication activity with WMI-related process execution.

## Findings

The sample contains multiple Windows Security Event ID 4624 network logon events.

An observed authentication sequence includes:

- Target account: `Administrator`
- Logon type: `3`
- Authentication package: `Kerberos`
- Source IP: `10.0.2.17`

Additional authentication activity from the same source address was observed against the target system.

The sample also contains Windows Security Event ID 4688 process creation events.

One event created:

`C:\Windows\System32\wbem\WmiPrvSE.exe`

The corresponding event recorded:

- Event ID: `4688`
- New Process ID: `0x0000000000000ae8`

A subsequent process creation event created:

`C:\Windows\System32\calc.exe`

This event recorded:

- Event ID: `4688`
- New Process ID: `0x0000000000000424`
- Parent Process ID: `0x0000000000000ae8`

The parent process ID corresponds to the previously observed `WmiPrvSE.exe` process.

## Event Relationship

The observed process relationship is:

`WmiPrvSE.exe (PID 0x0ae8)`

↓

`calc.exe (PID 0x0424)`

The telemetry therefore provides a process-parent relationship in which `calc.exe` was created by the WMI Provider Host process.

The authentication telemetry also shows network logon activity from `10.0.2.17` involving the `Administrator` account.

## Finding Assessment

The telemetry contains evidence consistent with WMI-based execution:

1. Network authentication activity was observed from `10.0.2.17`.
2. The `Administrator` account was involved in a successful network logon.
3. `WmiPrvSE.exe` was created on the target host.
4. `calc.exe` was subsequently created as a child of the WMI Provider Host process.

These observations support the hunt hypothesis.

## Conclusion

**Confirmed: evidence consistent with WMI execution was identified in the selected telemetry.**

The strongest evidence is the observed `WmiPrvSE.exe` to `calc.exe` parent-child process relationship, combined with network authentication activity from `10.0.2.17`.

The telemetry alone does not establish the operator's intent or independently prove that the activity was malicious. The finding should therefore be interpreted as confirmed WMI execution activity within the attack sample.

## Detection Gap

The current detection library does not contain a dedicated detection for T1047 - Windows Management Instrumentation.

This hunt therefore identifies a detection coverage opportunity for WMI execution activity.

## Reproducibility

The raw EVTX dataset is maintained outside the Git repository.

Dataset provenance:

`4ceed2f4706daf601c212a8f91c113dd85349a2c`

Sample:

`Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx`

The hunt can be reproduced by parsing the selected EVTX file and reviewing Event IDs `4624` and `4688`, with particular attention to the source IP, target account, `WmiPrvSE.exe`, `calc.exe`, and the process ID relationship documented above.
