# PB-001: WMI Remote Execution Response

## Purpose

Provide a structured analyst workflow for investigating and responding to suspected Windows Management Instrumentation (WMI) execution activity.

This playbook is based on the WMI execution behavior observed during HUNT-001 and CASE-001.

## Applicable ATT&CK Technique

- **T1047 - Windows Management Instrumentation**
- **Tactic:** Execution

## Trigger Conditions

Initiate this playbook when one or more of the following are observed:

- WMI Provider Host (`WmiPrvSE.exe`) creates an unusual child process.
- Network authentication is followed by WMI-related process activity.
- A privileged account performs a network logon followed by suspicious process creation.
- Process telemetry shows a relationship such as:

`WmiPrvSE.exe → suspicious child process`

## Initial Triage

Record the following:

- Hostname
- Source IP address
- Source hostname, if available
- Target account
- Logon type
- Authentication package
- Event timestamps
- WMI Provider Host process ID
- Child process name
- Child process ID
- Parent process ID
- Command line, if available

### Relevant Windows Events

- Event ID `4624` - Successful logon
- Event ID `4688` - Process creation
- WMI operational telemetry, if available
- Sysmon telemetry, if available

## Investigation Workflow

### Step 1: Validate the Authentication

Review Event ID `4624`.

Determine:

- Which account authenticated?
- Was the account privileged?
- What was the logon type?
- What was the source IP?
- What authentication package was used?
- Was the source expected for this account?

Document the authentication event and timestamp.

### Step 2: Identify WMI Activity

Review process creation telemetry for:

`WmiPrvSE.exe`

Record:

- Process ID
- Parent Process ID
- Timestamp
- User context
- Command line, if available

### Step 3: Inspect Child Processes

Identify processes created by `WmiPrvSE.exe`.

Pay particular attention to:

- Command shells
- PowerShell
- Scripting interpreters
- Administrative utilities
- Newly introduced executables
- Unexpected applications

For each child process, record:

- Process name
- Process ID
- Parent process ID
- Command line
- Creation timestamp
- User context

### Step 4: Correlate the Timeline

Build a timeline connecting:

`Network authentication`

↓

`WmiPrvSE.exe`

↓

`Child process`

Determine whether the events occurred within a reasonable temporal sequence.

### Step 5: Validate Authorization

Determine whether:

- The source host is authorized to administer the target.
- The account is authorized to perform remote administration.
- The observed WMI activity corresponds to a known administrative task.
- A maintenance window or approved change explains the activity.

Do not classify the activity as malicious solely because WMI was used.

## Evidence Collection

Preserve:

- Windows Security logs
- Process creation logs
- WMI operational logs where available
- Sysmon logs where available
- Relevant endpoint telemetry
- Authentication records
- Command-line telemetry
- Host and account information

Record the original timestamps and source of each artifact.

## Containment Considerations

If unauthorized WMI execution is confirmed:

1. Identify the source host.
2. Identify the affected target host.
3. Validate whether the account credentials remain trustworthy.
4. Consider isolating the source or target host according to organizational procedures.
5. Preserve volatile and endpoint evidence where appropriate.
6. Restrict or disable compromised accounts according to incident-response procedures.

Containment actions should consider operational impact before execution.

## Eradication Considerations

Depending on investigation results:

- Remove unauthorized tools or payloads.
- Terminate unauthorized processes.
- Review scheduled tasks and services.
- Review persistence mechanisms.
- Reset compromised credentials where appropriate.
- Remove unauthorized administrative access.
- Validate that no additional hosts were accessed using the same account.

## Recovery

After containment and eradication:

1. Restore affected systems to a trusted state.
2. Validate authentication behavior.
3. Review subsequent process creation activity.
4. Confirm that unauthorized WMI activity has stopped.
5. Monitor for recurrence.
6. Document all recovery actions.

## Detection Opportunities

A detection strategy for WMI execution should consider correlation between:

- Event ID `4624`
- Event ID `4688`
- `WmiPrvSE.exe`
- Child process creation
- Source IP
- Target account
- Temporal proximity

A single WmiPrvSE.exe event should generally not be treated as sufficient evidence of malicious activity because WMI is a legitimate Windows management mechanism.

## False-Positive Considerations

Potential legitimate causes include:

- Remote administration
- Systems management software
- IT automation
- Configuration management
- Software deployment
- Administrative troubleshooting
- Enterprise management tooling

The analyst should validate the account, source host, target host, timing, and process behavior before escalating.

## Escalation Criteria

Escalate the investigation when one or more of the following are present:

- Unauthorized privileged account usage.
- Unexpected source host.
- Suspicious child process.
- Command-line evidence of offensive activity.
- Multiple target hosts accessed from the same source.
- Credential compromise indicators.
- Additional persistence or lateral movement evidence.

## Closure Criteria

The case may be closed when:

- The activity is confirmed as authorized and documented, or
- Unauthorized activity has been investigated and contained, and
- Relevant evidence has been preserved, and
- Detection gaps have been documented.

The closure record should include:

- Final classification
- Affected systems
- Accounts involved
- Evidence reviewed
- Response actions
- Detection improvements
- Remaining uncertainty

## Case Reference

This playbook was informed by:

- `HUNT-001_wmi_remote_execution.md`
- `CASE-001_wmi_remote_execution.md`

Observed attack-sample evidence included:

`10.0.2.17 → Administrator → WmiPrvSE.exe → calc.exe`

The observed telemetry demonstrates WMI-associated process execution but does not independently establish operator intent.
