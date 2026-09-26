# PB-003: Web Server Credential-Use Response

## Purpose

Provide a structured analyst workflow for investigating suspicious credential-use activity associated with an IIS web server process.

This playbook is based on the activity observed during CASE-002.

## Applicable ATT&CK Context

The investigation concerns web-server-associated credential use and authentication activity.

Potential ATT&CK mappings include:

- **T1505.003 - Server Software Component: Web Shell**
- **T1078 - Valid Accounts**

The exact applicability of these techniques should be validated against the observed evidence and the current ATT&CK coverage matrix.

## Trigger Conditions

Initiate this playbook when one or more of the following are observed:

- Event ID `4648` is associated with the IIS worker process `w3wp.exe`.
- `w3wp.exe` performs explicit credential use.
- Event ID `4648` is followed by Event ID `4624`.
- The same subject and target accounts appear across the related events.
- IIS worker processes are associated with unexpected authentication activity.
- A web-server process creates unusual child processes.

## Initial Triage

Record:

- Hostname
- IIS site or application, if available
- Subject account
- Target account
- Target server
- Process path
- Event IDs
- Logon type
- Authentication package
- Source IP
- Source port
- Event timestamps
- Process IDs
- Child processes, if available

### Relevant Windows Events

- Event ID `4648` - explicit credential use
- Event ID `4624` - successful logon
- Event ID `4688` - process creation
- IIS access logs
- IIS application logs
- Endpoint telemetry where available

## Investigation Workflow

### Step 1: Validate Explicit Credential Use

Review Event ID `4648`.

Determine:

- Which account initiated the credential use?
- Which account was targeted?
- What process performed the operation?
- What target server was recorded?
- Was an IP address available?
- Was the operation expected?

For the observed case, the process was:

`C:\Windows\System32\inetsrv\w3wp.exe`

### Step 2: Correlate the Successful Logon

Search for Event ID `4624` occurring immediately after the Event ID `4648`.

Compare:

- SubjectUserName
- SubjectDomainName
- TargetUserName
- TargetDomainName
- ProcessName
- LogonType
- AuthenticationPackageName
- Timestamp

Determine whether the same IIS process and account relationship appears in both events.

### Step 3: Investigate the IIS Application

Identify:

- IIS site
- Application pool
- Application name
- Worker process
- Listening port
- Associated virtual directory

Review IIS configuration and application ownership.

### Step 4: Review Web Access Logs

Review IIS access logs around the event timestamp.

Look for:

- Requests immediately preceding the authentication event
- Unusual URLs
- Unexpected HTTP methods
- Suspicious query parameters
- Upload activity
- Requests to administrative endpoints
- Repeated requests from unusual clients
- Requests associated with recently modified files

Preserve relevant request records.

### Step 5: Inspect Web-Directory Activity

Review file creation and modification activity in relevant web directories.

Look for:

- Newly created scripts
- Recently modified application files
- Unexpected executable content
- Suspicious filenames
- Files that do not match the application's normal deployment pattern

Do not assume that a suspicious filename alone proves webshell activity.

### Step 6: Review Child Processes

Review Event ID `4688` or equivalent endpoint telemetry for processes created by `w3wp.exe`.

Pay particular attention to:

- `cmd.exe`
- `powershell.exe`
- Script interpreters
- Administrative utilities
- Unexpected binaries
- Network utilities

Record:

- Process name
- Parent process
- Process ID
- Command line
- Timestamp
- User context

### Step 7: Validate Account Authorization

Determine whether:

- `svc01` is an expected IIS service identity.
- `IEUser` is an expected target account.
- The account relationship is documented.
- The activity occurred during an approved application operation.
- The authentication pattern matches normal application behavior.

Do not classify the activity as malicious solely because `w3wp.exe` performed credential use.

## Evidence Collection

Preserve:

- Windows Security Event ID `4648`
- Windows Security Event ID `4624`
- Event ID `4688`, if available
- IIS access logs
- IIS configuration
- Application logs
- Web-directory file metadata
- Relevant endpoint telemetry
- Authentication records
- Process command lines

Maintain original timestamps and source references.

## Correlation Strategy

A useful analytical sequence is:

`w3wp.exe`

↓

`Event 4648`

↓

`Target account`

↓

`Event 4624`

↓

`Web request / process activity`

The strongest investigations correlate Windows Security telemetry with IIS access logs and endpoint process telemetry.

## Observed Case Pattern

CASE-002 contained:

- Subject account: `svc01`
- Target account: `IEUser`
- Target server: `localhost`
- Process: `C:\Windows\System32\inetsrv\w3wp.exe`
- Event ID `4648`
- Event ID `4624`
- LogonType: `3`
- Authentication package: `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`

The two events occurred approximately 70 microseconds apart.

The Security telemetry establishes the authentication relationship but does not independently prove webshell installation.

## False-Positive Considerations

Potential legitimate causes include:

- IIS application authentication
- Service-account operations
- Application impersonation
- Scheduled web application tasks
- Administrative web applications
- Legitimate application access to local resources
- Deployment or maintenance activity

The analyst should validate the application, account relationship, web request, timing, and process behavior before escalation.

## Escalation Criteria

Escalate when one or more of the following are observed:

- Unexpected credential use by `w3wp.exe`.
- Unauthorized target account.
- Suspicious IIS request immediately preceding the authentication.
- Unexpected web-directory file modification.
- `w3wp.exe` creates a command shell or scripting interpreter.
- Suspicious command-line activity.
- Evidence of persistence.
- Evidence of additional host access.
- Credentials appear compromised.
- Multiple indicators support unauthorized web-server activity.

## Containment Considerations

If unauthorized web-server activity is confirmed:

1. Identify the affected IIS server.
2. Identify the affected application and application pool.
3. Preserve IIS and Windows Security evidence.
4. Consider isolating the affected host according to organizational procedures.
5. Restrict compromised accounts where appropriate.
6. Preserve suspicious files before removal.
7. Prevent continued unauthorized access while maintaining required evidence.

Containment should consider service availability and business impact.

## Eradication Considerations

Depending on investigation results:

- Remove unauthorized web content.
- Remove unauthorized scripts or binaries.
- Correct compromised application configuration.
- Reset compromised credentials.
- Review IIS application pools.
- Remove unauthorized persistence.
- Patch exploited application components where applicable.
- Review other hosts running the same application.

## Recovery

After containment and eradication:

1. Restore the IIS application to a trusted state.
2. Validate application functionality.
3. Confirm that unexpected authentication activity has stopped.
4. Review subsequent Event ID `4648` and `4624` activity.
5. Monitor IIS access logs.
6. Monitor process creation from `w3wp.exe`.
7. Document recovery actions and remaining risks.

## Detection Opportunities

A correlation-style detection could combine:

- Event ID `4648`
- Event ID `4624`
- `ProcessName = C:\Windows\System32\inetsrv\w3wp.exe`
- Matching subject and target accounts
- Short temporal proximity

Additional enrichment could include:

- IIS request data
- Web-directory file changes
- Child processes
- Command-line telemetry

This approach provides stronger context than treating either Event ID `4648` or `4624` independently.

## Detection Gap

The current detection library does not contain a dedicated detection for web-server-associated explicit credential use.

CASE-002 therefore identifies an opportunity for a correlation-style Sigma rule based on:

- Event ID `4648`
- Event ID `4624`
- IIS worker process
- Account relationship
- Temporal proximity

The rule should be tested against actual telemetry and tuned for legitimate IIS application behavior before being considered production-ready.

## Closure Criteria

The case may be closed when:

- The activity is confirmed as legitimate and documented, or
- Unauthorized activity has been investigated and contained, and
- Relevant evidence has been preserved, and
- Affected accounts and systems have been addressed, and
- Detection gaps have been documented.

The closure record should include:

- Final classification
- Affected IIS application
- Accounts involved
- Evidence reviewed
- Web activity reviewed
- Response actions
- Detection improvements
- Remaining uncertainty

## Case Reference

This playbook was informed by:

- `CASE-002_webserver_credential_use.md`
- `IOC-RESEARCH-001_telemetry_indicators.md`

Observed case evidence included:

`w3wp.exe → Event 4648 → IEUser → Event 4624`

The observed Security telemetry confirms explicit credential use and subsequent successful authentication associated with the IIS worker process. It does not independently establish webshell installation or malicious intent.
