# EVTX-ATTACK-SAMPLES Dataset Metadata

## Dataset Identity

- **Dataset:** EVTX-ATTACK-SAMPLES
- **Repository:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
- **Local path:** `data/raw/evtx-attack-samples`
- **Dataset Git commit:** `4ceed2f4706daf601c212a8f91c113dd85349a2c`
- **Commit date:** 2023-01-24 12:02:50 UTC
- **Local dataset size:** 51M
- **EVTX files:** 278

## Purpose

The dataset contains Windows Event Log (`.evtx`) samples associated with attack behaviors and security-relevant activity. It is being used as a primary telemetry source for the Cyberion Defense Labs Detection Engineering & Threat Hunting Engagement.

The dataset supports analysis of Windows telemetry, identification of relevant event providers and fields, detection-rule development, and threat-hunting exercises.

## Observed Dataset Categories

The dataset contains categories including:

- AutomatedTestingTools
- Command and Control
- Credential Access
- Defense Evasion
- Discovery
- Execution
- Lateral Movement
- Persistence
- Privilege Escalation
- Other

The repository also contains `EVTX_ATT&CK_Metadata`.

## Observed Telemetry Sources

Initial inspection has identified the following Windows telemetry sources:

### Windows Security Event Log

Observed event IDs include:

- 1102 - Security audit log cleared
- 4624 - Successful logon
- 4625 - Failed logon
- 4662 - An operation was performed on an object
- 4663 - An attempt was made to access an object
- 5156 - Windows Filtering Platform connection allowed

### Microsoft Sysmon

Observed Sysmon event IDs include:

- Event ID 1 - Process creation
- Event ID 3 - Network connection
- Event ID 5 - Process termination

These observations are based on initial inspection of representative EVTX files and are not intended to represent every event type contained in the dataset.

## Initial Analysis Observations

Representative files were inspected from multiple dataset categories.

Examples include:

- Security Event ID 1102 containing security-log-clearing activity.
- Security Event ID 4662 containing directory-service object access telemetry associated with DCSync-related activity.
- Sysmon Event ID 1 containing process creation telemetry with process image, command line, parent process, user, integrity level, and hash information.
- Sysmon Event ID 3 containing network connection telemetry.
- Security Event IDs 4624 and 4625 containing successful and failed logon telemetry.

These observations will be used to guide telemetry-field analysis and subsequent detection engineering.

## Reproducibility

The dataset is maintained as an external Git repository and is intentionally excluded from the main project repository through `.gitignore`.

The dataset version used for this engagement is identified by the Git commit:

`4ceed2f4706daf601c212a8f91c113dd85349a2c`

This allows the analysis environment to reference a specific dataset revision without committing the third-party raw telemetry into the project repository.

## Scope and Limitations

- The dataset consists of publicly available attack/security telemetry samples.
- The samples are not equivalent to a continuous production environment.
- Event availability and field coverage vary between individual EVTX files.
- Detection logic must therefore be tested against the actual fields present in the selected telemetry.
- Dataset filenames and directory names may indicate an attack technique, but detection conclusions must be based on the underlying event data rather than filenames alone.

## Role in Project 2

This dataset will serve as the primary Windows telemetry source for:

1. Telemetry familiarization
2. Data dictionary development
3. Sigma detection engineering
4. ATT&CK technique mapping
5. Threat-hunting exercises
6. Detection testing and evidence collection
