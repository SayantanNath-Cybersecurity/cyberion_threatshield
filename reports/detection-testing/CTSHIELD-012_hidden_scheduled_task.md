# CTSHIELD-012 Detection Test Report

## Detection

- Rule: CTSHIELD-012
- Title: Hidden Windows Scheduled Task Created
- Rule file: `detections/sigma/CTSHIELD-012_hidden_scheduled_task.yml`
- Status: Experimental
- Severity: High

## Dataset

- Dataset: EVTX-ATT&CK-SAMPLES
- Source file: `Execution/temp_scheduled_task_4698_4699.evtx`
- Log channel: Security
- Detection event: Event ID 4698

## Detection Logic

The rule detects Windows Security Event ID `4698`, which records scheduled task creation.

The detection focuses on scheduled task content containing both:

- `<Hidden>true</Hidden>`
- `<UserId>S-1-5-18</UserId>`

`S-1-5-18` represents the LocalSystem security principal.

The combination identifies a scheduled task configured to run as LocalSystem while being hidden from normal task enumeration.

## Observed Evidence

The selected EVTX file contained an Event ID `4698` scheduled task creation event.

Observed values included:

- SubjectUserName: `Administrator`
- TaskName: `\CYAlyNSS`
- Task content configured with `<Hidden>true</Hidden>`
- Task content configured with `<UserId>S-1-5-18</UserId>`
- RunLevel: `HighestAvailable`
- Action command: `cmd.exe`
- Arguments included `/C tasklist`
- The task was configured to run under the LocalSystem principal.

The same dataset also contained a corresponding Event ID `4699` for deletion of the task.

The observed configuration is consistent with a hidden scheduled task operating with LocalSystem privileges. The telemetry alone does not independently establish malicious intent.

## Test Method

The automated test is located at:

`tests/detections/test_ctshield_012.py`

Command:

`python -m pytest -q tests/detections/test_ctshield_012.py -s`

Result:

`CTSHIELD-012 matched 1 hidden LocalSystem scheduled task creation event(s).`

`1 passed in 0.05s`

## Sigma Validation

The rule was validated using Sigma CLI.

Result:

`Found 0 errors, 0 condition errors and 0 issues.`

## False Positive Considerations

Potential benign causes include:

- Authorized administrative scheduled tasks configured to run as LocalSystem
- Legitimate system maintenance tasks
- Enterprise software deployment or management tools
- Security testing environments

The combination of hidden configuration and LocalSystem execution should be investigated in context rather than treated as definitive proof of malicious activity.

Relevant investigation context can include the task name, task XML, creating account, command or executable, parent process telemetry, authentication events, and surrounding system activity.

## ATT&CK Mapping

- Technique: T1053.005
- Technique name: Scheduled Task/Job: Scheduled Task
- Tactics: Execution, Persistence, Privilege Escalation

## Test Conclusion

CTSHIELD-012 successfully matched one hidden LocalSystem scheduled task creation event in the selected public EVTX telemetry.

The Sigma rule passed validation and the corresponding automated test passed against the actual dataset.

The detection provides a focused signal for investigating scheduled tasks that combine hidden execution with LocalSystem privileges.
