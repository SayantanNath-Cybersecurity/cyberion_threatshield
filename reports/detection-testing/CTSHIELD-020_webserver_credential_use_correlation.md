# CTSHIELD-020 Detection Test Report

## Detection

- **Rule:** CTSHIELD-020
- **Title:** IIS Worker Process Credential Use Followed by Successful Logon
- **Rule file:** `detections/sigma/ctshield-020_webserver_credential_use_correlation.yml`
- **ATT&CK Technique:** T1078 - Valid Accounts
- **Status:** Experimental
- **Severity:** High

## Dataset

- **Dataset:** EVTX-ATTACK-SAMPLES
- **Source file:** `Privilege Escalation/Runas_4624_4648_Webshell_CreateProcessAsUserA.evtx`
- **Dataset commit:** `4ceed2f4706daf601c212a8f91c113dd85349a2c`

## Correlation Logic

The rule correlates:

1. Event ID `4648` explicit credential use by `w3wp.exe`
2. Event ID `4624` successful network logon
3. Same `SubjectUserName`
4. Same `TargetUserName`
5. `w3wp.exe` process context
6. Maximum correlation window of `1m`

## Observed Evidence

The selected telemetry contains:

### Event 4648

- SubjectUserName: `svc01`
- TargetUserName: `IEUser`
- ProcessName: `C:\Windows\System32\inetsrv\w3wp.exe`
- TargetServerName: `localhost`
- TargetInfo: `localhost`

### Event 4624

- SubjectUserName: `svc01`
- TargetUserName: `IEUser`
- LogonType: `3`
- ProcessName: `C:\Windows\System32\inetsrv\w3wp.exe`
- AuthenticationPackageName: `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`

The events occurred approximately `0.000070` seconds apart.

## Test Result

**PASS**

Observed result:

```text
CTSHIELD-020 matched IIS explicit credential use followed by successful logon after 0:00:00.000070.
1 passed in 0.06s
