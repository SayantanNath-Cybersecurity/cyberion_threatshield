# CTSHIELD-018 Detection Test Report

## Detection

- **Rule:** CTSHIELD-018
- **Title:** Kerberos Pre-Authentication Failures Against Multiple Accounts
- **Rule file:** `detections/sigma/ctshield-018_kerberos_multi_account_correlation.yml`
- **ATT&CK Technique:** T1110.003 - Password Spraying
- **Tactic:** Credential Access
- **Status:** Experimental
- **Severity:** Medium

## Dataset

- **Dataset:** EVTX-ATTACK-SAMPLES
- **Source file:** `Credential Access/kerberos_pwd_spray_4771.evtx`
- **Dataset commit:** `4ceed2f4706daf601c212a8f91c113dd85349a2c`

## Correlation Logic

The rule correlates the CTSHIELD-002 Kerberos pre-authentication failure detection.

Correlation parameters:

- Group by `IpAddress`
- Time window: `5m`
- Require at least `2` distinct `TargetUserName` values

This identifies repeated Kerberos pre-authentication failures from one source address against multiple accounts.

## Observed Evidence

The selected telemetry contains:

- TargetUserName: `Administrator`
- TargetUserName: `backdoor`
- IpAddress: `172.16.66.1`
- Event ID: `4771`
- Status: `0x00000018`

The two matching events occurred approximately `0.000474` seconds apart.

## Test Result

**PASS**

Observed result:

```text
CTSHIELD-018 matched one source address against 2 target accounts within 0:00:00.000474.
1 passed in 0.10s
