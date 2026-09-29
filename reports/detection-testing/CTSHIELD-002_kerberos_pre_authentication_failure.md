# CTSHIELD-002 Detection Test

## Detection

- **Rule ID:** CTSHIELD-002
- **Rule:** Kerberos Pre-Authentication Failure
- **ATT&CK Technique:** T1110.001 - Password Guessing
- **Tactic:** Credential Access
- **Severity:** Medium
- **Status:** Experimental

## Test Dataset

- **Dataset:** EVTX-ATTACK-SAMPLES
- **Sample:** `Credential Access/kerberos_pwd_spray_4771.evtx`
- **Dataset Commit:** `4ceed2f4706daf601c212a8f91c113dd85349a2c`

## Detection Logic Tested

The detection selects:

- `EventID = 4771`
- `Status = 0x00000018`

The test also verifies that the event belongs to the Windows `Security` channel.

## Test Method

The selected EVTX file was parsed using the `python-evtx` library.

Each event was parsed from XML and evaluated against the detection selection represented by CTSHIELD-002.

## Test Result

**PASS**

Observed result:

`CTSHIELD-002 matched 2 Kerberos pre-authentication failure event(s).`

## Observed Evidence

### Event 9

- Event ID: `4771`
- Provider: `Microsoft-Windows-Security-Auditing`
- Channel: `Security`
- TargetUserName: `Administrator`
- Status: `0x00000018`
- PreAuthType: `2`
- IpAddress: `172.16.66.1`
- IpPort: `55967`

### Event 10

- Event ID: `4771`
- Provider: `Microsoft-Windows-Security-Auditing`
- Channel: `Security`
- TargetUserName: `backdoor`
- Status: `0x00000018`
- PreAuthType: `2`
- IpAddress: `172.16.66.1`
- IpPort: `55968`

Both events originated from the same observed source address and occurred within a very short interval.

## Evidence Interpretation

Windows Security Event ID 4771 records a Kerberos pre-authentication failure.

The selected sample contains two such failures with status `0x00000018`. The events target different accounts and originate from the same observed source address within a very short interval.

This provides useful evidence for investigating repeated authentication failures and possible credential-access activity.

The atomic detection does not independently establish password spraying or malicious intent. Correlation across authentication events, source addresses, target accounts, and time windows provides stronger evidence for password-guessing or password-spraying hypotheses.

## False-Positive Considerations

Potential legitimate causes include:

- Incorrect passwords
- Expired or invalid credentials
- Misconfigured applications or services
- Legitimate authentication failures

## ATT&CK Mapping

- **Technique:** T1110.001
- **Technique Name:** Password Guessing
- **Tactic:** Credential Access

The rule provides an atomic authentication-failure signal. Multi-account correlation is handled separately by CTSHIELD-018.

## Reproduction

Run:

`python tests/detections/test_ctshield_002.py`

Expected result:

`CTSHIELD-002 matched 2 Kerberos pre-authentication failure event(s).`

Validate the Sigma rule with:

`sigma check detections/sigma/CTSHIELD-002_kerberos_pre_authentication_failure.yml`

Expected validation result:

`Found 0 errors, 0 condition errors and 0 issues.`

## Dataset Reproducibility

The raw EVTX dataset is maintained outside the project Git repository and is identified by the recorded upstream Git commit:

`4ceed2f4706daf601c212a8f91c113dd85349a2c`
