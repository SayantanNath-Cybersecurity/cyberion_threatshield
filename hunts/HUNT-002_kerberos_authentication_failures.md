# HUNT-002: Kerberos Pre-Authentication Failure Activity

## Hunt Objective

Investigate whether the selected Windows Security telemetry contains evidence of repeated Kerberos pre-authentication failures associated with authentication activity from a common source address.

## Hypothesis

A source system may be generating repeated Kerberos pre-authentication failures against multiple user accounts, creating activity that warrants investigation for possible credential-access behavior.

## ATT&CK Technique

- **Technique:** Credential Access
- **Technique mapping:** The observed telemetry is assessed for credential-access activity; the specific ATT&CK technique will be finalized in the coverage matrix after ATT&CK validation.

## Dataset

- **Dataset:** EVTX-ATTACK-SAMPLES
- **Sample:** `Credential Access/kerberos_pwd_spray_4771.evtx`
- **Dataset Commit:** `4ceed2f4706daf601c212a8f91c113dd85349a2c`

## Analysis Method

The EVTX sample was parsed using the `python-evtx` library.

The analysis examined:

- Windows Security Event ID `4771`
- Kerberos pre-authentication failure status
- `TargetUserName`
- `PreAuthType`
- `IpAddress`
- `IpPort`
- Event timestamps
- The relationship between repeated failures and source addresses

The analysis focused on determining whether multiple authentication failures occurred from the same source within a short period and whether different target accounts were involved.

## Findings

The selected sample contains Windows Security Event ID `4771` events indicating Kerberos pre-authentication failures.

Two relevant events were observed.

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

Both failures originated from the same observed source address:

`172.16.66.1`

The events targeted different accounts:

- `Administrator`
- `backdoor`

The two events occurred within a very short interval.

## Finding Assessment

The hunt identified repeated Kerberos pre-authentication failures from the same source address against different target accounts.

This pattern is relevant for investigation because repeated authentication failures involving multiple accounts can indicate credential-access activity.

However, the observed telemetry contains only two relevant failures in this sample. The evidence is therefore insufficient to independently establish a password-spraying campaign.

## Conclusion

**Confirmed: repeated Kerberos pre-authentication failure activity was identified.**

The observed events show:

1. Two Event ID `4771` failures.
2. The same source IP address, `172.16.66.1`.
3. Different target accounts.
4. Status `0x00000018` for both failures.
5. A very short interval between the events.

The evidence supports the hunt hypothesis that repeated authentication-failure activity occurred.

The telemetry does not independently establish malicious intent or conclusively prove password spraying.

## Detection Gap

The existing CTSHIELD-002 detection identifies individual Event ID `4771` failures with status `0x00000018`.

This hunt demonstrates that additional correlation across:

- source IP,
- target accounts,
- event frequency,
- and time windows

could provide stronger analytical context than a single-event detection.

## Reproducibility

The raw EVTX dataset is maintained outside the Git repository.

Dataset provenance:

`4ceed2f4706daf601c212a8f91c113dd85349a2c`

Sample:

`Credential Access/kerberos_pwd_spray_4771.evtx`

The hunt can be reproduced by parsing the selected EVTX file and reviewing Event ID `4771` events with status `0x00000018`, source address, target account, and event timestamp.

## Limitations

The selected sample contains only a small number of relevant failure events.

A larger authentication dataset would be required to establish stronger frequency-based evidence for password spraying or another coordinated credential-access technique.
