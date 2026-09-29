# CTSHIELD-006 Tuning Pass

## Detection

- Rule: CTSHIELD-006
- Title: Failed Interactive Logon
- Rule file: `detections/sigma/CTSHIELD-006_failed_interactive_logon.yml`
- Status: Experimental
- Tuning type: Analytical correlation tuning

## Original Detection Logic

The original detection matches:

- Windows Security Event ID `4625`
- Logon Type `2`

The original rule treats each failed interactive logon as an independent detection event.

## Observed Noisy Authentication Context

Dataset:

`EVTX-ATTACK-SAMPLES`

Source:

`Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx`

The selected telemetry contains one failed interactive logon followed by successful interactive logon events.

The failed Event ID `4625` contains:

- TargetUserName: `IEUser`
- LogonType: `2`
- LogonProcessName: `Chrome`
- ProcessId: `0x0000000000001358`
- ProcessName: `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`
- Status: `0xc000006d`
- SubStatus: `0xc000006a`
- WorkstationName: `MSEDGEWIN10`

The subsequent Event ID `4624` records contain:

- TargetUserName: `IEUser`
- LogonType: `2`
- LogonProcessName: `Chrome`
- ProcessId: `0x0000000000001358`
- ProcessName: `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`
- WorkstationName: `MSEDGEWIN10`

The repeated account and process context, together with successful interactive authentication after the failure, provides evidence of a likely routine authentication retry sequence.

The telemetry does not explicitly state why the first authentication failed. Therefore, the investigation does not claim that an incorrect password was definitely entered.

## Observed False-Positive / Noise Classification

Classification:

**Likely benign authentication noise based on surrounding telemetry.**

The classification is based on:

1. A failed interactive authentication.
2. Subsequent successful interactive authentication.
3. The same target account.
4. The same Chrome process.
5. The same process ID.
6. The same workstation.

The Event ID `4625` record should therefore not automatically be treated as a high-confidence malicious event in isolation.

## Tuning Change

The atomic Sigma rule remains unchanged.

The tuning is applied at the investigation and alert-triage layer:

**Original behavior**

Treat every Event ID `4625` with Logon Type `2` as an independent detection.

**Tuned behavior**

Use surrounding authentication telemetry before escalation. A failed interactive logon followed by successful interactive authentication for the same account and process context should receive lower investigative priority unless additional suspicious evidence exists.

The tuning should therefore be implemented as a correlation or triage condition in a downstream detection workflow rather than by excluding Chrome or removing Event ID `4625` from the atomic rule.

## Trade-Off

### Benefit

The tuning reduces unnecessary investigation of routine authentication failures that are immediately followed by successful authentication using the same account and process context.

It also preserves the original 4625 telemetry for investigations where additional suspicious activity exists.

### Cost

A genuine attack could potentially produce a failed authentication followed by a successful authentication.

Therefore, the correlation context must not be treated as proof of benign activity. Additional indicators should still be considered before closing an event.

## Validation

The original detection test remains:

`tests/detections/test_ctshield_006.py`

Command:

`python -m pytest -q tests/detections/test_ctshield_006.py -s`

Expected result:

`1 passed`

The relevant EVTX file was inspected directly and contained the failed and subsequent successful authentication records described above.

## Conclusion

CTSHIELD-006 produced a defensible tuning case based on observed authentication noise.

The atomic detection remains unchanged.

The tuning reduces standalone alert priority for failed interactive authentication when surrounding telemetry shows subsequent successful authentication for the same account and process context.

This preserves detection coverage while providing a documented method for reducing routine authentication noise.
