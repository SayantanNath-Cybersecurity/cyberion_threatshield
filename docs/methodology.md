# Cyberion ThreatShield Methodology

## 1. Project Purpose

Cyberion ThreatShield is a detection-engineering and threat-hunting engagement focused on developing portable Sigma detections, validating them against public security telemetry, mapping them to MITRE ATT&CK, conducting structured hunts, and documenting incident investigations.

The project is analytical and detection-content focused. It does not build or deploy a production application, SIEM, SOAR platform, backend service, or database.

## 2. Dataset

The primary telemetry source is:

**EVTX-ATTACK-SAMPLES**

The dataset was obtained from the public repository:

`https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES`

The project records the upstream dataset commit:

`4ceed2f4706daf601c212a8f91c113dd85349a2c`

The raw dataset is kept outside the project Git repository.

## 3. Telemetry Types

The selected samples contain Windows telemetry including:

- Windows Security event logs
- Sysmon process and process-access events
- Authentication events
- Process creation events
- WMI-related telemetry
- IIS/web-server-related authentication telemetry

Relevant Windows Security events used during detection development include events such as:

- 4624: successful logon
- 4625: failed logon
- 4648: explicit credential use
- 4662: directory-service access where applicable
- 4771: Kerberos pre-authentication failure

Relevant Sysmon telemetry includes process creation and process-access events.

## 4. Detection Engineering Process

Detection development followed this sequence:

1. Inspect available telemetry.
2. Identify attacker behavior represented by the telemetry.
3. Identify available fields.
4. Select an ATT&CK technique supported by the observed behavior.
5. Write the behavior as Sigma logic.
6. Document realistic false-positive conditions.
7. Create a reproducible test against the actual EVTX data.
8. Run the detection test.
9. Validate the Sigma syntax using Sigma CLI.
10. Document the result.
11. Perform tuning where observed telemetry justified it.

## 5. Sigma Validation

The project uses Sigma CLI for rule validation.

The final library contains:

**19 Sigma rules**

The final validation run produced:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
