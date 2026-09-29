# Cyberion ThreatShield

Detection Engineering & Threat Hunting

## Overview

Cyberion ThreatShield is an analytical cybersecurity project focused on detection engineering, threat hunting, MITRE ATT&CK mapping, incident investigation, and detection tuning.

The project uses public Windows security telemetry to develop and validate portable Sigma detections.

It is intentionally not a production application, SIEM, SOAR platform, backend service, or database.

## Project Scope

The project includes:

- Sigma detection engineering
- MITRE ATT&CK mapping
- Detection testing against actual EVTX telemetry
- Correlation detections
- Threat hunting
- Incident investigation
- Incident response playbooks
- IOC research
- False-positive analysis
- Detection tuning
- Executive reporting

## Dataset

Primary dataset:

**EVTX-ATTACK-SAMPLES**

Source:

`https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES`

Dataset commit used for reproducibility:

`4ceed2f4706daf601c212a8f91c113dd85349a2c`

Raw EVTX files are excluded from the Git repository.

## Detection Library

The final detection library contains:

**19 Sigma rules**

Every final rule includes:

- ATT&CK technique mapping
- Detection logic
- References
- False-positive considerations
- Severity
- Test evidence

## Validation

Sigma validation:

```text
0 errors
0 condition errors
0 issues
