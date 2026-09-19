# Cyberion ThreatShield

## Cyberion Defense Labs
### Detection Engineering & Threat Hunting Engagement

**Project Code:** CDL-DET-V2  
**Version:** 2.0  
**Engagement Type:** Individual Detection Engineering Track  
**Duration:** 4 Weeks

---

## 1. Project Overview

Cyberion ThreatShield is a detection engineering and threat hunting engagement focused on analyzing publicly available security telemetry, engineering Sigma detection rules, mapping detections to MITRE ATT&CK, conducting structured threat hunts, and documenting confirmed security incidents.

This project is an analytical and content-engineering engagement. It does not develop or deploy a custom security application.

---

## 2. Objectives

The engagement aims to:

- Analyze real security log datasets.
- Build and test a documented Sigma detection library.
- Map detections to MITRE ATT&CK techniques.
- Conduct structured threat hunts.
- Investigate confirmed findings through incident case reports.
- Develop practical incident response playbooks.
- Research indicators of compromise.
- Document false-positive considerations and detection tuning.
- Produce reproducible, evidence-backed security documentation.

---

## 3. Project Targets

| Deliverable | Target |
|---|---:|
| Sigma detection rules | 15+ |
| ATT&CK techniques assessed | 20+ |
| Threat hunts | 2+ |
| Incident case reports | 2+ |
| IR playbooks | 3+ |
| Rules tested against actual telemetry | 100% |
| Rules with documented FP considerations | 100% |

---

## 4. Repository Structure

```text
data/              Security telemetry and dataset documentation
detections/        Sigma detection rules and detection evidence
hunts/             Structured threat hunting reports
incidents/         Incident investigation case reports
playbooks/         Incident response playbooks
ioc-research/      IOC research and operationalization notes
reports/           Executive and engagement reports
docs/              Methodology, data dictionary and supporting documentation
tests/             Detection testing and validation material
