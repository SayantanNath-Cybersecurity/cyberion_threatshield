# Cyberion ThreatShield

Detection Engineering & Threat Hunting

A structured cybersecurity detection engineering and threat hunting project focused on Windows security telemetry, Sigma detection development, MITRE ATT&CK mapping, behavioral correlation, threat hunting, incident investigation, detection tuning, IOC research, and incident response documentation.

Cyberion ThreatShield was developed as a defensive cybersecurity project with a focus on transforming raw Windows event telemetry into validated, documented, and operationally useful detection content.

The project follows an evidence-driven workflow:

```text
Telemetry
    ↓
Analysis
    ↓
Detection Engineering
    ↓
ATT&CK Mapping
    ↓
Validation
    ↓
Threat Hunting
    ↓
Investigation
    ↓
Detection Tuning
    ↓
Documentation
Project Status

Finalized

The core Cyberion ThreatShield project milestone has been completed.

The final project includes:

19 Sigma detection rules
3 correlation-style detections
20 MITRE ATT&CK techniques assessed
4+ ATT&CK tactics assessed
22 automated detection tests
2 structured threat hunts
2 incident investigation cases
3 incident response playbooks
IOC research
Detection tuning documentation
ATT&CK coverage matrix
Detection testing evidence
Methodology documentation
Executive summary
Final project presentation

Final validation:

22 passed

Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
Project Objectives

Cyberion ThreatShield was developed to demonstrate a practical detection engineering and threat hunting workflow using publicly available Windows security telemetry.

The primary objectives are:

Analyze Windows EVTX security telemetry.
Identify observable security-relevant behaviors.
Develop portable Sigma detections.
Map detections to MITRE ATT&CK techniques.
Validate detections against actual telemetry.
Develop behavioral correlation detections.
Conduct structured threat hunts.
Investigate telemetry-driven security findings.
Document incident response procedures.
Identify and document false-positive behavior.
Tune detection logic based on observed telemetry.
Document detection engineering decisions.
Produce reusable defensive security content.
Core Features
Detection Engineering
Windows EVTX telemetry analysis
Sigma detection development
Event ID analysis
Field-level telemetry analysis
Process and authentication analysis
Detection logic development
Severity classification
False-positive consideration
ATT&CK technique mapping
Detection testing against actual EVTX files
Correlation-style detection engineering
Threat Hunting
Structured threat hunting
Hypothesis-driven investigation
Authentication behavior analysis
Kerberos authentication analysis
WMI execution analysis
Cross-event correlation
Source and target account analysis
Evidence-based hunt findings
Incident Investigation
Event-level investigation
Security event timeline analysis
Authentication analysis
Process execution analysis
Behavioral correlation
ATT&CK technique identification
Evidence documentation
Investigation limitations
Case-based reporting
Detection Tuning
False-positive analysis
Detection logic refinement
Authentication noise analysis
Process filtering
Correlation refinement
Observed-match comparison
Detection retirement when appropriate
Tuning trade-off documentation
Incident Response

The project contains three incident response playbooks covering investigated security scenarios.

Playbooks provide structured response guidance based on the telemetry and investigation findings documented within the project.

IOC Research

The project contains dedicated IOC and telemetry research covering indicators and observable characteristics that can support:

Detection development
Threat hunting
Analyst triage
Investigation
Correlation
Defensive monitoring
Reporting

The project includes:

Detection testing reports
Detection tuning reports
Threat hunting reports
Incident case reports
ATT&CK coverage documentation
Methodology documentation
Executive summary
Final presentation
Project Requirements

The project was designed around the following major requirements:

Requirement	Status
Detection engineering	✅ Completed
Sigma detection library	✅ Completed
15+ final detections	✅ Completed
Correlation-style detections	✅ Completed
MITRE ATT&CK mapping	✅ Completed
20 techniques assessed	✅ Completed
4+ tactics assessed	✅ Completed
Detection testing against actual telemetry	✅ Completed
False-positive review	✅ Completed
Detection tuning	✅ Completed
Threat hunts	✅ Completed
Incident investigations	✅ Completed
Incident response playbooks	✅ Completed
IOC research	✅ Completed
Executive reporting	✅ Completed
Final presentation	✅ Completed
Dataset
EVTX-ATTACK-SAMPLES

The primary telemetry source used by Cyberion ThreatShield is:

EVTX-ATTACK-SAMPLES

Upstream repository:

https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

Dataset commit used for reproducibility:

4ceed2f4706daf601c212a8f91c113dd85349a2c

The dataset contains Windows EVTX telemetry representing security-relevant and adversarial behaviors.

The project analyzes telemetry from areas including:

Credential Access
Defense Evasion
Execution
Lateral Movement
Privilege Escalation
Persistence
Discovery
Authentication activity
Process execution
Other Windows security behaviors represented in the dataset

The raw third-party dataset is intentionally excluded from Git version control.

Dataset metadata is documented in:

data/metadata/evtx_attack_samples.md
Detection Library

The final detection library contains:

19 Sigma rules

Each final detection includes:

Detection identifier
Detection title
Detection logic
MITRE ATT&CK technique
References
Severity
False-positive considerations
Testing evidence

The final library contains both atomic detections and correlation-style detections.

Detection Inventory
ID	Detection	ATT&CK
CTSHIELD-001	Windows Security Event Log Cleared	T1685.005
CTSHIELD-002	Kerberos Pre-Authentication Failure	T1110.001
CTSHIELD-003	WMI Provider Host Process Creation	T1047
CTSHIELD-004	WMIC Explicit Credential Use	T1047
CTSHIELD-005	Network Logon to Administrator Account	T1078.001
CTSHIELD-006	Failed Interactive Logon	T1110.001
CTSHIELD-007	DCSync	T1003.006
CTSHIELD-008	PowerShell Credential Prompt/Extraction	T1059.001
CTSHIELD-009	Test Signing Enabled	T1553.006
CTSHIELD-010	Browser Credential Store Access	T1555.003
CTSHIELD-011	Plink Network Tunneling	T1572
CTSHIELD-012	Hidden Scheduled Task	T1053.005
CTSHIELD-013	Suspicious Service Creation	T1543.003
CTSHIELD-014	Computer Account Creation	T1136.002
CTSHIELD-015	Mimikatz Process Access to LSASS	T1003.001
CTSHIELD-016	PowerShell Remoting Child Process	T1021.006
CTSHIELD-018	Kerberos Multi-Account Correlation	T1110.003
CTSHIELD-019	WMI Authentication/Execution Correlation	T1047
CTSHIELD-020	IIS Credential-Use Correlation	T1078
Retired Detection
CTSHIELD-017

CTSHIELD-017 was developed as an experimental detection during the detection engineering and tuning workflow.

Testing identified limitations in the signal quality of the original detection.

The detection was therefore removed from the final detection library.

Its tuning history remains documented in:

reports/tuning/CTSHIELD-017_tuning.md

This preserves the detection engineering lifecycle and demonstrates that detection development includes evaluating whether a rule should be retained, modified, or retired.

The final library therefore contains:

19 final Sigma rules

rather than counting the retired experimental detection.

Correlation Detection

Three correlation-style detections are included in the final library.

CTSHIELD-018
Kerberos Multi-Account Correlation

Correlates Kerberos pre-authentication failures originating from the same source address against multiple target accounts within a defined time window.

The detection uses multiple authentication failure events to identify a behavioral pattern rather than relying on a single event.

The corresponding testing evidence demonstrates multiple target accounts associated with the same source address.

CTSHIELD-019
WMI Authentication/Execution Correlation

Correlates:

Successful Network Logon
        ↓
WMI Provider Host Process Creation

The events are correlated using the Windows host and a defined temporal window.

This provides additional behavioral context around WMI-related remote execution activity.

CTSHIELD-020
IIS Credential-Use Correlation

Correlates explicit credential use by an IIS worker process with a subsequent successful logon involving the corresponding account context.

The detection provides behavioral context around web-server credential use.

The associated investigation also documents the limitations of Windows Security telemetry when attempting to establish the complete scope or cause of a web-server compromise.

MITRE ATT&CK Coverage

The project contains a dedicated ATT&CK coverage analysis.

Coverage is documented in:

docs/attack_coverage_matrix.md

The final analysis assesses:

20 MITRE ATT&CK techniques
4+ ATT&CK tactics

The coverage analysis connects detection content to specific ATT&CK techniques.

The project therefore maintains traceability between:

Telemetry
    ↓
Observed Behavior
    ↓
Detection
    ↓
ATT&CK Technique
    ↓
Testing Evidence
Detection Engineering Pipeline

Cyberion ThreatShield follows a structured detection engineering workflow.

                  ┌─────────────────────┐
                  │   EVTX Telemetry    │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Telemetry Analysis  │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Behavior Discovery  │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Sigma Development   │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ ATT&CK Mapping      │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Telemetry Testing   │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ FP Analysis         │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Detection Tuning    │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Correlation Logic   │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Documentation       │
                  └─────────────────────┘
Threat Hunting Workflow

Threat hunting follows an evidence-driven workflow:

Hunt Hypothesis
      ↓
Identify Relevant Telemetry
      ↓
Inspect Event Fields
      ↓
Search for Behavioral Patterns
      ↓
Correlate Related Events
      ↓
Validate Against Dataset
      ↓
Document Evidence
      ↓
Map to ATT&CK
      ↓
Record Hunt Finding

Two structured hunts are included.

HUNT-001
WMI Remote Execution

File:

hunts/HUNT-001_wmi_remote_execution.md

The hunt examines WMI-related authentication and process execution telemetry.

HUNT-002
Kerberos Authentication Failures

File:

hunts/HUNT-002_kerberos_authentication_failures.md

The hunt examines repeated Kerberos authentication failures and multi-account activity originating from a common source.

Incident Investigation

Two incident cases are included.

CASE-001
WMI Remote Execution

File:

incidents/CASE-001_wmi_remote_execution.md

The case documents investigation of WMI-related remote execution telemetry.

CASE-002
Web Server Credential Use

File:

incidents/CASE-002_webserver_credential_use.md

The case documents Windows Security telemetry associated with IIS worker process credential use and successful authentication.

The investigation distinguishes between directly observed telemetry and conclusions that cannot be established from the available event data alone.

Incident Response Playbooks

Three incident response playbooks are included.

PB-001
WMI Remote Execution Response
playbooks/PB-001_wmi_remote_execution_response.md
PB-002
Kerberos Authentication Failure Response
playbooks/PB-002_kerberos_authentication_failure_response.md
PB-003
Web Server Credential Use Response
playbooks/PB-003_web_server_credential_use_response.md
IOC Research

IOC research is documented in:

ioc-research/IOC-RESEARCH-001_telemetry_indicators.md

The research examines indicators and telemetry characteristics that can support:

Detection engineering
Threat hunting
Analyst triage
Investigation
Correlation
Defensive monitoring
Detection Testing

The project includes automated tests for detection behavior.

The test suite covers:

Atomic detection logic
Correlation detections
Event field matching
Temporal relationships
Source and target relationships
Detection tuning behavior

Run the complete test suite:

python -m pytest -q

Current result:

22 passed in 2.20s
Sigma Validation

Sigma rules can be validated using:

sigma check detections/sigma/

Current validation result:

Found 0 errors, 0 condition errors and 0 issues.

No rule errors found.
No condition errors found.
No validation issues found.
Detection Tuning

Detection tuning was performed using observed telemetry and documented false-positive behavior.

The tuning process considers:

Initial detection matches
Legitimate activity
Authentication noise
Process relationships
Event context
Logic refinement
Signal quality
Detection trade-offs

Documented tuning reports are located in:

reports/tuning/

Current documented tuning work includes:

CTSHIELD-006
CTSHIELD-016
CTSHIELD-017

The CTSHIELD-017 tuning history also demonstrates the decision to retire an experimental detection from the final library.

Documentation

The project documentation is organized as follows:

docs/
│
├── data_dictionary.md
├── technique_candidates.md
├── attack_coverage_matrix.md
└── methodology.md
data_dictionary.md

Documents relevant telemetry fields and event structures used during analysis.

technique_candidates.md

Documents candidate ATT&CK techniques considered during detection development.

attack_coverage_matrix.md

Documents final ATT&CK technique coverage and detection relationships.

methodology.md

Documents the project's overall detection engineering, hunting, investigation, and validation methodology.

Reports

The reports directory contains:

reports/
│
├── detection-testing/
├── tuning/
├── presentation/
├── executive_summary.md
└── Cyberion_ThreatShield_Final_Presentation.pptx
Detection Testing

Contains individual validation reports for the final detection library.

Tuning

Contains documented false-positive and tuning passes.

Executive Summary

Provides a high-level summary of the completed project and major findings.

Final Presentation

Contains the completed project presentation.

Project Structure
cyberion_threatshield/
│
├── data/
│   ├── raw/
│   │   └── evtx-attack-samples/
│   └── metadata/
│       └── evtx_attack_samples.md
│
├── detections/
│   └── sigma/
│       ├── CTSHIELD-001_*.yml
│       ├── CTSHIELD-002_*.yml
│       ├── ...
│       ├── CTSHIELD-016_*.yml
│       ├── ctshield-018_*.yml
│       ├── ctshield-019_*.yml
│       └── ctshield-020_*.yml
│
├── docs/
│   ├── data_dictionary.md
│   ├── technique_candidates.md
│   ├── attack_coverage_matrix.md
│   └── methodology.md
│
├── hunts/
│   ├── HUNT-001_wmi_remote_execution.md
│   └── HUNT-002_kerberos_authentication_failures.md
│
├── incidents/
│   ├── CASE-001_wmi_remote_execution.md
│   └── CASE-002_webserver_credential_use.md
│
├── ioc-research/
│   └── IOC-RESEARCH-001_telemetry_indicators.md
│
├── playbooks/
│   ├── PB-001_wmi_remote_execution_response.md
│   ├── PB-002_kerberos_authentication_failure_response.md
│   └── PB-003_web_server_credential_use_response.md
│
├── reports/
│   ├── detection-testing/
│   ├── tuning/
│   ├── presentation/
│   ├── executive_summary.md
│   └── Cyberion_ThreatShield_Final_Presentation.pptx
│
├── tests/
│   └── detections/
│
├── .gitignore
└── README.md
Architecture

Cyberion ThreatShield is an analytical/content-engineering project rather than a deployed application.

Its architecture is therefore centered around the relationship between telemetry, detection content, testing, and investigation.

                    ┌─────────────────────┐
                    │ Public EVTX Dataset │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Telemetry Analysis  │
                    └──────────┬──────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
             ▼                 ▼                 ▼
       Detection           Threat Hunt      IOC Research
       Engineering              │                 │
             │                  │                 │
             ▼                  ▼                 │
       Sigma Rules         Hunt Findings          │
             │                  │                 │
             └────────────┬─────┴─────────────────┘
                          │
                          ▼
                 ┌─────────────────────┐
                 │ ATT&CK Mapping      │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Detection Testing   │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ FP Review & Tuning  │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Incident Cases      │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Response Playbooks  │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Final Documentation │
                 └─────────────────────┘
Installation

Cyberion ThreatShield is primarily an analytical repository.

The project does not require:

A database server
A web server
A REST API
A SIEM platform
A SOAR platform
A backend service

The primary environment used for analysis is a Linux security-analysis environment with Python and Sigma CLI.

Requirements

Recommended software:

Python 3.14.x (validated environment)
Git
Python virtual environment support
Sigma CLI

Python packages used by the project include:

python-evtx
pytest
python-pptx
Installation & Setup
1. Clone the Repository
git clone <repository-url>
cd cyberion_threatshield

Replace <repository-url> with the actual Git repository URL.

2. Create the Python Virtual Environment
python3 -m venv .venv

Activate it:

source .venv/bin/activate
3. Upgrade pip
python -m pip install --upgrade pip
4. Install Python Dependencies
python -m pip install python-evtx pytest python-pptx
5. Install Sigma CLI
python -m pip install sigma-cli

Verify:

sigma --version

Confirm the environment is using the virtual-environment installation:

which sigma
Dataset Setup

The raw EVTX dataset is excluded from Git version control.

Clone the upstream dataset:

git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git \
data/raw/evtx-attack-samples

For reproducibility, use the documented upstream commit:

cd data/raw/evtx-attack-samples

git checkout 4ceed2f4706daf601c212a8f91c113dd85349a2c

cd ../../..

The dataset metadata is documented in:

data/metadata/evtx_attack_samples.md
Running Validation

Activate the virtual environment:

source .venv/bin/activate

Run the detection test suite:

python -m pytest -q

Validate the Sigma library:

sigma check detections/sigma/
Testing

The project includes automated tests covering the detection library.

Run:

python -m pytest -q

Current test result:

22 passed in 2.20s

Sigma validation:

0 errors
0 condition errors
0 issues
Final Validation Summary
Validation Area	Result
Final Sigma rules	19
ATT&CK techniques assessed	20
ATT&CK tactics assessed	4+
Correlation detections	3
Threat hunts	2
Incident cases	2
Response playbooks	3
IOC research reports	1
Documented tuning passes	3
Automated tests	22
Pytest result	22 passed
Sigma errors	0
Sigma condition errors	0
Sigma issues	0
Final Deliverables

The completed project provides the following major deliverables:

Detection Rule Library
        │
        ├── 19 Sigma Rules
        └── 3 Correlation Detections

ATT&CK Coverage
        │
        └── 20 Techniques / 4+ Tactics

Threat Hunting
        │
        ├── HUNT-001
        └── HUNT-002

Incident Investigation
        │
        ├── CASE-001
        └── CASE-002

Incident Response
        │
        ├── PB-001
        ├── PB-002
        └── PB-003

Research
        │
        └── IOC Research

Detection Quality
        │
        ├── Detection Testing
        └── Detection Tuning

Project Documentation
        │
        ├── Methodology
        ├── ATT&CK Coverage Matrix
        ├── Data Dictionary
        ├── Technique Candidates
        └── Executive Summary

Presentation
        │
        └── Final Project Presentation
Presentation

The final presentation is available at:

reports/Cyberion_ThreatShield_Final_Presentation.pptx

The presentation covers:

Project objectives
Dataset
Detection engineering methodology
Detection library
ATT&CK coverage
Correlation detections
Threat hunting
Incident investigations
Detection tuning
IOC research
Incident response playbooks
Validation results
Project deliverables
Final conclusions

The presentation generation script is also retained at:

reports/presentation/create_presentation.py
Reproducibility

The project records the exact upstream dataset commit used during development:

4ceed2f4706daf601c212a8f91c113dd85349a2c

This allows the telemetry foundation of the project to be reproduced independently.

The repository itself contains the detection logic, testing code, reports, investigation documentation, playbooks, and analytical documentation.

The third-party raw EVTX dataset is not committed to Git.

Security & Usage Notes

Cyberion ThreatShield is a defensive cybersecurity detection engineering project.

The project is intended for:

Security research
Detection engineering
Threat hunting
SOC training
Defensive security analysis
Security portfolio demonstration

The telemetry used by the project comes from a public security dataset.

Testing and analysis should be performed only against systems, files, and telemetry that you are authorized to access.

Project Outcome

Cyberion ThreatShield demonstrates an end-to-end defensive detection engineering workflow:

                ┌───────────────────┐
                │ Public Telemetry  │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │ Detection Design  │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │ ATT&CK Mapping    │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │ Testing            │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │ Threat Hunting    │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │ Investigation     │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │ Tuning            │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │ Documentation     │
                └───────────────────┘

The completed project combines detection content, telemetry analysis, ATT&CK mapping, threat hunting, incident investigation, tuning, and response documentation into a single reproducible security analysis repository.

License & Third-Party Data

Cyberion ThreatShield uses the publicly available EVTX-ATTACK-SAMPLES dataset as its primary telemetry source.

The upstream dataset is maintained by its original authors.

Users reproducing or extending this project should review and comply with the applicable terms of the upstream dataset and repository.
