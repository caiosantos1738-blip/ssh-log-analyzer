# Advanced Security Log Analyzer

A Python-based security log analysis tool designed to identify suspicious SSH authentication activities through automated detection rules, event correlation, MITRE ATT&CK mapping, risk scoring, and security alert generation.

This project is part of a hands-on cybersecurity portfolio focused on **SOC Analyst, Blue Team, and Security Monitoring** skills.

## Project Overview

The Advanced Security Log Analyzer processes SSH authentication logs, extracts structured security events, identifies suspicious activity, and generates sanitized reports.

The detection engine currently supports three security scenarios:

- **SSH Brute Force:** Detects repeated failed authentication attempts from the same source IP.
- **Password Spraying:** Identifies attempts involving multiple usernames from the same source IP.
- **Suspicious Login:** Detects successful authentication following multiple failed login attempts.

Generated alerts are enriched with MITRE ATT&CK technique information and a risk score. Sensitive information, including usernames and source IP addresses, is pseudonymized before report generation.

## Features

- SSH authentication log parsing.
- Support for ISO and traditional syslog timestamps.
- Automated security event classification.
- Brute force detection.
- Password spraying detection.
- Suspicious login detection.
- Time-window-based event correlation.
- MITRE ATT&CK technique mapping.
- Risk scoring and risk classification.
- Alert enrichment based on event volume and temporal correlation.
- Username and IP address pseudonymization.
- CSV security event reports.
- JSON security alert reports.
- Unit and integration testing.

## Technologies

| Technology | Purpose |
|---|---|
| Python 3 | Main programming language |
| Regular Expressions | Log parsing |
| CSV | Security event reporting |
| JSON | Alert reporting |
| Unittest | Automated testing |
| Linux / Ubuntu | Development environment |
| Git / GitHub | Version control |

**Dependencies:** The project uses Python standard library modules and does not require external Python packages.

## Detection Rules

| Detection Rule | Detection Criteria | Initial Severity |
|---|---|---|
| SSH Brute Force | 5 failed attempts within 5 minutes | HIGH |
| Password Spraying | 5 or more distinct usernames within 10 minutes from the same IP | HIGH |
| Suspicious Login | Successful login following at least 3 failed attempts within 10 minutes | HIGH |

These thresholds are configurable in the detection engine and are intended for educational security monitoring.

An alert indicates suspicious behavior, not definitive proof of a successful attack.

## Risk Scoring Engine

The project includes a risk scoring engine that evaluates generated security alerts and assigns a numerical score from 0 to 100.

The scoring mechanism considers three factors:

1. **Base Risk Score:** Each detection rule has an initial score according to its potential security impact.
2. **Event Volume Bonus:** Additional events above the minimum detection threshold increase the score.
3. **Correlation Bonus:** Alerts involving the same source IP and different detection rules receive an additional score when their time intervals overlap or are separated by no more than 10 minutes.

### Base Risk Scores

| Detection Rule | Base Score | Minimum Events |
|---|---:|---:|
| SSH Brute Force | 50 | 5 |
| Password Spraying | 55 | 5 |
| Suspicious Login | 65 | 4 |

### Scoring Parameters

| Parameter | Value |
|---|---:|
| Additional event bonus | +5 points per event |
| Maximum event volume bonus | +20 points |
| Temporal correlation bonus | +15 points |
| Maximum risk score | 100 |
| Correlation window | 10 minutes |

### Risk Classification

| Risk Score | Risk Level |
|---|---|
| 0–24 | LOW |
| 25–49 | MEDIUM |
| 50–74 | HIGH |
| 75–100 | CRITICAL |

The final risk classification is also reflected in the alert severity field.

**Note:** Risk scores are heuristic indicators intended to support security triage and investigation. They do not represent a definitive measurement of compromise.

## MITRE ATT&CK Integration

The detection engine enriches generated alerts with MITRE ATT&CK technique identifiers, names, and tactics.

| Detection Rule | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| SSH Brute Force | T1110.001 | Password Guessing | Credential Access |
| Password Spraying | T1110.003 | Password Spraying | Credential Access |
| Suspicious Login | T1110 | Brute Force | Credential Access |

The suspicious login mapping represents a behavioral correlation involving repeated authentication failures followed by a successful login. It does not independently confirm account compromise.

## Project Architecture

```text
ssh-log-analyzer/
│
├── docs/
│   └── INVESTIGATION_PLAYBOOK.md
│
├── evidence/
│   └── ssh-auth.log
│
├── reports/
│
├── src/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── parser.py
│   ├── detection.py
│   └── risk.py
│
├── tests/
│   ├── fixtures/
│   │   └── brute_force.log
│   ├── test_detection.py
│   ├── test_integration.py
│   └── test_risk.py
│
├── .gitignore
└── README.md
```

## How It Works

The analysis pipeline follows five main stages:

**1. Log Collection and Parsing**

The parser reads SSH authentication logs and extracts:

- Timestamp
- Event type
- Username
- Source IP address

**2. Event Processing**

Authentication records are converted into structured Python dictionaries for analysis.

**3. Threat Detection and MITRE Mapping**

The detection engine evaluates authentication events using configurable thresholds and time windows. When suspicious behavior is identified, the corresponding MITRE ATT&CK information is attached to the alert.

**4. Risk Scoring and Alert Enrichment**

The risk engine calculates a numerical score for each alert, evaluates temporal correlation between different detection rules, and assigns a risk classification.

**5. Report Generation**

The analyzer generates two output files:

| File | Description |
|---|---|
| `ssh-analysis.csv` | Sanitized authentication event report with risk information |
| `security-alerts.json` | Security alerts enriched with MITRE ATT&CK metadata and risk scores |

### Report Risk Attribution

The JSON report contains alert-specific risk scores and classifications.

In the CSV report, risk information is assigned at the source IP level using the highest alert risk score observed for that IP across the analyzed dataset. Therefore, the CSV risk score is not an individual event-level assessment.

Events without an associated alert receive an informational severity and a zero risk score.

## Installation

Clone the repository:

```bash
git clone https://github.com/caiosantos1738-blip/ssh-log-analyzer.git
```

Navigate to the project directory:

```bash
cd ssh-log-analyzer
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

No additional Python packages are required.

## Usage

Place your SSH authentication log at:

```text
evidence/ssh-auth.log
```

Run the analyzer from the project root:

```bash
python3 -m src.analyzer
```

Generated reports will be saved in:

```text
reports/
├── ssh-analysis.csv
└── security-alerts.json
```

## Running Tests

Execute the complete automated test suite:

```bash
python3 -m unittest discover -v
```

The test suite validates:

- Brute force detection.
- Password spraying detection.
- Suspicious login detection.
- Behavior below detection thresholds.
- MITRE ATT&CK mapping for all three detection rules.
- Risk score calculation.
- Risk classification boundaries.
- Event volume bonus and score limits.
- Temporal correlation between alerts.
- Alerts exactly at the 10-minute correlation boundary.
- Alerts outside the correlation window.
- Complete analysis pipeline and report generation.
- Data pseudonymization during report export.

**Current validation: 20 automated tests passed.**

## Example Detection Alert

A simulated brute force scenario involving five failed SSH authentication attempts within two minutes can generate an alert similar to the following:

```json
{
    "rule_id": "SSH_BRUTE_FORCE",
    "severity": "HIGH",
    "description": "Repeated SSH authentication failures detected",
    "source_ip": "IP_001",
    "event_count": 5,
    "first_seen": "2026-11-06T14:00:00+00:00",
    "last_seen": "2026-11-06T14:02:00+00:00",
    "mitre_technique_id": "T1110.001",
    "mitre_technique_name": "Password Guessing",
    "mitre_tactic": "Credential Access",
    "risk_score": 50,
    "risk_level": "HIGH"
}
```

The example uses a pseudonymized IP address and simulated authentication events.

## Security and Privacy

- Usernames and source IP addresses are pseudonymized in generated reports.
- Test fixtures use fictitious authentication records.
- Raw authentication logs should not be committed to public repositories.
- This project is intended for educational and controlled laboratory environments.

**Important:** Pseudonymization reduces exposure of sensitive information but does not guarantee complete anonymity. Review all files before publishing.

## Skills Demonstrated

- Linux security log analysis.
- Python scripting and automation.
- SSH authentication monitoring.
- Security event correlation.
- Detection engineering fundamentals.
- MITRE ATT&CK framework fundamentals.
- Risk-based alert prioritization.
- Incident detection and alert classification.
- Data sanitization and pseudonymization.
- Unit and integration testing.
- Git and GitHub workflows.

## Future Improvements

- Add Windows Event Log analysis.
- Implement additional detection rules.
- Improve alert correlation and deduplication.
- Add configurable detection thresholds.
- Improve timestamp and timezone handling.
- Generate visual security dashboards.
- Expand automated test coverage.

## Investigation Playbook

This project includes a security investigation playbook designed for SOC Analysts and Blue Team professionals.

The playbook covers:

- SSH Brute Force investigation.
- SSH Password Spraying investigation.
- Failed logins followed by successful authentication.
- Evidence collection and preservation.
- Incident classification.
- MITRE ATT&CK mapping.

Full documentation:

[SSH Security Investigation Playbook](docs/INVESTIGATION_PLAYBOOK.md)

## Disclaimer

This project is intended for educational purposes and cybersecurity portfolio development. Detection results are based on heuristic rules and should be investigated before being treated as confirmed security incidents.

---

**Developed as a cybersecurity portfolio project focused on SOC Analysis and Blue Team operations.**
