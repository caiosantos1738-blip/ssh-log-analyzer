# SSH Security Incident Investigation Playbook

**Project:** Advanced Security Log Analyzer
**Role:** SOC Analyst / Blue Team
**Environment:** Linux SSH Authentication Logs
**Framework:** MITRE ATT&CK
**Document Type:** Security Investigation Playbook
**Version:** 1.0

---

## 1. Purpose

This playbook establishes a standardized procedure for investigating suspicious SSH authentication activities detected by the Advanced Security Log Analyzer.

Its objectives are to:

- Identify suspicious authentication patterns.
- Investigate potential brute-force attacks.
- Detect password spraying attempts.
- Identify suspicious successful logins following repeated failures.
- Collect and preserve relevant evidence.
- Recommend appropriate containment and remediation actions.
- Document investigation findings.

## 2. Scope

This playbook covers three detection scenarios:

| Detection Rule | MITRE ATT&CK | Severity |
|---|---|---|
| SSH_BRUTE_FORCE | T1110.001 – Password Guessing | High |
| SSH_PASSWORD_SPRAYING | T1110.003 – Password Spraying | High |
| SSH_FAILURES_FOLLOWED_BY_SUCCESS | T1110 – Brute Force | High |

These detections indicate suspicious authentication behavior. An alert alone does not confirm that a system has been compromised.

## 3. Investigation Workflow

Every investigation should follow these stages:

1. Alert identification.
2. Initial triage.
3. Evidence collection.
4. Event correlation.
5. Impact assessment.
6. Containment recommendations.
7. Documentation and closure.

---

## 4. Playbook 01 – SSH Brute Force

### Detection

**Rule:** SSH_BRUTE_FORCE

**MITRE ATT&CK:** T1110.001 – Password Guessing

**Trigger condition:** Five or more failed SSH authentication attempts from the same source IP within five minutes.

### Investigation Procedure

**Step 1 – Identify the source IP**

Extract the source IP associated with the alert.

Review:
- Source IP address.
- First observed timestamp.
- Last observed timestamp.
- Number of failed authentication attempts.

**Step 2 – Analyze authentication patterns**

Determine whether:
- Attempts target a single username.
- Multiple usernames are being targeted.
- Authentication attempts occur at regular intervals.
- Attempts originate from an unexpected network.

**Step 3 – Review successful authentication events**

Check whether the same source IP has any successful SSH authentication events.

A successful login following repeated failures increases the priority of the investigation.

**Step 4 – Assess potential impact**

Determine:
- Whether the targeted account is privileged.
- Whether the source IP is expected.
- Whether additional suspicious activity occurred after authentication.

### Recommended Response

If the activity is confirmed as malicious:

- Escalate the incident to the appropriate security team.
- Consider temporarily blocking the source IP through approved security controls.
- Review the targeted account for unauthorized access.
- Reset potentially compromised credentials.
- Review SSH authentication policies.
- Consider disabling password-based SSH authentication where operationally appropriate.

### Investigation Outcome

Classify the finding as:

- True Positive.
- False Positive.
- Benign True Positive.
- Inconclusive.

---

## 5. Playbook 02 – SSH Password Spraying

### Detection

**Rule:** SSH_PASSWORD_SPRAYING

**MITRE ATT&CK:** T1110.003 – Password Spraying

**Trigger condition:** Failed authentication attempts against five or more distinct usernames from the same source IP within ten minutes.

### Investigation Procedure

**Step 1 – Identify targeted accounts**

Extract the usernames associated with the suspicious source IP.

Look for:
- Standard user accounts.
- Administrative accounts.
- Service accounts.
- Accounts with unusual naming patterns.

**Step 2 – Analyze attack distribution**

Determine whether:
- Multiple accounts are targeted.
- Attempts are distributed over time.
- Authentication attempts use similar patterns.
- The same source IP has triggered previous alerts.

**Step 3 – Check for successful authentication**

Identify whether any targeted account successfully authenticated during or after the suspicious activity.

**Step 4 – Assess account exposure**

Review whether targeted accounts have:
- Administrative privileges.
- Access to sensitive resources.
- Weak or reused credentials, if authorized evidence is available.

### Recommended Response

- Escalate suspicious activity.
- Review all targeted accounts.
- Investigate successful authentication events.
- Consider source IP blocking through approved procedures.
- Require credential resets when compromise is suspected.
- Review MFA and SSH authentication controls.

### Investigation Outcome

Document the number of targeted accounts, authentication failures, successful logins, and potential exposure.

---

## 6. Playbook 03 – Failed Logins Followed by Successful Authentication

### Detection

**Rule:** SSH_FAILURES_FOLLOWED_BY_SUCCESS

**MITRE ATT&CK:** T1110 – Brute Force

**Trigger condition:** Three or more failed authentication attempts followed by a successful login from the same source IP within ten minutes.

### Investigation Procedure

**Step 1 – Identify the successful authentication**

Extract:
- Source IP.
- Username.
- Successful authentication timestamp.
- Previous failed authentication timestamps.

**Step 2 – Establish the event timeline**

Build a chronological sequence of authentication events.

Example:

| Timestamp | Event |
|---|---|
| 14:00:10 | Failed login |
| 14:01:05 | Failed login |
| 14:02:20 | Failed login |
| 14:03:15 | Successful login |

**Step 3 – Validate the authentication context**

Determine whether:
- The successful login used the same source IP.
- The account owner recognizes the activity.
- The login time is expected.
- The source IP belongs to an authorized network.

**Step 4 – Investigate post-authentication activity**

If authorized logs are available, inspect:
- Shell command history.
- Privilege escalation events.
- New user creation.
- Changes to SSH configuration.
- Unusual processes.
- Access to sensitive files.

### Recommended Response

If unauthorized access is suspected:

- Escalate immediately.
- Consider isolating the affected host according to incident response procedures.
- Disable or secure the potentially compromised account.
- Revoke unauthorized SSH keys.
- Review privileged activity.
- Preserve relevant logs and evidence.
- Assess whether credentials or sensitive information were exposed.

### Investigation Outcome

A successful login after repeated failures is a strong investigation signal, but it does not independently prove account compromise.

---

## 7. Evidence Collection Checklist

During every investigation, collect the following information:

- [ ] Alert identifier and detection rule.
- [ ] Source IP address.
- [ ] Targeted username or usernames.
- [ ] First observed timestamp.
- [ ] Last observed timestamp.
- [ ] Number of failed authentication attempts.
- [ ] Number of successful authentication attempts.
- [ ] Related authentication events.
- [ ] Relevant system logs.
- [ ] Investigation timeline.
- [ ] Analyst findings.
- [ ] Recommended response actions.

**Evidence handling:**

- Preserve original log files.
- Work with copies whenever possible.
- Restrict access to sensitive evidence.
- Avoid publishing real usernames, IP addresses, or authentication logs.
- Record timestamps and relevant investigation actions.

---

## 8. Incident Classification

| Classification | Description |
|---|---|
| Critical | Confirmed unauthorized privileged access or severe compromise |
| High | Strong indicators of unauthorized authentication activity |
| Medium | Suspicious activity requiring additional validation |
| Low | Limited suspicious behavior without evidence of compromise |

The classification must consider the actual impact and available evidence, not only the detection rule severity.

## 9. MITRE ATT&CK Reference

| Technique | Name | Tactic |
|---|---|---|
| T1110 | Brute Force | Credential Access |
| T1110.001 | Password Guessing | Credential Access |
| T1110.003 | Password Spraying | Credential Access |

Reference: https://attack.mitre.org/techniques/T1110/

## 10. Investigation Report Template

Use the following template when documenting an investigation:

**Incident ID:**
**Detection Rule:**
**Date and Time:**
**Source IP:**
**Affected Account(s):**
**Severity:**
**MITRE ATT&CK Technique:**

### Executive Summary

Describe the suspicious activity and why it was investigated.

### Technical Findings

Document relevant authentication events, timestamps, source addresses, and account information.

### Timeline

Provide a chronological sequence of relevant events.

### Impact Assessment

Describe whether unauthorized access or system compromise was confirmed.

### Response Actions

Document containment, remediation, and escalation actions.

### Final Classification

- True Positive
- False Positive
- Benign True Positive
- Inconclusive

### Analyst Notes

Include additional observations, limitations, and recommendations.

---

## 11. Important Investigation Considerations

- Detection thresholds are configurable and do not represent universal attack definitions.
- A source IP may represent multiple users behind NAT or a corporate gateway.
- Repeated failed logins may result from legitimate misconfigured services.
- Successful authentication does not automatically indicate compromise.
- Additional telemetry may be necessary to establish the full attack impact.
- All containment actions must follow organizational authorization procedures.

## 12. Playbook Completion Criteria

An investigation is considered complete when:

- The alert has been reviewed.
- Relevant evidence has been collected.
- Authentication events have been correlated.
- Potential impact has been assessed.
- The finding has been classified.
- Recommended or executed response actions have been documented.
- The incident has been closed or escalated.

---

**End of Playbook**

*Advanced Security Log Analyzer – SSH Log Analyzer Project*
