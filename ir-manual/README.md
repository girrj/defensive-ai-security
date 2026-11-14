# Cyber incident response manual

A template incident response (IR) manual for an organization with an in-house SOC or CERT. It is structured around **NIST SP 800-61 Rev. 3** (April 2025), which aligns incident response with the six CSF 2.0 Functions (Govern, Identify, Protect, Detect, Respond, Recover) and replaces the Rev. 2 incident-handling lifecycle. It also includes Korean legal reporting requirements as of November 2026.

Fill in everything in `<angle brackets>`, review the manual with legal and management, test it in an exercise at least once a year, and record the review date.

| Part | Contents |
| --- | --- |
| [1. Governance](#1-governance) | Scope, definitions, roles, authority |
| [2. Severity and escalation](#2-severity-and-escalation) | Classification, escalation triggers, response targets |
| [3. Response process](#3-response-process) | Detect → analyze → contain → eradicate → recover → learn |
| [4. Communication](#4-communication) | Internal and external, cadence, templates |
| [5. Legal and regulatory reporting (Korea)](#5-legal-and-regulatory-reporting-korea) | Network Act and PIPA timelines, decision tree |
| [6. Evidence and documentation](#6-evidence-and-documentation) | What to record and keep |
| [7. Preparation and readiness](#7-preparation-and-readiness) | Prerequisites, exercises, review |
| [Appendix A](#appendix-a-contact-sheet) | Contact sheet |
| [Appendix B](#appendix-b-first-hour-checklist) | First-hour checklist |

---

## 1. Governance

### 1.1 Scope

This manual covers cybersecurity incidents that affect `<organization>`'s information systems, data, or services, including those run by third parties on its behalf (cloud, managed services, outsourcing).

### 1.2 Definitions

| Term | Meaning |
| --- | --- |
| **Event** | Any observable occurrence (a log entry, an alert) |
| **Security alert** | An event flagged by a control as potentially malicious |
| **Incident** | An occurrence that actually or imminently jeopardizes the confidentiality, integrity, or availability of information or systems, or violates security policy |
| **Personal data breach** | Loss, theft, or leakage of personal information, including suspected cases (see §5) |
| **Major incident** | Severity 1, or any incident that triggers a legal report, affects customers, or needs executive decisions |

### 1.3 Roles

| Role | Responsibilities | Primary / backup |
| --- | --- | --- |
| **Incident Commander (IC)** | Owns the incident: decisions, priorities, coordination, and declaring closure. Doesn't do hands-on analysis | `<name>` / `<name>` |
| **Technical Lead** | Directs analysis, containment, and eradication, and assigns analysts | |
| **SOC / CERT analysts** | Triage, investigation, forensics, detection updates | |
| **Scribe** | Keeps the incident log and timeline in real time | |
| **Communications Lead** | Internal updates, and media and customer messaging with legal | |
| **Legal / Privacy (CPO)** | Regulatory reporting decisions, privilege, notification content | |
| **CISO** | Escalation point, executive briefings, risk acceptance | |
| **System / service owners** | Business impact, approval for downtime, recovery | |
| **External IR retainer** | Surge capacity and specialist forensics | `<vendor, contract #, hotline>` |

### 1.4 Pre-approved authority

To avoid delay, the IC and the Technical Lead may do the following **without further approval** and inform the owner right after:

- Network-isolate any endpoint, or any server below `<criticality tier>`, through EDR
- Disable user accounts and revoke sessions and tokens
- Block IPs, domains, URLs, and hashes at perimeter controls
- Reset credentials for accounts showing compromise

Actions that need the CISO's (or a delegate's) approval: isolating crown-jewel systems, shutting down customer-facing services, engaging law enforcement, paying any third party connected to the incident, and any public statement.

---

## 2. Severity and escalation

| Severity | Criteria (any one) | Examples | IC assigned | CISO informed | Updates |
| --- | --- | --- | --- | --- | --- |
| **S1 Critical** | Active compromise of crown-jewel systems. Ransomware or destructive activity. Confirmed exfiltration of sensitive or personal data. Customer-facing outage from an attack | Domain admin compromise, encryption in progress | Immediately | Immediately | Hourly |
| **S2 High** | Confirmed compromise of a server or several hosts. Suspected personal data breach. Exploitation of an internet-facing system | Web shell on a production server | ≤ 1h | ≤ 2h | Every 4h |
| **S3 Medium** | A single compromised endpoint, contained. A malicious email with clicks but no execution | Commodity malware blocked after execution | Team lead | Daily summary | Daily |
| **S4 Low** | Attempted attack with no impact. Policy violation | Blocked scanning, unsuccessful phishing | — | Weekly report | — |

**Escalate immediately** when there's evidence of lateral movement, privileged account compromise, data leaving the network, a second business unit affected, media or attacker contact (extortion), or the possible legal reporting triggers in §5.

---

## 3. Response process

NIST SP 800-61r3 treats preparation and lessons learned as continuous activities across the CSF Functions, and treats detection, response, and recovery as the incident-handling core. The phases below follow that model and are written as runnable steps.

### 3.1 Detect and declare

1. An alert, a user report, a third-party notification, or a threat-intelligence match comes in.
2. The SOC triages it according to the [alert triage standard](../soc-operations/alert-triage-standard.md).
3. Once it is confirmed or strongly suspected as an incident: **declare it**, open an incident record, set the severity, and assign the IC. Record the **time of awareness**, because legal reporting clocks start from it (§5).

### 3.2 Analyze and scope

- Build the timeline from raw logs: initial access → execution → persistence → privilege escalation → lateral movement → actions on objectives.
- Identify all affected hosts, accounts, and data, using indicators **and** behaviors.
- Decide what evidence to preserve before containment changes anything (§6, [forensics](../forensics/)).
- Use the matching playbook: [web shell](../playbooks/web-shell-compromise.md), [ransomware](../playbooks/ransomware-precursor.md), [zero-day](../playbooks/zero-day-response.md), [AI coding agent](../playbooks/ai-coding-agent-incident.md).

### 3.3 Contain

| Strategy | When |
| --- | --- |
| **Immediate containment** | Destructive activity, active exfiltration, ransomware |
| **Monitored containment** | The attacker isn't yet fully scoped and early action would tip them off. Requires IC approval and close monitoring |

Short term: isolate hosts, disable accounts, block indicators. Long term: segment, rebuild or patch, and keep enhanced monitoring in place.

Check before you contain: is evidence preserved, are backups protected, and do you know **every** access path the attacker has? Contain them all at once, because partial containment tips off the attacker.

### 3.4 Eradicate

- Remove persistence, malware, and attacker accounts and keys.
- Close the initial access vector with a patch, a configuration change, or a credential reset.
- Reset credentials in scope. For domain compromise, follow a planned **KRBTGT double reset** and tier-0 credential rotation.
- Rebuild from known-good images rather than cleaning, for any host where the attacker had administrative execution.

### 3.5 Recover

- Restore from backups that have been checked as clean. Scan the restored data and confirm the backup date is before the earliest attacker activity.
- Bring systems back in stages under heightened monitoring, and watch for re-entry for at least 30 days.
- The service owner confirms that business functions work before the incident is declared resolved.

### 3.6 Lessons learned (within 10 business days of closure)

A blameless review covering:

- **Timeline metrics**: time to detect, time to contain, time to recover
- What worked, and what slowed us down (tools, access, decisions, information)
- Root cause, and why existing controls didn't stop it
- Corrective actions, each with an owner and a due date, tracked to completion
- Detection improvements (new or tuned rules, see the [detection engineering lifecycle](../soc-operations/detection-engineering-lifecycle.md)) and updates to this manual

---

## 4. Communication

| Audience | Owner | Channel | Content | Cadence (S1 / S2) |
| --- | --- | --- | --- | --- |
| Response team | IC | Dedicated incident channel, plus an out-of-band backup | Tasks, findings, decisions | Continuous |
| CISO and executives | IC → CISO | Briefing call or written update | Status, impact, decisions needed, next update time | Hourly / every 4h |
| Service owners | Technical Lead | Direct | Actions on their systems, downtime | As needed |
| All staff | Communications Lead | Email / intranet | Instructions only (e.g. "don't open X", "reset your password") | As needed |
| Customers and data subjects | Communications Lead + Legal | Per §5 | Legally required content | Per §5 |
| Regulators and authorities | Legal / CPO | Official portals | Legally required content | Per §5 |
| Media | Communications Lead | Statement | Approved holding statement only | Only if needed |

**If you suspect the attacker can read company email or chat** (for example, after mailbox or directory compromise), move incident communication to a pre-arranged out-of-band channel.

Every update follows the same format: *what we know, what we don't know yet, what we're doing, what we need from you, next update at.*

---

## 5. Legal and regulatory reporting (Korea)

> **Status as of November 2026. Have legal confirm before each use.** Both laws below were amended in 2026, and reporting thresholds and deadlines continue to change. Other duties may also apply: sector regulators (finance, telecom, public sector), contracts with customers, cyber insurance, and foreign laws for data subjects abroad (e.g. GDPR).

### 5.1 Information and Communications Network Act (정보통신망법): breach of an information and communications service

- **Who**: information and communications service providers (정보통신서비스 제공자) and certain other operators covered by the Act.
- **What**: a cybersecurity incident (침해사고) affecting the service.
- **When**: report to the Ministry of Science and ICT or KISA **within 24 hours of becoming aware** of the incident (initial report), and report anything learned later **within 24 hours of confirming it** (supplementary report). The 24-hour rule came into force on 14 August 2024, and the initial report must not be delayed while the cause is still being investigated.
- **Content**: the date and time of occurrence, the cause, the damage, and the response so far.
- **2026 amendment**: confirms the 24-hour reporting window, adds a duty to notify users without delay for incidents specified by Presidential Decree, and makes an incident management and response manual mandatory. Check the effective date and the enforcement decree for your organization.

### 5.2 Personal Information Protection Act (개인정보 보호법): personal data breach

| Duty | Trigger | Deadline | Recipient |
| --- | --- | --- | --- |
| **Report to the authority** | (a) personal information of **1,000 or more** data subjects leaked, **or** (b) **sensitive or unique identifying information** leaked, **or** (c) any leakage caused by **unlawful external access** to a personal information processing system or to devices used to process personal information | **Within 72 hours** of becoming aware | PIPC (개인정보보호위원회) or KISA |
| **Notify data subjects** | Any confirmed leakage of their personal information | **Within 72 hours** of becoming aware | Each affected data subject, individually. If contact details are unknown, a website notice for at least 30 days |
| **Notify of possible leakage** (since 11 September 2026) | Leakage not yet confirmed, but its *possibility* is recognized: e.g. unlawful access to a processing system detected, or company member data seen being traded | **Within 72 hours** | All potentially affected data subjects. A follow-up notice is required once confirmed, or once ruled out |

If the details are not yet known, **report what you know first** and add details as they're confirmed. Don't miss the deadline waiting for a complete picture.

Required report and notice content includes the personal data items involved, when and how the leak happened, the steps taken to minimize harm, what data subjects can do themselves, how to get redress, and a contact point.

### 5.3 Decision tree

```text
Incident declared ── record "time of awareness" (T0)
   │
   ├─ Is it an incident affecting an information and communications service?
   │      └─ yes → Network Act initial report by T0 + 24h, supplementary reports within 24h of new facts
   │
   ├─ Personal information involved (confirmed OR possible)?
   │      ├─ possible, not confirmed → possible-leakage notice to subjects by T0 + 72h
   │      ├─ confirmed → notify subjects by T0 + 72h
   │      └─ ≥1,000 subjects OR sensitive/unique-ID data OR unlawful external access
   │             → report to PIPC/KISA by T0 + 72h
   │
   ├─ Credit information, finance, telecom, public sector, or overseas subjects?
   │      └─ yes → Legal checks sector-specific and foreign obligations
   │
   └─ Contractual notice to customers or partners? Cyber insurance notice?
          └─ Legal checks contract and policy deadlines
```

The IC makes sure Legal / the CPO is engaged **at declaration** of any S1 or S2 incident, or any incident where personal information could be involved. The CPO owns the reporting decision and its timing.

---

## 6. Evidence and documentation

- **Incident log**: kept by the Scribe in real time. Timestamp (UTC and local), who, what, and the outcome. Record decisions with their rationale.
- **Evidence**: collected and handled according to [evidence-handling.md](../forensics/evidence-handling.md), with hashes and chain of custody.
- **Log preservation**: on declaration, extend retention or export logs for the incident window (SIEM, EDR, firewall, proxy, VPN, cloud audit, email). Some sources roll over within days.
- **Report**: written using the [incident report template](../soc-operations/incident-report-template.md). Every timeline entry is backed by a log an analyst actually pulled.
- **Retention**: keep incident records for `<n>` years, or longer if legal hold applies.

---

## 7. Preparation and readiness

| Item | Standard |
| --- | --- |
| Contact sheet (Appendix A) | Verified every quarter |
| Out-of-band communication channel | Set up and tested every 6 months |
| EDR coverage and log sources | Measured every month (see [EDR guide](../edr/README.md)) |
| Offline or immutable backups | Restore tested every quarter |
| Forensic toolkit (collection scripts, write blockers, storage) | Ready and version-checked |
| External IR retainer | Contract active, hotline tested |
| Tabletop exercise | Every 6 months, alternating scenarios (ransomware, data breach, cloud compromise, insider) |
| Technical exercise (purple team) | Every year |
| Manual review | Every year, and after every S1 or S2 incident |

---

## Appendix A: contact sheet

| Role | Name | Phone | Backup channel |
| --- | --- | --- | --- |
| Incident Commander | | | |
| Technical Lead | | | |
| CISO | | | |
| CPO / Legal | | | |
| Communications | | | |
| IT infrastructure on-call | | | |
| Cloud / SaaS admin on-call | | | |
| External IR retainer | | | |
| Cyber insurance | | | |
| KISA incident reporting | Phone 118 / official reporting portal | | |
| Police cyber bureau | Phone 182 / ECRM | | |

## Appendix B: first-hour checklist

- [ ] Incident declared, severity set, IC assigned, **time of awareness (T0) recorded**
- [ ] Incident channel opened, Scribe assigned
- [ ] Legal / CPO engaged if S1–S2 or if personal data is possibly involved
- [ ] Log retention extended for the affected sources
- [ ] Volatile evidence collected from key hosts before containment, where safe
- [ ] Containment decision made and recorded (immediate vs. monitored)
- [ ] Backups confirmed safe and isolated (ransomware or destructive scenarios)
- [ ] First executive update sent with the time of the next update
- [ ] Regulatory clocks noted: Network Act T0 + 24h, PIPA T0 + 72h
