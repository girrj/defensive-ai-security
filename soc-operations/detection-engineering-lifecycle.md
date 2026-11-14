# Detection engineering lifecycle

Every rule in `detections/` follows this lifecycle. The aim is that every production rule has a stated purpose, a known false-positive profile, an owner, and a test.

```text
 Requirement ──► Research ──► Build ──► Test ──► Deploy (experimental) ──► Tune ──► Stable ──► Review / retire
      ▲                                                                                     │
      └──────────────────────────── gaps found in incidents, hunts, threat intel ◄─────────┘
```

## 1. Requirement

A detection starts from one of these:

- **A threat intelligence report** about a technique being used against our sector
- **An incident or hunt finding**: what we missed, or caught late
- **An ATT&CK coverage gap** for a high-priority technique
- **An emergency vulnerability** (see [zero-day-response](../playbooks/zero-day-response.md))

Write it as: *"Detect <behavior> on <asset scope> using <log source>, so that <response action>."*

## 2. Research

- Which log source records this behavior, and is it actually collected and parsed everywhere it needs to be?
- What does the benign version of this behavior look like in our environment? Run the draft logic as a hunt over 30 days before turning it into an alert.
- Does a community rule (SigmaHQ, vendor content) already cover it? Adapting one is better than writing from scratch.

## 3. Build: rule standards

| Field | Requirement |
| --- | --- |
| Title | Describes the behavior, not the tool ("LSASS memory dump via comsvcs", not "Mimikatz") |
| Description | What it detects, why it matters, and how an attacker would use it |
| ATT&CK tags | At least one technique |
| False positives | Specific known benign causes, never just "unknown" |
| Level | Set from the expected precision, using the severity matrix in the triage standard |
| Status | `experimental` until it has passed the tuning stage |

Prefer behavior over indicators. A hash rule lasts until the next recompile, while a process-relationship rule lasts until the technique changes.

## 4. Test

- **Positive test:** reproduce the behavior in a lab, or replay recorded attack telemetry. The rule must fire.
- **Negative test:** run the rule over 7–30 days of production data. Record the number of alerts per day and the share that are false positives.
- **Syntax:** CI validates every Sigma rule and compiles every YARA rule on each push.

## 5. Deploy and tune

- Deploy as `experimental` at reduced severity. Review every hit for two weeks.
- Each tuning change gets a reason in the commit message. Exclusions must be as narrow as possible: full command line plus host, never just a process name.
- Promote to `stable` when the false-positive rate is acceptable and at least one true positive or lab positive is documented.

## 6. Measure

| Metric | Why |
| --- | --- |
| Alerts per rule per day | Finds noisy rules that are wearing out analysts |
| True-positive rate per rule | Finds rules that never find anything |
| Time from technique disclosure to deployed detection | Measures engineering agility |
| ATT&CK coverage, weighted by threat relevance | Shows where the gaps are |
| Mean time to detect, from incidents | The outcome that actually matters |

## 7. Review and retire

Review each rule every 6 months. Retire it when its log source is gone, it has had no true positives and no reason to expect any, or a better rule covers the same behavior.
