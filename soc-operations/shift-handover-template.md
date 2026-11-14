# SOC shift handover template

Copy this for each handover. Fill in every section; write "none" rather than leaving one blank.

```markdown
## Shift handover: YYYY-MM-DD HH:MM (outgoing → incoming)

### Open incidents
| ID | Severity | Summary | Current status | Next action | Owner |
|----|----------|---------|----------------|-------------|-------|

### Alerts under investigation (not yet incidents)
| Alert | Host / user | What's been checked | What's left |
|-------|-------------|---------------------|-------------|

### Temporary measures in effect
<!-- Blocks, containments, temporary detections, increased logging. Include an expiry for each. -->
| Measure | Applied to | Reason | Expires / review on |
|---------|------------|--------|---------------------|

### Emergency vulnerabilities in progress
| CVE / advisory | Phase | Exposure count | Blocker |
|----------------|-------|----------------|---------|

### Tooling and log source health
<!-- Collector lag, parser failures, missing log sources, SIEM or EDR outages. -->

### Notes for the incoming shift
<!-- Expected maintenance, approved pentests, VIP travel, anything that changes what "normal" looks like. -->
```
