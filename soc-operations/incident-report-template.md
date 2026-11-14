# Incident report template

```markdown
# Incident report: <short title>

| Field | Value |
|-------|-------|
| Incident ID | |
| Severity | Critical / High / Medium / Low |
| Status | Open / Contained / Eradicated / Closed |
| Detected | YYYY-MM-DD HH:MM (source: rule, report, ...) |
| Contained | YYYY-MM-DD HH:MM |
| Incident lead | |

## 1. Summary
Three to five sentences: what happened, how it was found, impact, current state.

## 2. Timeline
All times in one time zone; state which.
| Time | Event | Source |
|------|-------|--------|

## 3. Root cause
The initial access vector and the weakness that allowed it.

## 4. Scope and impact
- Affected hosts:
- Affected accounts:
- Data accessed or exfiltrated (confirmed / suspected / ruled out):
- Business impact:

## 5. Response actions
| Time | Action | By | Verified how |
|------|--------|----|--------------|

## 6. Indicators
| Type | Value (defanged) | Context |
|------|------------------|---------|

## 7. Corrective actions
| Action | Owner | Due | Status |
|--------|-------|-----|--------|

## 8. Detection improvements
What would have caught this earlier, and the rule or logging change that follows from it.

## Appendix: evidence
Screenshots of the queries an analyst ran and their results, kept next to the timeline entries they support.
```

## Writing guidance

- Separate **confirmed** from **suspected**. Write "no evidence of exfiltration was found in proxy and firewall logs for <period>", not "no data was exfiltrated".
- Every timeline entry must be backed by a log the analyst queried. Inferences go in the root-cause section and are labeled as inferences.
- Defang indicators (`hxxp`, `[.]`) so the report can be emailed safely. `tools/ioc_extract.py --defang` does this.
