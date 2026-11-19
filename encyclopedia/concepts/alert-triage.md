# Alert triage (경보 분류·초동 분석)

## Definition (정의)

Alert triage (경보 분류) is the first evidence-based decision about an alert: credible threat, authorized activity or insufficient data.

## Why it matters

A closed alert without scope or owner can leave an active attacker uninvestigated.

## How to do it / what to check

Read the raw event, validate asset and identity, inspect related events and record confidence, severity, owner and next action. Escalate blocked exfiltration and repeated authentication failures.

## In this repository

[alert-triage-standard.md](../../soc-operations/alert-triage-standard.md) is the related procedure or implementation.

## Seen in (Korean cases)

[Case 08](../../threat-intel/korea-incidents/cases/08-gs-retail-credential-stuffing.md), [Case 12](../../threat-intel/korea-incidents/cases/12-tving-access-key.md)

## References

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
