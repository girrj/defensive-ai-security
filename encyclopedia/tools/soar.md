# SOAR (보안 오케스트레이션·자동 대응)

## Definition (정의)

SOAR (보안 오케스트레이션·자동 대응) coordinates enrichment, case handling and controlled response actions.

## Why it matters

Automation reduces repetitive work, but a mistaken disable or isolation action can have real impact.

## How to do it / what to check

Start with read-only enrichment, validate input and permission scope, record audit trails and rollback, then gate containment and external communications on approval.

## In this repository

[alert-triage-standard.md](../../soc-operations/alert-triage-standard.md) provides a related guide, rule or workflow.

## Seen in (Korean cases)

[Case 06](../../threat-intel/korea-incidents/cases/06-sgi-gunra-ransomware.md), [Case 12](../../threat-intel/korea-incidents/cases/12-tving-access-key.md)

## References

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
