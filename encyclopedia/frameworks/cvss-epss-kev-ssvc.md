# Vulnerability scoring and prioritization

## Definition (정의)

CVSS v4 (심각도), EPSS (악용 확률), CISA KEV (실제 악용) and SSVC (의사결정 분류) answer different vulnerability questions.

## Why it matters

A high severity score alone does not establish active exploitation or local business impact.

## How to do it / what to check

Check vendor applicability and exposure first; add KEV status, EPSS and mission impact; decide a remediation deadline and verify the fix on every asset.

## In this repository

[README.md](../../vuln-triage/README.md) provides a local control or procedure.

## Seen in (Korean cases)

[Case 07](../../threat-intel/korea-incidents/cases/07-lotte-card-weblogic.md), [Case 11](../../threat-intel/korea-incidents/cases/11-korean-air-kcd-oracle-ebs.md)

## References

- [FIRST CVSS v4.0](https://www.first.org/cvss/v4.0/)
- [FIRST EPSS](https://www.first.org/epss/)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
