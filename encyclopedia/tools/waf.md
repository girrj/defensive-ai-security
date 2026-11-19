# WAF (웹 방화벽)

## Definition (정의)

WAF (웹 방화벽) inspects HTTP requests and applies application-layer rules or policies.

## Why it matters

It can provide temporary risk reduction for exposed web services, but does not repair vulnerable code or prove a host is clean.

## How to do it / what to check

Inventory protected routes, test legitimate requests, validate block and audit modes, review bypass and parser gaps, and pair virtual patches with vendor fixes.

## In this repository

[README.md](../../detections/waf/README.md) provides a related guide, rule or workflow.

## Seen in (Korean cases)

[Case 07](../../threat-intel/korea-incidents/cases/07-lotte-card-weblogic.md), [Case 11](../../threat-intel/korea-incidents/cases/11-korean-air-kcd-oracle-ebs.md)

## References

- [OWASP Web Application Firewall](https://owasp.org/www-community/Web_Application_Firewall)
