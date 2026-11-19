# SIEM (통합 보안 이벤트 관리)

## Definition (정의)

SIEM (통합 보안 이벤트 관리) collects and searches security events across sources, often normalizing and correlating them.

## Why it matters

Central visibility helps connect identity, endpoint and network evidence; missing ingestion can hide an incident.

## How to do it / what to check

Inventory required sources, validate raw-to-normalized field mapping and timestamps, monitor ingestion gaps, restrict access to sensitive logs and test detection latency.

## In this repository

[splunk-spl.md](../../hunting/splunk-spl.md) provides a related guide, rule or workflow.

## Seen in (Korean cases)

[Case 01](../../threat-intel/korea-incidents/cases/01-skt-usim-bpfdoor.md), [Case 08](../../threat-intel/korea-incidents/cases/08-gs-retail-credential-stuffing.md)

## References

- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
