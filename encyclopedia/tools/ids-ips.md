# IDS / IPS (침입 탐지·방지)

## Definition (정의)

IDS/IPS (침입 탐지·방지) observes network traffic and raises or blocks matches to detection logic.

## Why it matters

Blocking can interrupt known threats, while blind placement, packet loss or overly broad signatures can miss or disrupt traffic.

## How to do it / what to check

Map sensor coverage, validate protocol parsing, test expected and benign pcaps, monitor dropped packets and review signatures after application changes.

## In this repository

[README.md](../../detections/suricata/README.md) provides a related guide, rule or workflow.

## Seen in (Korean cases)

[Case 01](../../threat-intel/korea-incidents/cases/01-skt-usim-bpfdoor.md), [Case 07](../../threat-intel/korea-incidents/cases/07-lotte-card-weblogic.md), [Case 11](../../threat-intel/korea-incidents/cases/11-korean-air-kcd-oracle-ebs.md)

## References

- [Suricata documentation](https://docs.suricata.io/en/latest/)
