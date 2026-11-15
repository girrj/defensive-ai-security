# NDR (네트워크 탐지·대응)

## Definition (정의)

NDR (네트워크 탐지·대응) analyzes connection and protocol telemetry for suspicious traffic patterns.

## Why it matters

It can reveal server-to-server activity when host telemetry is sparse, but encrypted traffic and NAT limit attribution.

## How to do it / what to check

Place sensors at relevant paths, retain Zeek or flow metadata, test clock and asset mapping, baseline rare destinations and validate alerts against host logs.

## In this repository

[README.md](../../ndr/README.md) provides a related guide, rule or workflow.

## Seen in (Korean cases)

[Case 01](../../threat-intel/korea-incidents/cases/01-skt-usim-bpfdoor.md), [Case 02](../../threat-intel/korea-incidents/cases/02-kt-femtocell-and-servers.md)

## References

- [Zeek documentation](https://docs.zeek.org/en/current/)
