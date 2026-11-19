# Logging and telemetry: what to collect, how long (로그·텔레메트리)

## Definition (정의)

Logging and telemetry (로그·텔레메트리) are recorded observations from identity, endpoint, application, network and cloud control planes.

## Why it matters

A long retention setting is ineffective if an exposed service never sends logs or key fields are missing.

## How to do it / what to check

Inventory log sources and owners, verify time sync and raw-event preservation, test ingestion and parser fields, set retention from investigation and legal needs, and monitor gaps.

## In this repository

[google-secops-udm.md](../../hunting/google-secops-udm.md) is the related procedure or implementation.

## Seen in (Korean cases)

[Case 01](../../threat-intel/korea-incidents/cases/01-skt-usim-bpfdoor.md), [Case 02](../../threat-intel/korea-incidents/cases/02-kt-femtocell-and-servers.md), [Case 08](../../threat-intel/korea-incidents/cases/08-gs-retail-credential-stuffing.md)

## References

- [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final)
