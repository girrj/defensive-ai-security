# Threat-intel sharing standards

## Definition (정의)

STIX (위협정보 표현), TAXII (정보 교환) and TLP (공유 등급) support structured threat sharing with handling rules.

## Why it matters

An indicator without provenance, confidence, scope or redistribution rights can cause bad detections or unsafe sharing.

## How to do it / what to check

Record source URL, observed time, indicator scope and TLP marking; validate before import and keep expiration/review dates.

## In this repository

[README.md](../../threat-intel/korea-incidents/iocs/README.md) provides a local control or procedure.

## Seen in (Korean cases)

[Case 06](../../threat-intel/korea-incidents/cases/06-sgi-gunra-ransomware.md), [Case 11](../../threat-intel/korea-incidents/cases/11-korean-air-kcd-oracle-ebs.md)

## References

- [OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [OASIS TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- [FIRST TLP 2.0](https://www.first.org/tlp/)
