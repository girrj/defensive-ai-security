# VPN and edge appliance compromise (엣지 장비 침해)

## Definition (정의)

VPN and edge appliance compromise (엣지 장비 침해) is unauthorized control of a device that brokers remote or perimeter access.

## Why it matters

An appliance can become both an entry point and a blind spot when its management plane is exposed or logs are not forwarded.

## How to do it / what to check

Inventory firmware and exposed interfaces, disable default accounts, restrict management, enforce MFA, patch, export logs and review new local administrators.

## In this repository

[zero-day-response.md](../../playbooks/zero-day-response.md) provides a related defensive procedure or detection.

## Seen in (Korean cases)

[Case 04](../../threat-intel/korea-incidents/cases/04-onnara-gpki.md), [Case 06](../../threat-intel/korea-incidents/cases/06-sgi-gunra-ransomware.md)

## References

- [CISA/FBI Gunra advisory: edge-device abuse and mitigation](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a)
