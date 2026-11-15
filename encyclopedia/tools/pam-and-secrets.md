# PAM and secrets management (특권 접근·비밀값 관리)

## Definition (정의)

PAM and secrets management (특권 접근·비밀값 관리) limits, brokers and audits high-privilege access and keys.

## Why it matters

Shared or long-lived secrets allow misuse and make attribution difficult after an account or device is compromised.

## How to do it / what to check

Use individual identities, least privilege, short-lived checkout, rotation and revocation; alert on unusual vault export and access from new devices.

## In this repository

[hunting.md](../../threat-intel/korea-incidents/hunting.md) provides a related guide, rule or workflow.

## Seen in (Korean cases)

[Case 02](../../threat-intel/korea-incidents/cases/02-kt-femtocell-and-servers.md), [Case 03](../../threat-intel/korea-incidents/cases/03-lgu-appm-leak.md), [Case 09](../../threat-intel/korea-incidents/cases/09-coupang-signing-key.md), [Case 12](../../threat-intel/korea-incidents/cases/12-tving-access-key.md)

## References

- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
