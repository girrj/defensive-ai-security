# Insider risk and offboarding (내부자 위험·퇴사자 관리)

## Definition (정의)

Insider and offboarding risk (내부자 위험·퇴사자 관리) includes authorized access used beyond purpose and credentials retained after a role ends.

## Why it matters

A valid token can hide misuse if key ownership and revocation are weak.

## How to do it / what to check

Revoke accounts, sessions, signing keys and repository access on role change; audit privileged exports and unusual data reads; separate investigation facts from attribution.

## In this repository

[hunting.md](../../threat-intel/korea-incidents/hunting.md) provides a related defensive procedure or detection.

## Seen in (Korean cases)

[Case 09](../../threat-intel/korea-incidents/cases/09-coupang-signing-key.md)

## References

- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
