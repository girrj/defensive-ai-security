# Certificate and device identity theft (인증서·장비 식별정보 탈취)

## Definition (정의)

Certificate and device identity theft (인증서·장비 식별정보 탈취) allows an unapproved device to appear trusted when keys are copied or shared.

## Why it matters

Shared fleet credentials defeat per-device revocation and make source attribution difficult.

## How to do it / what to check

Issue unique hardware-protected identities, monitor certificate use across devices and networks, shorten validity, and revoke copied or retired certificates.

## In this repository

[hunting.md](../../threat-intel/korea-incidents/hunting.md) provides a related defensive procedure or detection.

## Seen in (Korean cases)

[Case 02](../../threat-intel/korea-incidents/cases/02-kt-femtocell-and-servers.md), [Case 04](../../threat-intel/korea-incidents/cases/04-onnara-gpki.md)

## References

- [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html)
