# Credential stuffing (크리덴셜 스터핑)

## Definition (정의)

Credential stuffing (크리덴셜 스터핑) uses previously exposed credentials against other services; defenders should detect patterns without assuming one successful login proves compromise.

## Why it matters

Reused passwords and broad automated login attempts can expose many accounts without a software vulnerability.

## How to do it / what to check

Measure distinct users per source and failure-to-success sequences, add rate limits and breached-password checks, and require strong MFA for sensitive actions.

## In this repository

[hunting.md](../../threat-intel/korea-incidents/hunting.md) provides a related defensive procedure or detection.

## Seen in (Korean cases)

[Case 08](../../threat-intel/korea-incidents/cases/08-gs-retail-credential-stuffing.md)

## References

- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
