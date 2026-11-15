# Broken access control and authorization flaws (접근통제 미흡·인가 결함)

## Definition (정의)

Broken access control (접근통제 미흡) occurs when a caller can read or change data outside their authorized scope.

## Why it matters

Authentication alone does not enforce object- or function-level authorization.

## How to do it / what to check

Test access on every object and action with different roles and tenants, enforce checks server-side, log denied access, and review data-return paths for excessive exposure.

## In this repository

[mcp-security-checklist.md](../../ai-security/mcp-security-checklist.md) provides a related defensive procedure or detection.

## Seen in (Korean cases)

No direct example is documented in the current Korean case set; apply the control to local risk.

## References

- [OWASP Top 10 Broken Access Control](https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/)
