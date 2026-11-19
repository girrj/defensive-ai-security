# Hardcoded secrets and key misuse (하드코딩 비밀값·키 오용)

## Definition (정의)

Secret and key misuse (비밀값·키 오용) includes plaintext keys in source, retained signing keys and excessive privileges.

## Why it matters

One stolen or unrotated key can give access far beyond the account that originally held it.

## How to do it / what to check

Scan source and CI artifacts, use a vault/KMS, separate duties, set expiry, rotate on exposure or offboarding, and monitor key use from new sources.

## In this repository

[check-public.sh](../../tools/check-public.sh) provides a related defensive procedure or detection.

## Seen in (Korean cases)

[Case 09](../../threat-intel/korea-incidents/cases/09-coupang-signing-key.md), [Case 12](../../threat-intel/korea-incidents/cases/12-tving-access-key.md)

## References

- [NIST SP 800-57 Part 1](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
