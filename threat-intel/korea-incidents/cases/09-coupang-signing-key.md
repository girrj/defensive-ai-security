# 09. Coupang account data leak through a retained signing key (쿠팡 서명키 악용 유출), 2025

A former employee kept a token-signing key, forged access tokens with it, and read the profile and delivery-address data of about 33.67 million accounts over five months. The key was hardcoded and had never been rotated.

| Field | Value |
| --- | --- |
| Period | Government findings: 14 April – 8 November 2025 (the company first cited 24 June). Disclosed 18–29 November 2025. Joint investigation results 10 February 2026 |
| Sector | E-commerce (전자상거래) |
| Impact | About 33.67 million names and emails from the "edit my information" page; delivery-address lists (including door entry codes in some cases) viewed about 140–150 million times |
| Initial access | Forged tokens signed with a key the insider took when leaving |
| Related CVEs | None (design and key-management failure) |
| Attribution | Former employee (insider) |
| Public IOCs | None |

## What happened

1. The company's access tokens were signed with a key that was **hardcoded in source code** and stored on developer laptops. Changing it was cumbersome, so it was **never rotated**, including after the employee who had it left.
2. Using the key, the former employee issued valid-looking tokens and called internal profile and address APIs through overseas servers.
3. Anomaly detection did not flag the volume of lookups for about five months.
4. Initial reports said 4,500 accounts. Within 11 days the company raised it to 33.7 million.
5. Investigators found that logs were deleted despite a data-preservation order; the government imposed a fine and referred the matter to the police.

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |
| Credential Access | T1552.001 Credentials in Files | Signing key in source and on laptops |
| Credential Access / Defense Evasion | T1606.001 Forge Web Credentials: Web Cookies (tokens) | Forged JWT access tokens |
| Initial Access | T1078 Valid Accounts (insider) | Former employee |
| Collection | T1213 Data from Information Repositories | Bulk API lookups |
| Defense Evasion | T1090 Proxy | Overseas servers |

## Detect it with this repo

| Layer | Detection |
| --- | --- |
| Hunting | [Token-signing key misuse](../hunting.md#token-key-misuse) |
| Secret scanning | `gitleaks` runs on this repo's full history in CI ([workflow](../../../.github/workflows/validate.yml)); do the same on application repos |
| Forensics | [Evidence handling](../../../forensics/evidence-handling.md): preserve logs when ordered, and before |

## Lessons for SOC and CERT

- **Keys belong in a KMS or HSM**, never in code. Sign tokens with keys the application can use but no person can export.
- **Rotate on schedule and on every departure** of someone who had access. If rotation is hard, that is the bug to fix first.
- **Watch the data plane.** One identity reading millions of records is visible in API logs even when authentication looks valid.
- **Offboarding is a security control**: revoke accounts, keys, tokens and VPN access the same day, and audit what the person could reach.

## Sources

- [Boan News: hardcoded signing key could not be rotated](https://m.boannews.com/html/detail.html?idx=142059)
- [Boan News: 33.67 million records, log deletion despite preservation order](https://m.boannews.com/html/detail.html?idx=142046)
- [Newsis: joint investigation, 33.67 million and about 140 million lookups](https://mobile.newsis.com/view/NISX20260210_0003510149)
- [Twig24: 14 April – 8 November window, delivery-list lookups](https://www.twig24.com/news/2026/02/10/20260210500387)
- [Boan News: JWT signing key retained by a former employee](https://m.boannews.com/html/detail.html?idx=140706)
- [Money Today: 4,500 accounts first, then 33.7 million](https://www.mt.co.kr/living/2025/11/30/2025113012513277649)
