# 08. GS Retail credential stuffing (GS리테일 크리덴셜 스터핑), 2024–2025

Attackers replayed leaked ID and password pairs against two retail websites for months and harvested member profiles from the "edit my information" page. The same attack continued on the second site for more than a month after the first site's breach had been found.

| Field | Value |
| --- | --- |
| Period | GS SHOP: 21 June 2024 – 13 February 2025. GS25: 26 December 2024 – 4 January 2025 |
| Sector | Retail, home shopping (유통·홈쇼핑) |
| Impact | GS SHOP 1,581,025 members and GS25 79,128 members: name, sex, date of birth, phone, address, email; some customs IDs |
| Initial access | Credential stuffing (T1110.004) |
| Related CVEs | None |
| Sanctions | PIPC fine of ₩12.836 billion and ₩3 million administrative fine (decided 26 August 2026) |
| Public IOCs | None published |

## What happened

1. The attacker used credential lists from other breaches to log in at scale, from the same IPs, in short bursts.
2. Successful logins were followed by visits to the member-information page, which displayed full profile data.
3. GS25's breach was found in early January 2025. The company widened its log review to one year and then found the GS SHOP breach, which had been running since June 2024.
4. The regulator found no control to detect or block mass login attempts from one IP, and no alert on the spike in login failures.

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |
| Credential Access | T1110.004 Credential Stuffing | Mass logins with reused credentials |
| Initial Access | T1078 Valid Accounts | Successful logins |
| Collection | T1213 Data from Information Repositories | Profile page scraping |

## Detect it with this repo

| Layer | Detection |
| --- | --- |
| Hunting | Credential stuffing: failure rate, accounts per IP, success after failures (to be added) |
| WAF | Bot and scanner signals ([1009107](../../../detections/waf/modsecurity/blue-team-waf.conf)); add rate limits on login endpoints at the WAF or gateway |
| SOC | [Detection engineering lifecycle](../../../soc-operations/detection-engineering-lifecycle.md) for tuning thresholds per site |

## Lessons for SOC and CERT

- **Login telemetry is security telemetry.** Send authentication logs (result, user, IP, user agent) to the SIEM and alert on failure ratio and distinct accounts per IP.
- **When one property is hit, check them all at once.** The same IPs were active on both sites. Share attacker IPs across business units immediately.
- **Step-up on sensitive pages.** Re-authenticate or require MFA before showing full profile data, and mask fields by default.
- **Offer MFA and breached-password checks** at login.

## Sources

- [ZDNet Korea: fine and per-site numbers](https://zdnet.co.kr/view?no=20260831091556)
- [Financial News: no detection of mass logins from the same IP](https://www.fnnews.com/news/202608311153379786)
- [Segye: PIPC decision on 26 August 2026](https://www.segye.com/newsView/20260831507079)
- [Kuki News: log review widened to one year](https://www.kukinews.com/article/view/kuk202503050185)
