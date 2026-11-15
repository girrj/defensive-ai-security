# 03. LG Uplus server access-control (APPM) data leak (LG유플러스 APPM 유출), 2025

Data from a carrier's server access-control and password management system (APPM, 통합 서버 접근제어·비밀번호 관리) appeared in a leak published by Phrack. Servers that could have shown how the data left were reinstalled or discarded after the authorities warned the company.

| Field | Value |
| --- | --- |
| Disclosed | Phrack article, August 2025. KISA had notified the company on 19 July 2025. Government findings 29 December 2025 |
| Sector | Telecommunications (통신) |
| Impact | Server lists, server account information and employee and contractor names from APPM. Press reports cited about 8,938 servers, 42,526 accounts and 167 people |
| Initial access | Unknown. A tip claimed the APPM vendor was breached first; the network path could not be examined |
| Related CVEs | None named |
| Attribution | The Phrack authors attributed the wider dump to Kimsuky. Not confirmed by the government |
| Public IOCs | None |

## What happened

1. A dump published with the Phrack article contained text files that matched data held in the company's APPM.
2. KISA shared the indicators with the company on 19 July 2025 and advised it to report.
3. The operating systems of the APPM servers were **reinstalled on 12 and 14 August**, and one server was **discarded on 25 August**, before investigators started. The company reported the breach formally on 23 October 2025.
4. Forensics on the remaining APPM server did not match the leaked data. Servers on the path from a vendor laptop to APPM had been reinstalled or discarded, so the entry path could not be traced.
5. The Ministry of Science and ICT referred the case to the police for obstruction of official duties by deception. The privacy regulator (PIPC) also suspended its own investigation in July 2026 and referred the case to investigators.

## Why it matters

APPM-type systems (PAM, privileged access management) hold the keys to every other server. Losing one gives an attacker a map of the network and, often, working credentials. The case is also the clearest Korean example of **evidence destroyed before the investigation**, which ended any chance of establishing root cause.

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |
| Initial Access | T1199 Trusted Relationship | Alleged entry through the APPM vendor (unconfirmed) |
| Credential Access | T1555 Credentials from Password Stores | Account data from the password management system |
| Discovery | T1087 Account Discovery, T1018 Remote System Discovery | Server and account lists |
| Exfiltration | T1041 / T1567 (method unknown) | Data later published |

## Detect it with this repo

| Layer | Detection |
| --- | --- |
| Hunting | PAM and password vault access anomalies (to be added) |
| Forensics | [Evidence handling and preservation](../../../forensics/evidence-handling.md) |
| IR manual | [Legal and regulatory reporting](../../../ir-manual/README.md#5-legal-and-regulatory-reporting-korea) |

## Lessons for SOC and CERT

- **Preserve before you rebuild.** Take disk and memory images, export logs and record hashes before any OS reinstall. Rebuild a *copy*, not the evidence.
- **A third-party notification starts the clock.** Treat a KISA or regulator notice as the moment of awareness for reporting purposes, and start preservation immediately.
- **Monitor the PAM itself.** Bulk exports, new admin sessions, access from vendor networks and configuration changes in the vault are high-value alerts.
- **Vendor access paths are part of your attack surface.** Inventory them and log every hop.

## Sources

- [Boan News: findings on KT and LG Uplus, police referral](https://m.boannews.com/html/detail.html?idx=141219)
- [Byline Network: OS reinstall on 12 and 14 Aug, server discarded 25 Aug](https://byline.network/2026/07/30-590/)
- [Newsis: PIPC suspends its investigation and refers the case](https://www.newsis.com/view/NISX20260730_0003729305)
- [Hankyung: suspected scope (servers, accounts, staff)](https://www.hankyung.com/article/2025121947137)
- [SBS Biz: company's investment-risk disclosure](https://biz.sbs.co.kr/amp/article/20000286490)
