# Patterns across Korean cases (국내 사례 공통 패턴)

This matrix groups **documented weaknesses and defensive lessons** from [cases 01–13](README.md). A grouping is an analyst synthesis, not a claim that the cases share an actor, exploit or identical sequence. Case 13 remains an aggregate with unresolved causes.

| Repeated pattern | Cases | Control that interrupts it | Evidence to review |
| --- | --- | --- | --- |
| Long-lived or exposed credentials, keys and certificates (장기·노출 인증정보) | [01](cases/01-skt-usim-bpfdoor.md), [02](cases/02-kt-femtocell-and-servers.md), [04](cases/04-onnara-gpki.md), [09](cases/09-coupang-signing-key.md), [12](cases/12-tving-access-key.md) | Inventory and rotate secrets; bind device identities to individual devices; revoke on offboarding; use short-lived credentials and least privilege | Secret scans, key issuance/rotation records, certificate use, source-network changes and unusual data reads |
| Weak authentication at exposed access points (외부 접점 인증 미흡) | [06](cases/06-sgi-gunra-ransomware.md), [08](cases/08-gs-retail-credential-stuffing.md) | Remove default accounts, enforce MFA and rate limits, restrict management access, detect failure-to-success sequences | VPN/appliance logs, account lockouts, MFA results, distinct accounts per source; [hunting guide](hunting.md#vpn-brute-force) |
| Vulnerable or poorly inventoried application paths (미패치·미식별 서비스) | [02](cases/02-kt-femtocell-and-servers.md), [07](cases/07-lotte-card-weblogic.md), [11](cases/11-korean-air-kcd-oracle-ebs.md) | Inventory every internet-facing instance, patch or isolate it, validate WAF coverage and hunt for compromise before declaring closure | Asset-to-patch reconciliation, WAF and application logs, unexpected web-server child processes; [CVE summary](vulnerabilities.md) |
| Limited telemetry or lost evidence (로그·증거 공백) | [01](cases/01-skt-usim-bpfdoor.md), [02](cases/02-kt-femtocell-and-servers.md), [03](cases/03-lgu-appm-leak.md), [07](cases/07-lotte-card-weblogic.md), [08](cases/08-gs-retail-credential-stuffing.md) | Centralize tamper-resistant logs, test retention and preserve images and hashes before rebuilding | Collector coverage, oldest available records, chain of custody, documented gaps; [forensics guide](../../forensics/evidence-handling.md) |
| Response or recovery control did not match impact (대응·복구 통제 부족) | [05](cases/05-yes24-ransomware.md), [06](cases/06-sgi-gunra-ransomware.md), [12](cases/12-tving-access-key.md) | Escalate blocked exfiltration as an incident, maintain isolated restore copies and rehearse on-call authority | Alert and escalation timestamps, backup isolation and restore tests; [IR manual](../../ir-manual/README.md) |

Case-specific evidence should drive each response. For [hot wallets](cases/10-upbit-hot-wallet.md), add independent withdrawal approval and key custody; for [token signing](cases/09-coupang-signing-key.md), validate key inventory and revoke retired keys. See the [hunting queries](hunting.md#hot-wallet-withdrawals) for starting points.

## References

- Each linked case lists its own official or public reporting sources.
- [NIST SP 800-61 Rev. 3: Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
