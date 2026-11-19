# 12. TVING breach through a stolen developer access key (티빙 개발자 접속키 탈취), 2026

An attacker took a developer's access key, found production keys and database credentials stored in plaintext in source code, and copied every account the streaming service held plus 361 internal projects. A 2024 penetration test had already flagged the hardcoded keys.

| Field | Value |
| --- | --- |
| Date | 30–31 May 2026. Government findings 3 September 2026 |
| Sector | Media, OTT streaming (방송·OTT) |
| Impact | 39,540,697 accounts (22.06 million active, 17.37 million dormant or withdrawn, about 0.11 million test), 20 data fields including CI. 361 development projects with source code. About 24 GB moved abroad. Passwords were one-way hashed |
| Initial access | Developer access key (개발자 접속키) stolen |
| Related CVEs | None (secrets management) |
| Attribution | Not published |
| Reporting | Reported about 29 hours after awareness, past the 24-hour window under the Network Act |
| Public IOCs | None |

## Attack chain

1. **Credential access**: a developer's access key for the development and operations environment was stolen.
2. **Discovery**: inside the source repositories the attacker found more access keys and database connection details in plaintext. Keys were also shared widely inside the company.
3. **First exfiltration attempt, 30 May**: a bulk read pushed the database server to 100% CPU, an alert fired, and the job was blocked. The company treated it as a system problem.
4. **Second attempt, next day**: through another route the attacker copied all account data and the projects.

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |
| Initial Access | T1078.004 Valid Accounts: Cloud Accounts | Developer access key |
| Credential Access | T1552.001 Credentials in Files | Keys and DB credentials in source |
| Collection | T1213.003 Code Repositories | 361 projects |
| Collection | T1005 Data from Local System | Account database |
| Exfiltration | T1567 / T1048 | About 24 GB abroad |

## Detect it with this repo

| Layer | Detection |
| --- | --- |
| Secret scanning | `gitleaks` in CI ([workflow](../../../.github/workflows/validate.yml)) and the pre-publication [`check-public.sh`](../../../tools/check-public.sh) |
| Hunting | [Access-key and bulk-read anomalies](../hunting.md#access-key-and-bulk-read) |
| SOC | [Alert triage standard](../../../soc-operations/alert-triage-standard.md): a blocked exfiltration is an incident, not a resolved alert |

## Lessons for SOC and CERT

- **A failed exfiltration means a live attacker.** The 30 May alert was the warning; it should have opened an incident, revoked keys and started a hunt.
- **Fix pentest findings or accept them in writing.** Hardcoded secrets were known for two years.
- **Short-lived, scoped credentials** (workload identity, SSO-issued tokens) instead of long-lived personal keys. Rotate everything a leaked key could reach.
- **Watch database reads by volume**, not only failures.

## Sources

- [Byline Network: developer access key, 2024 pentest finding not fixed](https://byline.network/2026/09/3-454/)
- [Segye: 39.54 million accounts, 24 GB abroad](https://www.segye.com/newsView/20260903516602)
- [Nocut News: 29-hour delay, CPU alert on the first attempt](https://nocutnews.co.kr/news/6572821)
- [Digital Daily Q&A: first and second attack paths](https://m.ddaily.co.kr/page/view/2026090315401333154)
- [Financial News: 20 fields, one-way hashed passwords](https://www.fnnews.com/news/202609031447014787)
