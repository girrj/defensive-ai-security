# 05. YES24 ransomware, twice (예스24 랜섬웨어), 2025

The country's largest online bookstore was taken offline by ransomware for five days in June 2025, then hit again in August. The first recovery depended on dealing with the attacker because there was no offsite backup; the second was restored from backup in about seven hours.

| Field | Value |
| --- | --- |
| Dates | 9 June 2025 (about 04:00), 11 August 2025 (about 04:30) |
| Sector | E-commerce, ticketing (전자상거래·예매) |
| Impact | First attack: all services (books, e-books, ticketing) down about 5 days. Second: about 7 hours |
| Initial access | Not published |
| Related CVEs | None published |
| Attribution | Not published |
| Public IOCs | None |

## Timeline

| Date | Event |
| --- | --- |
| 9 Jun 2025, ~04:00 | Ransomware encrypts systems. The first public notice calls it "system maintenance" |
| 10 Jun | Company confirms ransomware |
| 10–11 Jun | KISA analysts visit twice; KISA says the company is not accepting its technical support |
| 11 Jun | PIPC opens a personal-data investigation |
| ~14 Jun | Services restored in stages |
| 11 Aug 2025, ~04:30 | Second ransomware attack. Restored from backup in about 7 hours; KISA starts an on-site investigation |

## Root causes and response problems

- **No offsite backup.** KISA's H1 2025 threat report noted that the offsite backup the government had long recommended was missing, and that service was restored only through negotiation with the attacker. Reports said the backup network had also been encrypted in June.
- **Misleading first communication.** Calling a ransomware outage "maintenance" cost trust and delayed customers' own precautions.
- **Declining outside help** in the first days slowed the investigation.
- **Re-infection within two months** suggests the original access path or persistence was not fully removed.

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |
| Impact | T1486 Data Encrypted for Impact | Service-wide encryption |
| Impact | T1490 Inhibit System Recovery | Backups reachable from the production network were encrypted |
| Persistence | Unknown | Second attack within two months |

## Detect it with this repo

| Layer | Detection |
| --- | --- |
| EDR (Windows) | Sigma [`ransomware_recovery_inhibition`](../../../detections/sigma/ransomware_recovery_inhibition.yml), [`lsass_memory_dump`](../../../detections/sigma/lsass_memory_dump.yml), [`remote_service_install_psexec_style`](../../../detections/sigma/remote_service_install_psexec_style.yml) |
| Playbook | [Ransomware precursor response](../../../playbooks/ransomware-precursor.md) |
| IR manual | [Communication and reporting](../../../ir-manual/README.md) |

## Lessons for SOC and CERT

- **3-2-1-1-0 backups**: at least one copy offline or immutable, and restore tests that are actually run. The second recovery shows how much this changes the outcome.
- **After ransomware, assume persistence.** Rebuild from known-good images, rotate every credential the attacker could have seen, and hunt for the original entry point before declaring recovery.
- **Say "ransomware" when it is ransomware.** Honest early notice is also a legal duty when personal data may be involved (see the [IR manual](../../../ir-manual/README.md#5-legal-and-regulatory-reporting-korea)).
- **Accept the national CERT's support early.** It brings indicators from other victims.

## Sources

- [Byline Network: second infection and 7-hour recovery](https://byline.network/2025/08/12-446/)
- [Nocut News: KISA says it was not allowed to help](https://www.nocutnews.co.kr/news/6353675)
- [Dealsite: KISA H1 2025 report on missing offsite backup](https://dealsite.co.kr/articles/149503)
- [Segye: ransomware since 04:00 on 9 June](https://www.segye.com/newsView/20250611518412)
- [Wikitree: company statement on the 11 August attack](https://www.wikitree.co.kr/articles/1072261)
