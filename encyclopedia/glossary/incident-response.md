# Glossary: incident response and forensics (침해사고 대응·포렌식)

| Term | 한국어 | Definition | See also |
| --- | --- | --- | --- |
| Preparation / detection / containment / eradication / recovery / lessons learned | 준비·탐지·확산방지·제거·복구·사후개선 | A practical sequence of response activities; NIST SP 800-61r3 integrates them into ongoing risk management rather than prescribing one linear checklist. | [IR manual](../../ir-manual/README.md) |
| Scoping | 범위 산정 | Determining affected identities, systems, data and time window from evidence, while recording unknowns. | [Incident report](../../soc-operations/incident-report-template.md) |
| Root cause analysis | 근본 원인 분석 | Finding the control failure that allowed an incident, distinguishing evidence from hypothesis. | [IR manual](../../ir-manual/README.md) |
| Chain of custody | 증거 관리 연속성 | A record of who collected, handled, transferred and stored an item, when and how. | [Evidence handling](../../forensics/evidence-handling.md) |
| Order of volatility | 휘발성 순서 | Prioritizing evidence likely to disappear first, while balancing acquisition against service and safety impact. | [Memory guide](../../forensics/memory-forensics.md) |
| Live response | 활성 시스템 수집 | Documented evidence collection from a running system, where each action can alter the state. | [Linux collector](../../forensics/collect/collect_linux.sh) |
| Disk image | 디스크 이미지 | A verified copy of storage used for later analysis while preserving the original. | [Evidence handling](../../forensics/evidence-handling.md) |
| Memory image | 메모리 덤프 | A snapshot of volatile memory that may retain processes, connections and credentials; restrict access. | [Memory guide](../../forensics/memory-forensics.md) |
| Hash verification | 해시 검증 | Comparing cryptographic digests to detect evidence changes during copying and transfer. | [Evidence handling](../../forensics/evidence-handling.md) |
| Timeline analysis | 타임라인 분석 | Combining timestamped records across sources after normalizing clocks and time zones. | [Forensics guide](../../forensics/README.md) |
| EVTX | 윈도우 이벤트 로그 | Windows event-log file format; review event IDs with source and retention context. | [Windows artifacts](../../forensics/windows-artifacts.md) |
| Prefetch | 프리패치 | Windows execution optimization artifact that may indicate a program ran; availability depends on configuration. | [Windows artifacts](../../forensics/windows-artifacts.md) |
| Amcache | 앰캐시 | Windows application compatibility inventory that can help establish file presence and execution context. | [Windows artifacts](../../forensics/windows-artifacts.md) |
| ShimCache | 심캐시 | Windows compatibility cache that can show file-path history but does not by itself prove execution. | [Windows artifacts](../../forensics/windows-artifacts.md) |
| SRUM | 시스템 리소스 사용 모니터 | Windows resource-usage database useful for per-application activity, subject to retention limits. | [Windows artifacts](../../forensics/windows-artifacts.md) |
| $MFT | 마스터 파일 테이블 | NTFS metadata for files and directories, useful for file-system timelines. | [Windows artifacts](../../forensics/windows-artifacts.md) |
| USN Journal | 변경 저널 | NTFS change journal that records many file operations until entries roll over. | [Windows artifacts](../../forensics/windows-artifacts.md) |
| Registry hives | 레지스트리 하이브 | Windows configuration stores that can retain persistence and account context. | [Windows artifacts](../../forensics/windows-artifacts.md) |
| Linux auth/secure logs and journald | 리눅스 인증·저널 로그 | Sources for authentication and service activity; paths and persistence depend on distribution and configuration. | [Linux artifacts](../../forensics/linux-artifacts.md) |
| Shell history, cron, systemd units, /proc | 셸 기록·예약작업·서비스·프로세스 | Complementary Linux artifacts for user activity, persistence and live process state; absence is not proof of no activity. | [Linux artifacts](../../forensics/linux-artifacts.md) |
| Triage collection | 초동 수집 | A focused, documented first collection that preserves high-value volatile and log evidence. | [Collection guides](../../forensics/README.md) |
| Evidence preservation order | 증거 보전 요청 | A directive to retain relevant records and prevent routine deletion or rebuilding until authorized. | [IR manual](../../ir-manual/README.md) |
| Breach notification | 유출 통지 | Notifying affected people or regulators under the law applicable to the entity, incident and awareness date; duties are assessed separately. | [IR manual](../../ir-manual/README.md) |
| Post-incident review | 사후 검토 | A documented review of timeline, decisions, control gaps and corrective-action owners after recovery. | [Incident report](../../soc-operations/incident-report-template.md) |

## References

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST SP 800-86, forensic techniques](https://csrc.nist.gov/pubs/sp/800/86/final)
- [Korean Personal Information Protection Act, Article 34 (effective 2026-09-11)](https://www.law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1029334927)
