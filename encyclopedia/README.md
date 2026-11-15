# Blue Team, SOC and CERT Encyclopedia (블루팀·보안관제·침해대응 백과사전)

A reference for people who run security operations. Entries are in English with the Korean term in brackets. Each entry links to the rules, playbooks, procedures and incident cases in this repository that put it into practice.

**Status:** all listed entries are written. ✅ = written.

## Entry format

Glossary pages are tables: term, Korean term, one- or two-sentence definition, see also. Longer entries use these sections in order: Definition (정의) · Why it matters · How to do it / what to check · In this repository · Seen in (Korean cases) · References.

Keep entries defensive, cite primary sources, and paraphrase.

---

## 1. Glossary (용어집) — `glossary/`

| # | Page | Area | Status |
| --- | --- | --- | :---: |
| 1.1 | [`soc-operations.md`](glossary/soc-operations.md) | SOC operations (보안관제) | ✅ |
| 1.2 | [`detection.md`](glossary/detection.md) | Detection engineering (탐지 엔지니어링) | ✅ |
| 1.3 | [`incident-response.md`](glossary/incident-response.md) | Incident response and forensics (침해사고 대응·포렌식) | ✅ |
| 1.4 | [`threat-intel.md`](glossary/threat-intel.md) | Threat intelligence (위협 인텔리전스) | ✅ |
| 1.5 | [`vulnerability.md`](glossary/vulnerability.md) | Vulnerability management (취약점 관리) | ✅ |
| 1.6 | [`ai-security.md`](glossary/ai-security.md) | AI system security (AI 시스템 보안) | ✅ |
| 1.7 | [`korea.md`](glossary/korea.md) | Korean regulation and institutions (국내 법·제도·기관) | ✅ |

### Terms to cover per page

**1.2 Detection engineering**
Detection-as-code (코드형 탐지) · Signature (시그니처) · Behavioral detection (행위 기반 탐지) · Anomaly detection (이상 탐지) · Correlation rule (상관분석 룰) · Baseline (기준선) · Tuning (튜닝) · Allow-list / suppression (예외 처리) · Precision and recall (정밀도·재현율) · IOC vs IOA (침해지표·공격지표) · Pyramid of Pain · Data normalization: UDM, CIM, ECS, OCSF (로그 정규화) · Enrichment (보강) · Coverage mapping (커버리지 매핑) · Sigma · YARA · Suricata rule · YARA-L · SPL · KQL · Detection testing (탐지 시험) · Rule lifecycle and retirement (룰 수명주기)

**1.3 Incident response and forensics**
Preparation / detection / containment / eradication / recovery / lessons learned (대응 단계) · Scoping (범위 산정) · Root cause analysis (근본 원인 분석) · Chain of custody (증거 관리 연속성) · Order of volatility (휘발성 순서) · Live response (활성 시스템 수집) · Disk image (디스크 이미지) · Memory image (메모리 덤프) · Hash verification (해시 검증) · Timeline analysis (타임라인 분석) · Windows artifacts: EVTX, Prefetch, Amcache, ShimCache, SRUM, $MFT, USN Journal, Registry hives · Linux artifacts: auth/secure logs, journald, shell history, cron, systemd units, /proc · Triage collection (초동 수집) · Evidence preservation order (증거 보전) · Breach notification (유출 통지) · Post-incident review (사후 검토)

**1.4 Threat intelligence**
Strategic / operational / tactical / technical intelligence (CTI 수준) · Intelligence requirements (정보 요구사항) · IOC (침해지표) · TTP (전술·기법·절차) · Threat actor (위협 행위자) · APT (지능형 지속 위협) · Campaign (캠페인) · Attribution (공격 주체 판단) · Confidence levels (신뢰도) · Indicator decay (지표 노후화) · Defanging (무력화 표기) · Diamond Model · Cyber Kill Chain · STIX / TAXII · TLP (정보 공유 등급) · MISP · OpenCTI · ISAC (정보공유분석센터)

**1.5 Vulnerability management**
CVE · CWE · CVSS v4 · EPSS · CISA KEV · SSVC · Zero-day (제로데이) · N-day (엔데이) · Patch SLA (패치 기한) · Virtual patching (가상 패치) · Compensating control (보완 통제) · Attack surface management (공격 표면 관리) · Asset inventory / CMDB (자산 목록) · SBOM (소프트웨어 자재명세서) · VEX · Coordinated disclosure (협조적 공개) · End-of-life software (지원 종료 SW)

**1.6 AI system security**
Prompt injection, direct and indirect (프롬프트 인젝션) · Jailbreak (탈옥) · System prompt leakage (시스템 프롬프트 노출) · Excessive agency (과도한 권한 위임) · Tool / function calling (도구 호출) · AI agent (AI 에이전트) · MCP (Model Context Protocol) · RAG (검색 증강 생성) · Vector and embedding weaknesses (벡터·임베딩 취약점) · Model supply chain (모델 공급망) · Pickle vs safetensors · Data and model poisoning (데이터·모델 오염) · Unbounded consumption (무제한 자원 소비) · Guardrails (가드레일) · AI red teaming (AI 레드팀) · Human-in-the-loop approval (사람 승인) · OWASP LLM Top 10 2026 · OWASP Agentic Top 10 2026 · MITRE ATLAS

**1.7 Korean regulation and institutions**
정보통신망법 침해사고 신고 · 개인정보 보호법 유출 신고·통지 · 신용정보법 · 전자금융거래법 · ISMS-P · 망분리 (network separation) · GPKI / 행정전자서명 · KISA (한국인터넷진흥원) · KrCERT/CC · C-TAS · 개인정보보호위원회 (PIPC) · 과학기술정보통신부 (MSIT) · 금융위원회 · 금융감독원 · 금융보안원 (FSI) · 국가정보원 국가사이버안보센터 (NCSC) · 경찰청 사이버수사국 · 민관합동조사단

---

## 2. Concepts (개념) — `concepts/`

| # | File | Entry | Status |
| --- | --- | --- | :---: |
| 2.1 | [`soc-operating-model.md`](concepts/soc-operating-model.md) | SOC operating model: tiers, shifts, metrics (보안관제 운영 모델) | ✅ |
| 2.2 | [`alert-triage.md`](concepts/alert-triage.md) | Alert triage (경보 분류·초동 분석) | ✅ |
| 2.3 | [`detection-engineering.md`](concepts/detection-engineering.md) | Detection engineering (탐지 엔지니어링) | ✅ |
| 2.4 | [`threat-hunting.md`](concepts/threat-hunting.md) | Threat hunting (위협 헌팅) | ✅ |
| 2.5 | [`incident-response-lifecycle.md`](concepts/incident-response-lifecycle.md) | Incident response lifecycle (침해사고 대응 절차) | ✅ |
| 2.6 | [`digital-forensics-and-evidence.md`](concepts/digital-forensics-and-evidence.md) | Digital forensics and evidence handling (디지털 포렌식·증거 처리) | ✅ |
| 2.7 | [`logging-and-telemetry.md`](concepts/logging-and-telemetry.md) | Logging and telemetry: what to collect, how long (로그·텔레메트리) | ✅ |
| 2.8 | [`vulnerability-management.md`](concepts/vulnerability-management.md) | Vulnerability management and zero-day response (취약점 관리·제로데이 대응) | ✅ |
| 2.9 | [`threat-intelligence-program.md`](concepts/threat-intelligence-program.md) | Running a threat intelligence program (위협 인텔리전스 운영) | ✅ |
| 2.10 | [`security-for-ai-systems.md`](concepts/security-for-ai-systems.md) | Securing AI systems in operation (AI 시스템 운영 보안) | ✅ |
| 2.11 | [`crisis-communication.md`](concepts/crisis-communication.md) | Crisis communication and regulator reporting (위기 소통·신고) | ✅ |
| 2.12 | [`soc-automation.md`](concepts/soc-automation.md) | SOC automation and AI-assisted analysis (관제 자동화·AI 활용) | ✅ |

## 3. Frameworks and standards (프레임워크·표준) — `frameworks/`

| # | File | Entry | Status |
| --- | --- | --- | :---: |
| 3.1 | [`mitre-attack.md`](frameworks/mitre-attack.md) | MITRE ATT&CK | ✅ |
| 3.2 | [`mitre-atlas.md`](frameworks/mitre-atlas.md) | MITRE ATLAS | ✅ |
| 3.3 | [`mitre-d3fend.md`](frameworks/mitre-d3fend.md) | MITRE D3FEND | ✅ |
| 3.4 | [`nist-sp-800-61r3.md`](frameworks/nist-sp-800-61r3.md) | NIST SP 800-61 Rev. 3 | ✅ |
| 3.5 | [`nist-csf-2.md`](frameworks/nist-csf-2.md) | NIST Cybersecurity Framework 2.0 | ✅ |
| 3.6 | [`owasp-llm-top-10-2026.md`](frameworks/owasp-llm-top-10-2026.md) | OWASP Top 10 for LLM Applications 2026 | ✅ |
| 3.7 | [`owasp-agentic-top-10-2026.md`](frameworks/owasp-agentic-top-10-2026.md) | OWASP Top 10 for Agentic Applications 2026 | ✅ |
| 3.8 | [`kill-chain-and-pyramid-of-pain.md`](frameworks/kill-chain-and-pyramid-of-pain.md) | Cyber Kill Chain, Diamond Model, Pyramid of Pain | ✅ |
| 3.9 | [`cvss-epss-kev-ssvc.md`](frameworks/cvss-epss-kev-ssvc.md) | Vulnerability scoring and prioritization | ✅ |
| 3.10 | [`stix-taxii-tlp.md`](frameworks/stix-taxii-tlp.md) | Threat-intel sharing standards | ✅ |
| 3.11 | [`detection-rule-formats.md`](frameworks/detection-rule-formats.md) | Rule formats: Sigma, YARA, Suricata, YARA-L, SPL, KQL | ✅ |
| 3.12 | [`korean-regulation.md`](frameworks/korean-regulation.md) | Korean breach reporting and security certification (국내 신고·인증 제도) | ✅ |

## 4. Tool categories (도구 분류) — `tools/`

| # | File | Entry | Status |
| --- | --- | --- | :---: |
| 4.1 | [`siem.md`](tools/siem.md) | SIEM (통합 보안 이벤트 관리) | ✅ |
| 4.2 | [`edr.md`](tools/edr.md) | EDR / XDR (엔드포인트 탐지·대응) | ✅ |
| 4.3 | [`ndr.md`](tools/ndr.md) | NDR (네트워크 탐지·대응) | ✅ |
| 4.4 | [`ids-ips.md`](tools/ids-ips.md) | IDS / IPS (침입 탐지·방지) | ✅ |
| 4.5 | [`waf.md`](tools/waf.md) | WAF (웹 방화벽) | ✅ |
| 4.6 | [`soar.md`](tools/soar.md) | SOAR (보안 오케스트레이션·자동 대응) | ✅ |
| 4.7 | [`tip.md`](tools/tip.md) | Threat intelligence platform (위협 인텔리전스 플랫폼) | ✅ |
| 4.8 | [`forensics-toolkit.md`](tools/forensics-toolkit.md) | Forensics and live-response tools (포렌식 도구) | ✅ |
| 4.9 | [`vulnerability-scanner.md`](tools/vulnerability-scanner.md) | Vulnerability scanners and ASM (취약점 스캐너·공격 표면 관리) | ✅ |
| 4.10 | [`pam-and-secrets.md`](tools/pam-and-secrets.md) | PAM and secrets management (특권 접근·비밀값 관리) | ✅ |
| 4.11 | [`email-security.md`](tools/email-security.md) | Email security gateways (메일 보안) | ✅ |
| 4.12 | [`deception.md`](tools/deception.md) | Deception and honeypots (기만 기술·허니팟) | ✅ |
| 4.13 | [`ai-guardrails.md`](tools/ai-guardrails.md) | LLM guardrails and AI security tooling (AI 가드레일) | ✅ |

## 5. Techniques (위협 영역별 방어) — `techniques/`

| # | File | Entry | Korean cases | Status |
| --- | --- | --- | --- | :---: |
| 5.1 | [`web-shell.md`](techniques/web-shell.md) | Web shells (웹셸) | 02, 07 | ✅ |
| 5.2 | [`passive-backdoor.md`](techniques/passive-backdoor.md) | Passive backdoors and magic packets (수동형 백도어) | 01, 02 | ✅ |
| 5.3 | [`edge-device-compromise.md`](techniques/edge-device-compromise.md) | VPN and edge appliance compromise (엣지 장비 침해) | 04, 06 | ✅ |
| 5.4 | [`credential-stuffing.md`](techniques/credential-stuffing.md) | Credential stuffing (크리덴셜 스터핑) | 08 | ✅ |
| 5.5 | [`broken-access-control.md`](techniques/broken-access-control.md) | Broken access control and authorization flaws (접근통제 미흡·인가 결함) | — | ✅ |
| 5.6 | [`secrets-and-key-management.md`](techniques/secrets-and-key-management.md) | Hardcoded secrets and key misuse (하드코딩 비밀값·키 오용) | 09, 12 | ✅ |
| 5.7 | [`ransomware.md`](techniques/ransomware.md) | Ransomware and double extortion (랜섬웨어·이중 갈취) | 05, 06 | ✅ |
| 5.8 | [`supply-chain-and-third-party.md`](techniques/supply-chain-and-third-party.md) | Supply chain and third-party risk (공급망·협력사 위험) | 03, 11 | ✅ |
| 5.9 | [`insider-and-offboarding.md`](techniques/insider-and-offboarding.md) | Insider risk and offboarding (내부자 위험·퇴사자 관리) | 09 | ✅ |
| 5.10 | [`certificate-and-device-identity.md`](techniques/certificate-and-device-identity.md) | Certificate and device identity theft (인증서·장비 식별정보 탈취) | 02, 04 | ✅ |
| 5.11 | [`crypto-hot-wallet-theft.md`](techniques/crypto-hot-wallet-theft.md) | Hot wallet and key custody (핫월렛·키 보관) | 10 | ✅ |
| 5.12 | [`automated-and-ai-assisted-attacks.md`](techniques/automated-and-ai-assisted-attacks.md) | Automated and AI-assisted attack traffic (자동화·AI 활용 공격) | — | ✅ |
| 5.13 | [`prompt-injection.md`](techniques/prompt-injection.md) | Prompt injection against LLM applications (프롬프트 인젝션) | — | ✅ |
| 5.14 | [`mass-exploitation-campaigns.md`](techniques/mass-exploitation-campaigns.md) | Mass exploitation of a new vulnerability (대량 취약점 악용 캠페인) | 11 | ✅ |

---

## 6. Pages outside the encyclopedia

| File | What it should hold | Status |
| --- | --- | :---: |
| [`cases/13-financial-sector-incidents-2026.md`](../threat-intel/korea-incidents/cases/13-financial-sector-incidents-2026.md) | Case 13: 2026 financial-sector incidents (금융권 사례) | ✅ |
| [`attack-patterns.md`](../threat-intel/korea-incidents/attack-patterns.md) | Patterns repeated across the cases, with the control that breaks each | ✅ |
| [`hunting.md`](../threat-intel/korea-incidents/hunting.md) | Splunk SPL and Google SecOps queries, one section per anchor below | ✅ |

`hunting.md` section anchors used by the case files: `bpfdoor` · `rogue-device-registration` · `pam-vault-anomalies` · `vpn-new-source` · `vpn-brute-force` · `ioc-sweep` · `weblogic` · `credential-stuffing` · `token-key-misuse` · `hot-wallet-withdrawals` · `oracle-ebs` · `access-key-and-bulk-read`
