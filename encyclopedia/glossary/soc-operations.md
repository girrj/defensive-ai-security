# Glossary: SOC operations (보안관제)

| Term | 한국어 | Definition | See also |
| --- | --- | --- | --- |
| SOC (Security Operations Center) | 보안관제센터 | The team, process and tooling that monitors an organization's environment around the clock, triages alerts and starts incident response. | SOC operating model (planned) |
| CERT / CSIRT | 침해사고대응팀 | A team that handles confirmed incidents: scoping, containment, eradication, recovery, reporting. Often overlaps with or sits above the SOC. | [IR manual](../../ir-manual/) |
| MSSP / MSS | 보안관제 전문업체 / 관리형 보안 서비스 | A provider that runs monitoring or other security functions for customers under a service agreement. | |
| MDR (Managed Detection and Response) | 관리형 탐지·대응 | An MSS that includes active response (host isolation, account disable), usually built on the provider's EDR. | EDR (planned) |
| Tier 1 / 2 / 3 analyst | 1·2·3차 분석가 | Common SOC staffing split: T1 triages queued alerts, T2 investigates and escalates, T3 hunts, engineers detections and leads incidents. | Concept (planned) |
| Alert | 경보 / 탐지 이벤트 | A notification raised when a detection matches. An alert is a question, not a verdict. | [Triage standard](../../soc-operations/alert-triage-standard.md) |
| Event | 이벤트 | Any recorded occurrence in a system or network. Most events are normal. | |
| Incident | 침해사고 / 보안사고 | An event or series of events that actually or imminently threatens the confidentiality, integrity or availability of systems or data, as defined in the organization's IR policy. | [IR manual §1.2](../../ir-manual/README.md#12-definitions) |
| Triage | 분류·초동 분석 | Deciding quickly whether an alert is a true positive, a false positive or benign, and how urgent it is. | [Triage standard](../../soc-operations/alert-triage-standard.md) |
| True positive / false positive | 정탐 / 오탐 | TP: the alert fired and the behaviour it describes really happened. FP: it fired on something that does not match its intent. | [Detection lifecycle](../../soc-operations/detection-engineering-lifecycle.md) |
| Benign true positive | 정상 행위 정탐 | The behaviour really happened but was authorized, such as an admin's sanctioned PsExec. Usually tuned with an allow-list, not by weakening the rule. | |
| False negative | 미탐 | Malicious activity that no detection caught. Found by hunting, red teaming or incidents. | Threat hunting (planned) |
| Escalation | 에스컬레이션 / 상향 보고 | Handing an alert or incident to a higher tier or to management according to defined criteria. | [IR manual §2](../../ir-manual/README.md#2-severity-and-escalation) |
| Severity / priority | 심각도 / 우선순위 | Severity is the potential impact; priority also weighs asset value, confidence and urgency. | |
| SLA / SLO | 서비스 수준 협약 / 목표 | Agreed response times, for example "critical alerts acknowledged within 15 minutes". | |
| MTTD / MTTR | 평균 탐지 시간 / 평균 대응(복구) 시간 | Mean time to detect, and mean time to respond or recover. Useful trends, easy to game; read alongside quality measures. | |
| Dwell time | 체류 시간 | Time between initial compromise and detection. | [Case 01](../../threat-intel/korea-incidents/cases/01-skt-usim-bpfdoor.md) |
| Use case | 탐지 시나리오 | A documented detection goal: the threat, the data needed, the logic, and the response. | [Detection lifecycle](../../soc-operations/detection-engineering-lifecycle.md) |
| Runbook / playbook | 런북 / 플레이북 | Step-by-step response instructions. A runbook is usually narrower (one alert type); a playbook covers a whole incident type. | [Playbooks](../../playbooks/) |
| Shift handover | 근무 인수인계 | Structured transfer of open cases and context between shifts. | [Template](../../soc-operations/shift-handover-template.md) |
| Alert fatigue | 경보 피로 | Loss of attention caused by high alert volume and low precision. Fixed by tuning and automation, not by hiring alone. | |
| Log source onboarding | 로그 소스 연동 | Bringing a new data source into the SIEM: collection, parsing, normalization, and validating that detections can use it. | Logging and telemetry (planned) |
| Coverage | 탐지 커버리지 | Share of assets sending the needed telemetry, and share of relevant techniques with a working detection. | [EDR coverage](../../edr/README.md) |
| Purple teaming | 퍼플팀 | Red and blue teams working together on specific techniques to test and improve detections. | |
| Tabletop exercise | 모의훈련(토의형) | A discussion-based walk through an incident scenario to test the plan, roles and decisions. | [IR manual §7](../../ir-manual/README.md#7-preparation-and-readiness) |
