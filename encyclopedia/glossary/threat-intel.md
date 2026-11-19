# Glossary: threat intelligence (위협 인텔리전스)

| Term | 한국어 | Definition | See also |
| --- | --- | --- | --- |
| Strategic / operational / tactical / technical intelligence | 전략·운영·전술·기술 정보 | Different decision levels, from long-term risk and campaign planning to procedures and observables. | [Case index](../../threat-intel/korea-incidents/README.md) |
| Intelligence requirements | 정보 요구사항 | Specific questions and decisions that collection and analysis must support. | [Hunting](../../threat-intel/korea-incidents/hunting.md) |
| IOC | 침해지표 | An observable tied to a source and scope, such as a hash, domain or address; validate freshness. | [IOC format](../../threat-intel/korea-incidents/iocs/README.md) |
| TTP | 전술·기법·절차 | The behavior and sequence used in an intrusion, more useful for durable detection than a single hash. | [ATT&CK](https://attack.mitre.org/) |
| Threat actor | 위협 행위자 | A person or group behind activity; naming requires evidence and confidence, not just a tool match. | [Case index](../../threat-intel/korea-incidents/README.md) |
| APT | 지능형 지속 위협 | A label for a sustained, capable campaign; do not infer it from one sophisticated artifact. | [Case index](../../threat-intel/korea-incidents/README.md) |
| Campaign | 캠페인 | Related activity grouped by evidence and analytic confidence across time or victims. | [IOC scope](../../threat-intel/korea-incidents/iocs/README.md) |
| Attribution | 공격 주체 판단 | An evidence-based assessment of who conducted activity, with uncertainty and alternative explanations stated. | [Case template](../../threat-intel/korea-incidents/TEMPLATE.md) |
| Confidence levels | 신뢰도 | Explicit degree of support for an analytic judgment, with source quality and gaps recorded. | [Case template](../../threat-intel/korea-incidents/TEMPLATE.md) |
| Indicator decay | 지표 노후화 | Loss of an IOC's usefulness as infrastructure and files change; review expiry and false positives. | [IOC format](../../threat-intel/korea-incidents/iocs/README.md) |
| Defanging | 무력화 표기 | Rendering an observable non-clickable for safe sharing, while retaining a reversible value for controlled matching. | [IOC file](../../threat-intel/korea-incidents/iocs/iocs.csv) |
| Diamond Model | 다이아몬드 모델 | An analytic model relating adversary, infrastructure, capability and victim in an event. | [Case index](../../threat-intel/korea-incidents/README.md) |
| Cyber Kill Chain | 사이버 킬체인 | A phase model used to organize intrusion observations and defensive opportunities, not a required sequence. | [Patterns](../../threat-intel/korea-incidents/attack-patterns.md) |
| STIX / TAXII | 위협정보 표현·전송 표준 | STIX represents threat-intelligence objects and relationships; TAXII exchanges them between systems. | [IOC format](../../threat-intel/korea-incidents/iocs/README.md) |
| TLP | 정보 공유 등급 | FIRST's Traffic Light Protocol labels sharing boundaries; respect the source's marking. | [IOC format](../../threat-intel/korea-incidents/iocs/README.md) |
| MISP | 위협정보 공유 플랫폼 | A platform for sharing structured threat events and indicators with provenance and distribution controls. | [IOC format](../../threat-intel/korea-incidents/iocs/README.md) |
| OpenCTI | 공개 위협정보 플랫폼 | A platform for modeling threat entities, relationships and sources; imported claims still need validation. | [Case index](../../threat-intel/korea-incidents/README.md) |
| ISAC | 정보공유분석센터 | A sector-specific community for exchanging analyzed threats and defensive actions under agreed rules. | [Case 13](../../threat-intel/korea-incidents/cases/13-financial-sector-incidents-2026.md) |

## References

- [OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) and [TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- [FIRST TLP 2.0](https://www.first.org/tlp/)
- [MITRE ATT&CK](https://attack.mitre.org/)
