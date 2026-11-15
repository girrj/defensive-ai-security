# Glossary: detection engineering (탐지 엔지니어링)

| Term | 한국어 | Definition | See also |
| --- | --- | --- | --- |
| Detection-as-code | 코드형 탐지 | Version-controlled detection logic with review, tests and deployment history. | [Detection lifecycle](../../soc-operations/detection-engineering-lifecycle.md) |
| Signature | 시그니처 | A match on a recognizable artifact or pattern; useful for known threats but sensitive to change. | [Rules](../../detections/) |
| Behavioral detection | 행위 기반 탐지 | A rule on an action or sequence, such as a web server spawning a shell, rather than one hash. | [Web-shell rules](../../detections/sigma/webshell_child_process_linux.yml) |
| Anomaly detection | 이상 탐지 | Finding a deviation from an established peer or asset baseline; a deviation needs investigation. | [Hunting](../../hunting/) |
| Correlation rule | 상관분석 룰 | Logic that joins multiple events by identity, asset and time to detect a meaningful sequence. | [Detection lifecycle](../../soc-operations/detection-engineering-lifecycle.md) |
| Baseline | 기준선 | The measured normal range for a defined asset, user or cohort over a stated period. | [NDR guide](../../ndr/README.md) |
| Tuning | 튜닝 | Improving a rule's usefulness by reviewing matches, missed cases and changes in telemetry. | [Detection lifecycle](../../soc-operations/detection-engineering-lifecycle.md) |
| Allow-list / suppression | 예외 처리 | A narrow, documented exception for known authorized activity; it needs an owner and expiry review. | [Detection lifecycle](../../soc-operations/detection-engineering-lifecycle.md) |
| Precision and recall | 정밀도·재현율 | Precision is true detections among alerts; recall is detected threats among all relevant threats. Neither is reliable without labeled examples. | [Detection lifecycle](../../soc-operations/detection-engineering-lifecycle.md) |
| IOC vs IOA | 침해지표·공격지표 | An IOC is an observed artifact such as a hash; an IOA describes suspicious behavior and may survive artifact changes. | [IOC file](../../threat-intel/korea-incidents/iocs/iocs.csv) |
| Pyramid of Pain | 고통의 피라미드 | A model showing that changing hashes is easier for an adversary than changing tools, techniques and procedures. | [Hunting guide](../../threat-intel/korea-incidents/hunting.md) |
| Data normalization: UDM, CIM, ECS, OCSF | 로그 정규화 | Mapping source-specific events to a common schema so searches and correlations work across products; retain the raw event too. | [UDM hunts](../../hunting/google-secops-udm.md) |
| Enrichment | 보강 | Adding asset criticality, identity context or sourced threat intelligence to an event without replacing the raw record. | [IOC format](../../threat-intel/korea-incidents/iocs/README.md) |
| Coverage mapping | 커버리지 매핑 | Recording which threat behaviors have working rules, required telemetry and assets actually reporting. | [EDR coverage](../../edr/README.md) |
| Sigma | 시그마 | A vendor-neutral YAML format for log detection rules, converted for a target backend. | [Sigma rules](../../detections/sigma/) |
| YARA | 야라 | A rule language for matching file or memory content; test benign files as well as known samples. | [YARA rules](../../detections/yara/) |
| Suricata rule | 수리카타 룰 | Network IDS/IPS signature logic over observable traffic and protocol metadata. | [Suricata rules](../../detections/suricata/README.md) |
| YARA-L | 야라-L | Google SecOps language for event-based detection and correlation; it is distinct from file-oriented YARA. | [YARA-L rules](../../detections/yara-l/) |
| SPL | 스플렁크 검색 언어 | Splunk's search pipeline for filtering, transforming and aggregating indexed events. | [SPL hunts](../../hunting/splunk-spl.md) |
| KQL | 쿠스토 쿼리 언어 | Query language used by Microsoft security data services; field and table names vary by product. | [Logging concept](../concepts/logging-and-telemetry.md) |
| Detection testing | 탐지 시험 | Running expected-positive and benign-negative data through a rule, parser and deployment path. | [CI](../../.github/workflows/validate.yml) |
| Rule lifecycle and retirement | 룰 수명주기·폐기 | Review, test, deploy, tune and retire a rule when its threat or data dependency changes. | [Detection lifecycle](../../soc-operations/detection-engineering-lifecycle.md) |

## References

- [Sigma rule specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md)
- [MITRE ATT&CK data sources](https://attack.mitre.org/datasources/)
- [Google SecOps UDM overview](https://cloud.google.com/chronicle/docs/event-processing/udm-overview)
