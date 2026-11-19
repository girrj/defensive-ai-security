# Rule formats: Sigma, YARA, Suricata, YARA-L, SPL, KQL

## Definition (정의)

Sigma (로그), YARA (파일·메모리), Suricata (네트워크), YARA-L (Google SecOps), SPL (Splunk) and KQL (Microsoft) express detections for different data and execution engines.

## Why it matters

A syntactically valid rule may still fail because field mappings, parsers or benign traffic differ.

## How to do it / what to check

Select the format matching the data plane, declare required fields, test positive and benign cases and verify the deployed query or converted rule.

## In this repository

[webshell_child_process_linux.yml](../../detections/sigma/webshell_child_process_linux.yml) provides a local control or procedure.

## Seen in (Korean cases)

[Case 01](../../threat-intel/korea-incidents/cases/01-skt-usim-bpfdoor.md), [Case 07](../../threat-intel/korea-incidents/cases/07-lotte-card-weblogic.md)

## References

- [Sigma specification](https://github.com/SigmaHQ/sigma-specification/)
- [YARA documentation](https://yara.readthedocs.io/en/stable/)
- [Suricata rule documentation](https://docs.suricata.io/en/latest/rules/intro.html)
- [Google YARA-L documentation](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview)
