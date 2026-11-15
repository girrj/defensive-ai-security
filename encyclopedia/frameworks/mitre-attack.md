# MITRE ATT&CK

## Definition (정의)

MITRE ATT&CK (적대 행위 지식베이스) organizes observed adversary tactics, techniques and data sources across platforms.

## Why it matters

It gives teams a shared language for threat hypotheses and coverage gaps, but a technique label is not proof of attribution.

## How to do it / what to check

Map only behavior supported by case evidence; identify the data source and working detection for each mapping. Recheck live technique names because ATT&CK changes over time.

## In this repository

[webshell_child_process_linux.yml](../../detections/sigma/webshell_child_process_linux.yml) provides a local control or procedure.

## Seen in (Korean cases)

[Case 01](../../threat-intel/korea-incidents/cases/01-skt-usim-bpfdoor.md), [Case 07](../../threat-intel/korea-incidents/cases/07-lotte-card-weblogic.md), [Case 12](../../threat-intel/korea-incidents/cases/12-tving-access-key.md)

## References

- [MITRE ATT&CK Enterprise matrix](https://attack.mitre.org/matrices/enterprise/)
