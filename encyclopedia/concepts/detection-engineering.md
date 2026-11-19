# Detection engineering (탐지 엔지니어링)

## Definition (정의)

Detection engineering (탐지 엔지니어링) turns a threat behavior into tested logic, data requirements and a response path.

## Why it matters

A rule that parses but lacks telemetry, benign tests or ownership gives false confidence.

## How to do it / what to check

State the hypothesis and required fields, test positive and benign examples, validate the parser and backend, tune with reviewed cases, and retire rules when they no longer apply.

## In this repository

[detection-engineering-lifecycle.md](../../soc-operations/detection-engineering-lifecycle.md) is the related procedure or implementation.

## Seen in (Korean cases)

[Case 01](../../threat-intel/korea-incidents/cases/01-skt-usim-bpfdoor.md), [Case 07](../../threat-intel/korea-incidents/cases/07-lotte-card-weblogic.md)

## References

- [Sigma rule specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md)
