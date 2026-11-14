# Responsible use

This repository supports **defensive** security work: detecting, investigating, and responding to attacks, and finding and fixing vulnerabilities in systems the defender is responsible for.

## Scope of the work here

- Detection content, hunting queries, playbooks, and tooling for blue teams
- Vulnerability *prioritization* and *response*: which known vulnerabilities to fix first, how to mitigate them, and how to check for compromise
- Guidance on using AI tools safely in SOC and incident response work

This repository does **not** contain and won't accept exploit code, weaponized proofs of concept, malware, credential-theft tooling, or techniques for evading detection that serve no defensive purpose.

## Principles

1. **Authorization.** Testing, scanning, and code analysis are done only on assets the organization owns or has explicit written permission to assess.
2. **Least data.** Investigations collect and share only the data the question needs. Personal data and customer data are minimized and handled under policy and contract.
3. **Coordinated disclosure.** A vulnerability found in third-party software is reported privately to the vendor, or through a national CERT when the vendor can't be reached, and is not published until a fix or an agreed deadline. A 90-day default window is reasonable unless the flaw is actively exploited.
4. **Defensive output only.** Findings become patches, mitigations, detections, and advisories, not attack capability.
5. **Human accountability.** AI tools assist analysis, but people make and own decisions about containment, disclosure, and production changes.
6. **Proportionality.** Response actions (blocking, isolation, account suspension) are limited to what is needed to contain the threat, and are documented.

## Reporting a problem with this repository

See [SECURITY.md](SECURITY.md).
