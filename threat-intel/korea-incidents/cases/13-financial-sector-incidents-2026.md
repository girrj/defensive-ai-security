# 13. Financial-sector incident reports (2026년 금융권 침해사고), 2026

Korean financial regulators reported a series of incidents across several financial sectors. Their public releases support a sector-wide response, but do **not** establish one common actor or one common intrusion path. This is an aggregate case, not a finding that every listed firm suffered the same attack.

| Field | Value |
| --- | --- |
| Detected / disclosed | First incident cited by the Financial Services Commission (FSC): 30 September 2026; FSC updates on 2 October, 14 October and 5 November 2026 |
| Sector | Finance (금융): banking, securities, insurance, savings banks, electronic finance, online lending, virtual assets and other sectors |
| Impact | As of **3 November 2026**, the FSC reported **40 incident reports from 37 firms** and approximately **473,000 exposed records**. The scope was provisional; account passwords or other information enabling direct unauthorized payments had not been confirmed exposed in that release. These are aggregate figures, not a per-firm count |
| Initial access | Not established for the series in the cited FSC releases; external exposure and weak authentication/access control were subjects of sector-wide checks, not confirmed causes for every case |
| Related CVEs | None confirmed for this aggregate case |
| Attribution | Common actor and possible AI-assisted activity remained under investigation in the cited releases |
| Public IOCs | No stable, public IOC values in the cited releases; regulators shared indicators with affected institutions |

## Timeline

| Date | Event |
| --- | --- |
| 30 September 2026 | FSC later identified a Shinhan Bank information exposure as the first incident in this series |
| 2 October 2026 | FSC convened an emergency meeting and urged inventory of externally reachable services, authentication checks and sector-wide threat sharing |
| 14 October 2026 | FSC reported 16 affected firms and approximately 100,000 exposed records at that point; the cause and common actor were still being examined |
| 5 November 2026 | FSC published the updated count for 3 November: 37 firms, 40 reports and about 473,000 exposed records |

## What happened

The FSC described incidents across multiple types of financial firm and coordinated on-site examination, indicator sharing and customer protection. It asked firms to identify *all* externally accessible systems, including non-customer services; check whether personal information could be reached without sufficient authentication; and correct exposure and access-control gaps. The public releases do not provide enough evidence to assign one exploitation technique to every report.

## Root causes (근본 원인)

**Not yet determined for the aggregate series.** The FSC called for checks of internet-facing assets, authentication, authorization and unnecessary information exposure. Treat those as investigation and prevention priorities rather than proven root causes for each organization.

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |
| Not assigned | Not assigned | Public aggregate releases do not establish a consistent technique across the reports. Map individual incidents only after their evidence is published. |

## IOCs

No IOC was added to [`../iocs/iocs.csv`](../iocs/iocs.csv): the cited official releases say indicators were shared with institutions but do not publish values suitable for a public IOC row.

## Detect it with this repo

| Layer | Detection |
| --- | --- |
| Asset exposure | [Vulnerability triage](../../../vuln-triage/README.md) and the [zero-day response playbook](../../../playbooks/zero-day-response.md) support an inventory-led review of reachable services |
| Authentication | [Alert triage standard](../../../soc-operations/alert-triage-standard.md) helps escalate unusual login and access-control findings |
| Web and endpoint | [WAF rules](../../../detections/waf/README.md), [Suricata rules](../../../detections/suricata/README.md) and [EDR guidance](../../../edr/README.md) provide telemetry and control examples; none is a confirmed signature for this series |
| Response | [IR manual](../../../ir-manual/README.md) covers scoping, evidence preservation and applicable notification decisions |

## Lessons for SOC and CERT

- Inventory every externally reachable service, including supporting and partner-facing systems, and validate authentication and authorization on data retrieval paths.
- Preserve raw access, identity and application logs across the investigation window; record gaps rather than inferring that no data was accessed.
- Share validated indicators with the sector response channel and keep their scope and source attached. Do not label an IP match as proof of a common actor.
- Reassess counts and notification duties as investigation findings change. The 3 November numbers are a dated snapshot.

## Sources

- [FSC emergency response meeting, 2 October 2026](https://www.fsc.go.kr/no010101/87869)
- [FSC second emergency response meeting, 14 October 2026](https://www.fsc.go.kr/po010101/87927)
- [FSC financial-sector security response, 5 November 2026](https://www.fsc.go.kr/no010101/88086)
