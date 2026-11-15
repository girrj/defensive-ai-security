# 07. Lotte Card payment server breach (롯데카드 온라인결제 서버 해킹), 2025

An eight-year-old Oracle WebLogic vulnerability on one forgotten payment server let attackers steal about 200 GB of payment logs. Card numbers, CVCs and resident registration numbers were in those logs in plaintext.

| Field | Value |
| --- | --- |
| Disclosed | Breach found late August 2025. Scope announced 18 September 2025 |
| Sector | Finance, card issuer (금융·카드) |
| Impact | About 2.97 million customers. About 280,000 with card number, expiry, CVC and two PIN digits. About 450,000 resident registration numbers. About 200 GB taken |
| Initial access | CVE-2017-10271 (WebLogic WLS-WSAT XMLDecoder RCE) on an unpatched online-payment server |
| Attribution | Not published |
| Sanctions | PIPC fine of ₩9.62 billion (March 2026). FSC business suspension of 1.5 months and a ₩5 billion fine (July 2026) |
| Public IOCs | None |

## Attack chain

1. **Exploit** CVE-2017-10271 on the WebLogic server behind an overseas easy-payment service. Oracle patched it in October 2017. The company said 1 of 48 servers was missed because that payment route had little traffic.
2. **Persistence and execution** with malicious programs on the server. When antivirus was installed after the incident, it detected and removed malware immediately.
3. **Collection** of online-payment log files that held personal and card data in plaintext (data generated between 22 July and 27 August 2025).
4. **Exfiltration** of about 200 GB.

## Root causes (근본 원인)

- **Patch inventory gap**: one low-traffic server left out of patching for eight years, despite three FSI advisories (2018–2024) and a 2022 FSS inspection finding on vulnerability management.
- **Sensitive data in logs**, unencrypted.
- **No antivirus or EDR on the server.** The CISO had warned management in June 2025 that Linux servers lacked security software, citing the SKT case.

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |
| Initial Access | T1190 Exploit Public-Facing Application | CVE-2017-10271 |
| Execution | T1059.004 Unix Shell | Commands through the XMLDecoder payload |
| Persistence | T1505.003 Web Shell (likely) | Malicious programs on the WAS host |
| Collection | T1005 Data from Local System | Payment log files |
| Exfiltration | T1041 / T1048 | About 200 GB |

## Detect it with this repo

| Layer | Detection |
| --- | --- |
| IDS | Suricata [9100060](../../../detections/suricata/blue-team.rules) (WLS-WSAT XMLDecoder payload, pcap-tested) |
| WAF | [1009130](../../../detections/waf/modsecurity/blue-team-waf.conf) (deny `/wls-wsat/` and `/_async/`), 1009131 (XMLDecoder process payload in any body), both live-tested |
| EDR (Linux) | Sigma [`webshell_child_process_linux`](../../../detections/sigma/webshell_child_process_linux.yml) (Java parent spawning a shell), [`linux_reverse_shell_dev_tcp`](../../../detections/sigma/linux_reverse_shell_dev_tcp.yml) |
| Hunting | WebLogic exploitation (to be added) |
| Vulnerability triage | [`cve_triage.py`](../../../vuln-triage/) shows KEV status and EPSS for CVE-2017-10271 |
| Playbook | [Web shell compromise](../../../playbooks/web-shell-compromise.md) |

## Lessons for SOC and CERT

- **Scan by asset, not by importance.** Low-traffic servers are where old CVEs survive. Reconcile the CMDB with what actually answers on the network.
- **KEV-listed CVEs on internet-facing hosts get a hard deadline**, regardless of how old they are.
- **Never log what you would not store.** Mask PAN and CVC at the application, and alert on them in log pipelines.
- **No server without telemetry.** The malware was found minutes after an agent was installed.

## Sources

- [Bizwatch: CVE-2017-10271, 1 of 48 servers missed](https://news.bizwatch.co.kr/article/finance/2025/09/18/0040)
- [Newsis: 2.97 million affected, 200 GB](https://mobile.newsis.com/view/NISX20250918_0003334430)
- [Newsis: PIPC fine and 450,000 resident registration numbers](https://mobile.newsis.com/view/NISX20260312_0003544641)
- [MTN: FSS findings, CISO warning, malware found after AV install](https://news.mtn.co.kr/news-detail/2026080409061214867/share-modal)
- [Kyunghyang: business suspension and fine](https://khan.co.kr/article/202607311800001)
