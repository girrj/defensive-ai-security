# 02. KT illegal femtocell and server intrusion (KT 불법 펨토셀·서버 침해), 2025

Two connected problems at a mobile carrier: rogue small cells (femtocells) that joined the core network with a cloned certificate and were used for unauthorized micropayments, and a separate, long-running server compromise with BPFDoor and rootkits.

| Field | Value |
| --- | --- |
| Disclosed | Unauthorized micropayments surfaced in Aug–Sep 2025. Final government findings 29 December 2025 |
| Sector | Telecommunications (통신) |
| Impact | 368 customers, 777 unauthorized payments, about ₩243 million. IMSI, IMEI and phone numbers of 22,227 subscribers exposed. 94 servers infected with 103 malware samples |
| Initial access | Femtocell: cloned device certificate. Servers: web shell uploaded through a file-upload flaw, from about April 2022 |
| Related CVEs | None named publicly |
| Attribution | Not attributed |
| Public IOCs | No hashes published for this case. KISA's BPFDoor check guide applies |

## Two incidents in one

### A. Rogue femtocells (불법 펨토셀)

- Every femtocell supplied to the carrier used the **same certificate**, valid for **10 years**.
- The manufacturer handed cell IDs, certificates and core-network server IPs to an outsourced builder without security controls, and the data could be read off the device storage.
- With a cloned certificate, a rogue device registered as a legitimate cell. The core network did not check abnormal source IPs, install location or device configuration.
- Phones near the rogue cell attached to it. The operators could then intercept SMS-based authentication and run micropayments.
- Investigators also found that SMS encryption was not applied to some older handsets.

### B. Server compromise (서버 악성코드 감염)

- 94 servers infected with 103 samples, including BPFDoor, rootkits and DDoS bots.
- Entry by a **web shell uploaded through a file-upload vulnerability**, followed by BPFDoor.
- In 2024 the carrier had found 43 infected servers through an outside security check and **did not report them**. Investigators said this was concealed.
- Customer data leakage could only be ruled out for the most recent one to two months, because older logs did not exist.

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |
| Initial Access | T1190 Exploit Public-Facing Application | File-upload flaw used to drop a web shell |
| Persistence | T1505.003 Web Shell | Web shell on the upload host |
| Persistence | T1014 Rootkit | Kernel and user-mode rootkits |
| Command and Control | T1205.002 Socket Filters | BPFDoor |
| Initial Access (network) | T1200 Hardware Additions | Rogue femtocell attached to the core network |
| Credential Access | T1552.004 Private Keys | Shared device certificate and key cloned from the device |
| Collection | T1557 Adversary-in-the-Middle | Interception of SMS and authentication traffic through the rogue cell |
| Impact | T1657 Financial Theft | Unauthorized micropayments |

## Detect it with this repo

| Layer | Detection |
| --- | --- |
| WAF | Script upload deny [1009103](../../../detections/waf/modsecurity/blue-team-waf.conf), commands to script pages 1009104 |
| EDR (Linux) | Sigma [`webshell_child_process_linux`](../../../detections/sigma/webshell_child_process_linux.yml), [`bpfdoor_pid_file_artifacts`](../../../detections/sigma/bpfdoor_pid_file_artifacts.yml), [`bpfdoor_iptables_redirect`](../../../detections/sigma/bpfdoor_iptables_redirect.yml) |
| NDR / IDS | Suricata 9100070–72 |
| Hunting | Device registration from unexpected networks (to be added), BPFDoor (to be added) |
| Playbook | [Web shell compromise](../../../playbooks/web-shell-compromise.md) |

## Lessons for SOC and CERT

- **Per-device credentials.** One certificate shared by every device means one extraction compromises the fleet. Give each device its own key, short validity and a revocation path.
- **Validate the device, not just the certificate.** Source network, location and hardware profile are cheap checks that would have flagged rogue cells.
- **Reporting is part of containment.** Unreported infections cannot be checked against other victims or by investigators.
- **SMS is a weak second factor** once the radio layer is in the attacker's hands.

## Sources

- [Newsis: final findings, 94 servers and 103 samples](https://www.newsis.com/view/NISX20251229_0003457704)
- [Boan News: 22,227 IMSI/IMEI exposed, 94 servers](https://m.boannews.com/html/detail.html?idx=141219)
- [Byline Network: shared certificate with 10-year validity](https://byline.network/2025/11/6-292/)
- [Newsis: 43 infected servers concealed](https://www.newsis.com/view/NISX20251106_0003393244)
- [Kyunghyang: leakage could not be confirmed outside the logged period](https://www.khan.co.kr/article/202512302117005)
- [ThreatCluster summary: file-upload entry from April 2022](https://threatcluster.io/cluster/kt-breach-investigation-reveals-malware-infections-in-94-ser-9707d1eb)
