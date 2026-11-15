# 01. SK Telecom USIM data breach (SKT 유심 정보 유출), 2025

A multi-year intrusion into a mobile carrier's core network. The attacker planted BPFDoor passive backdoors and took the USIM authentication data of essentially every subscriber.

| Field | Value |
| --- | --- |
| Detected / disclosed | Detected 18 April 2025, reported to KISA 20 April 2025, final government findings 4 July 2025 |
| Sector | Telecommunications (통신) |
| Impact | 28 servers infected with 33 malware samples. 25 types of USIM data (9.82 GB), about 26.96 million IMSI records |
| Initial access | Not fully public. The first malware was planted in August 2021 |
| Related CVEs | None named publicly |
| Attribution | Not officially attributed. BPFDoor is linked by Trend Micro to Red Menshen / Earth Bluecrow, but its source code has been public since 2022 |
| Public IOCs | Yes: file hashes from KISA notices 1 and 2 (see [`../iocs/iocs.csv`](../iocs/iocs.csv)) |

## Timeline

| Date | Event |
| --- | --- |
| Aug 2021 | First malware installed on a server in the system management network |
| Jun 2022 | Web shell and BPFDoor installed on servers in the customer management network |
| 18 Apr 2025 | Abnormal data movement noticed |
| 20 Apr 2025 | Breach reported to KISA |
| 25 Apr and 3 May 2025 | KISA publishes BPFDoor hashes (notices 1 and 2) |
| 19 May 2025 | Second interim result: 23 servers, 25 malware samples |
| 4 Jul 2025 | Final result: 28 servers, 33 samples (BPFDoor 27, TinyShell 3, web shell 1, CrossC2 1, Sliver 1) |

## Attack chain

1. **Foothold** on a server in the system management network (Aug 2021).
2. **Credential access**: that server stored IDs and passwords for other management servers **in plaintext** (평문 계정정보).
3. **Lateral movement** with those credentials to other management servers, then to the HSS (Home Subscriber Server) management server, and from there to the HSS itself.
4. **Persistence**: BPFDoor on the HSS and other servers. BPFDoor opens no port; it waits for a "magic packet" read through a raw-socket BPF filter, so port scans and firewall logs show nothing.
5. **Collection and exfiltration** of USIM authentication data from the HSS.

## Root causes (근본 원인)

- Plaintext credentials on servers, which turned one foothold into access across the network.
- USIM authentication keys were not encrypted.
- An earlier infection (2022) was handled internally and not reported, so it was never fully investigated.
- No endpoint security on many Linux servers. Logs were not retained long enough to rule exfiltration in or out for most of the intrusion period.

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |
| Persistence | T1505.003 Web Shell | Web shell on a customer-network server |
| Credential Access | T1552.001 Credentials in Files | Plaintext account list on a management server |
| Lateral Movement | T1021.004 SSH | Logins to other servers with harvested credentials |
| Command and Control | T1205.002 Traffic Signaling: Socket Filters | BPFDoor magic packets |
| Defense Evasion | T1036.005 Match Legitimate Name | Binaries and pid files named like HAL and hardware daemons |
| Defense Evasion | T1070.003 Clear Command History | Shell spawned with history disabled |
| Command and Control | T1090 Proxy / T1572 Tunneling | CrossC2, Sliver, TinyShell implants |
| Exfiltration | T1041 Exfiltration Over C2 Channel | USIM data taken from the HSS |

## IOCs

12 file hashes (MD5 and SHA256) published by KISA and reproduced by AhnLab ASEC: `hpasmmld`, `smartadm`, `hald-addon-volume`, `dbus-srv-bin.txt`, five `dbus-srv` builds, `inode262394`, `File_in_Inode_#1900667`, `gm`, `rad`. All are in [`../iocs/iocs.csv`](../iocs/iocs.csv) with their source.

Hashes change with each build. The **behavioural** indicators below last longer.

- Raw sockets with a BPF filter held by a process with an odd name: `ss -0pb` or `lsof | grep -i 'raw\|packet'`.
- Pid files such as `/var/run/hald-smartd.pid`, `/var/run/hp-health.pid`, `/var/run/hald-addon.pid`, older builds `/var/run/haldrund.pid` and `/dev/shm/kdmtmpflush`.
- Short-lived `iptables -t nat ... -j REDIRECT --to-ports 42391-43390` rules.
- Magic bytes `0x5293` (TCP) and `0x7255` (UDP and ICMP) at the start of the payload.

## Detect it with this repo

| Layer | Detection |
| --- | --- |
| NDR / IDS | Suricata [9100070–72](../../../detections/suricata/blue-team.rules) (BPFDoor magic packets, tested by pcap replay) |
| EDR (Linux) | Sigma [`bpfdoor_pid_file_artifacts`](../../../detections/sigma/bpfdoor_pid_file_artifacts.yml), [`bpfdoor_iptables_redirect`](../../../detections/sigma/bpfdoor_iptables_redirect.yml), [`webshell_child_process_linux`](../../../detections/sigma/webshell_child_process_linux.yml) |
| File scan | YARA [`Linux_Backdoor_BPFDoor_Generic`](../../../detections/yara/linux_bpfdoor_generic.yar) |
| Hunting | BPFDoor hunting queries (to be added) |
| Forensics | [Linux artifacts](../../../forensics/linux-artifacts.md), [live response script](../../../forensics/collect/collect_linux.sh) |

## Lessons for SOC and CERT

- **Linux servers need telemetry**: process creation, file creation in `/var/run` and `/dev/shm`, and raw-socket inventory. Without it a passive backdoor is invisible.
- **A passive backdoor defeats port-based hunting.** Hunt for processes holding packet sockets instead.
- **Plaintext credential stores are a breach multiplier.** Treat them as findings with the same priority as an exposed RCE.
- **Report and investigate every infection.** The 2022 infection that went unreported left the same actor in place for three more years.
- **Keep logs long enough to answer "was data taken?"** Here, missing logs left most of the intrusion period unanswerable.

## Sources

- Ministry of Science and ICT final findings, as reported by [Digital Daily](https://www.ddaily.co.kr/page/view/2025070412563749518), [Boan News](https://m.boannews.com/html/detail.html?idx=137999), [News Tomato](https://newstomato.com/ReadNews.aspx?no=1267456), [Herald Economy](https://heraldk.com/2025/07/03/%ed%95%b4%ed%82%b9-4%eb%85%84%ec%a0%84-%ec%8b%9c%ec%9e%91%eb%90%90%eb%8b%a4%e2%80%a6%ec%9c%a0%ec%8b%ac-%ec%a0%95%eb%b3%b4-25%ec%a2%85%c2%b7imsi-2700%eb%a7%8c%ea%b1%b4-%ed%84%b8%eb%a0%a4/)
- KISA hash notices via [AhnLab ASEC: BPFDoor detection and KISA hash notice](https://asec.ahnlab.com/en/87863/)
- [Boan News: KISA publishes SKT-related malware](https://m.boannews.com/html/detail.html?idx=137004)
- [Trend Micro: BPFDoor's hidden controller](https://www.trendmicro.com/en_us/research/25/d/bpfdoor-hidden-controller.html)
