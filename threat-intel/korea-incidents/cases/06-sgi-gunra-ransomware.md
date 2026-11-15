# 06. SGI Seoul Guarantee ransomware (SGI서울보증 랜섬웨어, Gunra), 2025

A guarantee insurer's core services (jeonse deposit guarantees and others) stopped for about three days after a ransomware attack that entered through an SSL-VPN appliance with weak and default passwords. The Financial Security Institute recovered the data by finding a flaw in the encryptor.

| Field | Value |
| --- | --- |
| Date | Attack around 12–14 July 2025 (a Saturday, during outsourced remote monitoring). Services resumed 17 July |
| Sector | Finance, insurance (금융·보증보험) |
| Impact | Guarantee services disrupted for about 3 days. Only about 20% of backups survived |
| Initial access | SSL-VPN appliance: SSH service brute-forced; the vendor default password `0000` had never been changed; the admin account had a simple password |
| Related CVEs | None for this case |
| Attribution | Gunra ransomware suspected (Conti v2-derived) |
| Public IOCs | Gunra IOCs in joint advisory AA26-222A (campaign-wide, not specific to this victim) |

## Attack chain

1. **Initial access** through the SSL-VPN appliance. The SSH service on it had no login-attempt limit, no rate limiting and no MFA, and the default password was still set.
2. **Privilege**: the second-stage admin account also had an easily guessed password.
3. **Dwell time** of about a month before encryption, according to the regulator's findings reported in the press.
4. **Impact on a weekend**, when only outsourced staff monitored remotely. In-house staff noticed on Sunday afternoon.
5. **Backups**: the offsite backup was left connected to the network for convenience, so the ransomware reached it.
6. **Recovery**: FSI analysts extracted the key by exploiting a weakness in the malware and decrypted the files without paying.

## Gunra in brief

Gunra appeared in April 2025, is built on leaked Conti v2 code, and launched a ransomware-as-a-service affiliate program in early 2026. The joint advisory AA26-222A (FBI, CISA, DC3, NSA, USSS and the Korean National Police Agency, 10 August 2026) describes entry through FortiOS/FortiProxy authentication bypasses (CVE-2024-55591, CVE-2025-24472), a persistence account named `forticloud-sync`, tampering with a VDI portal's one-time-password step (T1556.006), the note `R3ADM3.txt` and the extensions `.ENCRT`, `.CRYPT` and `.GNRA` (Linux). The advisory names no victims.

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |
| Initial Access | T1133 External Remote Services | SSL-VPN appliance |
| Credential Access | T1110.001 Password Guessing | SSH brute force with no lockout |
| Initial Access | T1078.001 Default Accounts | Vendor default password |
| Impact | T1486 Data Encrypted for Impact | Core systems encrypted |
| Impact | T1490 Inhibit System Recovery | Connected backups encrypted |

## IOCs

This case has no victim-specific public IOCs. The Gunra IOCs from AA26-222A (4 SHA256 hashes, 18 IPs that may be historical, a clearnet leak-site domain, 3 onion addresses, 4 negotiation emails) are in [`../iocs/iocs.csv`](../iocs/iocs.csv) with `scope=campaign`. Match on them to find Gunra activity in general, not to prove this case.

## Detect it with this repo

| Layer | Detection |
| --- | --- |
| EDR (Windows) | Sigma [`gunra_ransomware_artifacts`](../../../detections/sigma/gunra_ransomware_artifacts.yml), [`ransomware_recovery_inhibition`](../../../detections/sigma/ransomware_recovery_inhibition.yml) |
| Hunting | [VPN/appliance brute force](../hunting.md#vpn-brute-force), [Gunra IOC sweep](../hunting.md#ioc-sweep) |
| Playbook | [Ransomware precursor response](../../../playbooks/ransomware-precursor.md) |
| Vulnerabilities | [CVE-2024-55591, CVE-2025-24472](../vulnerabilities.md) |

## Lessons for SOC and CERT

- **Edge appliances are servers.** Change default passwords, disable management services (SSH, web admin) on the internet side, enforce MFA and lockout, and forward their logs to the SIEM.
- **Weekend and night coverage must be able to act**, not only watch. Give the on-call team authority and a runbook to isolate.
- **A backup that the production network can write to is not a backup.**
- **Ask the sector CERT early.** FSI's decryption was only possible because it got the samples quickly.

## Sources

- [Boan News: initial access via SSL-VPN SSH, no login limit](https://m.boannews.com/html/detail.html?idx=138214)
- [Newsis: default password 0000, backups connected, 4 security staff](https://www.newsis.com/view/NISX20250901_0003311504)
- [Boan News: FSI decrypted without ransom](https://m.boannews.com/html/detail.html?idx=138237)
- [Boan News: Gunra suspected, SSH brute force](https://m.boannews.com/html/detail.html?idx=138242)
- [CISA/FBI et al., AA26-222A #StopRansomware: Gunra Ransomware (PDF)](https://www.ic3.gov/CSA/2026/260810.pdf), [CISA advisory page](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a)
