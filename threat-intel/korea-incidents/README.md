# Korean incident cases (국내 침해사고 사례)

Public Korean incidents from 2025–2026 rewritten from a defender's point of view. Each case records what is publicly known about cause, related vulnerabilities, ATT&CK mapping, public IOCs, relevant defenses and lessons for SOC and CERT teams. Case 13 is an aggregate report with causes still under investigation.

Everything here comes from public reporting and official advisories, and every case lists its sources. Nothing comes from non-public investigations.

## Index

| # | Case | When | Sector | Initial access | CVE | Public IOCs | Detections here |
| --- | --- | --- | --- | --- | --- | :---: | --- |
| 01 | [SK Telecom USIM data (BPFDoor)](cases/01-skt-usim-bpfdoor.md) | 2021–2025 | Telecom | Not public; plaintext credentials enabled lateral movement | — | ✅ hashes | Suricata, Sigma, YARA |
| 02 | [KT femtocells and servers](cases/02-kt-femtocell-and-servers.md) | 2022–2025 | Telecom | Cloned device certificate; web shell via file upload | — | — | WAF, Sigma, Suricata |
| 03 | [LG Uplus APPM leak](cases/03-lgu-appm-leak.md) | 2025 | Telecom | Unknown (evidence reinstalled) | — | — | Hunting, forensics |
| 04 | [Onnara and GPKI certificates](cases/04-onnara-gpki.md) | 2022–2025 | Government | Stolen certificates over the remote-work VPN | — | — | Hunting |
| 05 | [YES24 ransomware](cases/05-yes24-ransomware.md) | 2025 | E-commerce | Not public | — | — | Sigma, playbook |
| 06 | [SGI Seoul Guarantee (Gunra)](cases/06-sgi-gunra-ransomware.md) | 2025 | Finance | SSL-VPN appliance with default password | (campaign) CVE-2024-55591, CVE-2025-24472 | ✅ campaign | Sigma, hunting |
| 07 | [Lotte Card payment server](cases/07-lotte-card-weblogic.md) | 2025 | Finance | WebLogic RCE | CVE-2017-10271 | — | Suricata, WAF, Sigma |
| 08 | [GS Retail credential stuffing](cases/08-gs-retail-credential-stuffing.md) | 2024–2025 | Retail | Credential stuffing | — | — | Hunting |
| 09 | [Coupang signing key](cases/09-coupang-signing-key.md) | 2025 | E-commerce | Insider with a retained signing key | — | — | Hunting, secret scanning |
| 10 | [Upbit hot wallet](cases/10-upbit-hot-wallet.md) | 2025 | Virtual assets | Private-key inference flaw | — | — | Hunting |
| 11 | [Korean Air via KC&D (Oracle EBS)](cases/11-korean-air-kcd-oracle-ebs.md) | 2025 | Aviation supply chain | Oracle EBS zero-day | CVE-2025-61882, CVE-2025-61884 | ✅ campaign | Suricata, WAF, Sigma |
| 12 | [TVING developer access key](cases/12-tving-access-key.md) | 2026 | Media / OTT | Stolen developer key; plaintext secrets in source | — | — | Hunting, secret scanning |
| 13 | [Financial-sector incident reports](cases/13-financial-sector-incidents-2026.md) | 2026 | Finance | Under investigation; no common path established | — | — | Exposure review, response |

New cases use the next number and follow [`TEMPLATE.md`](TEMPLATE.md).

## Cross-case material

| Page | What it gives you |
| --- | --- |
| [`vulnerabilities.md`](vulnerabilities.md) | Every CVE named in the cases, the affected products and what to do |
| [`iocs/iocs.csv`](iocs/iocs.csv) | 61 public IOCs, defanged, each with its source and scope ([format](iocs/README.md)) |
| [`hunting.md`](hunting.md) | SPL and Google SecOps UDM starting points for the 12 case-linked hunts |
| [`attack-patterns.md`](attack-patterns.md) | Repeated weaknesses and the controls that interrupt them |

## What the cases have in common

- **Most did not start with a zero-day.** Plaintext credentials, default passwords, an eight-year-old CVE, keys in source code and reused passwords did most of the damage.
- **Linux servers with no telemetry** hid BPFDoor for years at two carriers and malware at a card issuer.
- **Late or missing reporting** (unreported infections, delayed notices, evidence reinstalled) made scope impossible to establish and drew the heaviest sanctions.
- **Logs ran out.** Several investigations could not say whether data left because the logs did not reach back far enough.

## Tests

`tests/test_iocs.py` checks the IOC file on every CI run: header, IOC types, hash format, defanging, valid IPs and onion addresses, a public source URL on every row, and a matching case file.

```bash
python3 -m unittest discover -s threat-intel/korea-incidents/tests
```
