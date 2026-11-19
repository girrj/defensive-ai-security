# Vulnerabilities named in the Korean cases

Five CVEs appear in the cases. Most of the cases have **no CVE at all**: they come from credentials, keys, configuration and missing monitoring.

Check current CISA KEV status and EPSS before you set a deadline:

```bash
python3 vuln-triage/cve_triage.py CVE-2017-10271 CVE-2025-61882 CVE-2025-61884 CVE-2024-55591 CVE-2025-24472 --exposure internet
```

| CVE | Product | Class | Case | Detections in this repo |
| --- | --- | --- | --- | --- |
| CVE-2017-10271 | Oracle WebLogic Server, WLS-WSAT component | Unauthenticated RCE via XMLDecoder deserialization | [07 Lotte Card](cases/07-lotte-card-weblogic.md) | Suricata 9100060; WAF 1009130, 1009131; Sigma `webshell_child_process_linux` |
| CVE-2025-61882 | Oracle E-Business Suite 12.2.3–12.2.14 (BI Publisher Integration / Concurrent Processing) | Unauthenticated RCE | [11 Korean Air / KC&D](cases/11-korean-air-kcd-oracle-ebs.md) | Suricata 9100061–62; WAF 1009132, 1009133; Sigma `linux_reverse_shell_dev_tcp` |
| CVE-2025-61884 | Oracle E-Business Suite (Configurator runtime UI) | Unauthenticated access to resources (SSRF) | [11 Korean Air / KC&D](cases/11-korean-air-kcd-oracle-ebs.md) | Suricata 9100061; WAF 1009132 |
| CVE-2024-55591 | Fortinet FortiOS / FortiProxy | Authentication bypass to super-admin | [06 SGI](cases/06-sgi-gunra-ransomware.md) (Gunra campaign, not this victim) | Hunting: new admin accounts on edge devices |
| CVE-2025-24472 | Fortinet FortiOS / FortiProxy | Authentication bypass to super-admin | [06 SGI](cases/06-sgi-gunra-ransomware.md) (Gunra campaign) | Same as above |

## What to do, by CVE

### CVE-2017-10271 (WebLogic WLS-WSAT)

- **Patch**: Oracle Critical Patch Update, October 2017, or any later WebLogic release.
- **If you cannot patch today**: block `/wls-wsat/*` and `/_async/*` at the WAF or reverse proxy (rule [1009130](../../detections/waf/modsecurity/blue-team-waf.conf)), or remove the `wls-wsat.war` component if no application uses it.
- **Hunt**: Review unexpected WebLogic Java child processes with the [WebLogic hunting query](hunting.md#weblogic).
- **Why it still matters**: the 2025 card breach used an eight-year-old fix that one server never received. Old KEV-listed CVEs on internet-facing hosts need the same deadline as new ones.

### CVE-2025-61882 and CVE-2025-61884 (Oracle EBS)

- **Patch**: Oracle Security Alerts of 4 and 11 October 2025. CVE-2025-61882 required the October 2023 CPU as a prerequisite.
- **Reduce exposure**: EBS should sit behind an access gateway or VPN. Deny `/OA_HTML/SyncServlet`, `/OA_HTML/configurator/UiServlet` and the XDO `TemplatePreviewPG` page from the internet ([1009132–133](../../detections/waf/modsecurity/blue-team-waf.conf)).
- **Look for compromise**, not only exposure: the campaign started about two months before the patch. Sweep the [Oracle IOCs](iocs/iocs.csv), review `XDO_TEMPLATES_B` and `XDO_LOBS` for templates you did not create, and check for outbound shells from the EBS tier.

### CVE-2024-55591 and CVE-2025-24472 (FortiOS / FortiProxy)

- **Patch** to a fixed FortiOS or FortiProxy release per Fortinet's PSIRT advisory.
- **Restrict** the management interface to a management network. It should never be reachable from the internet.
- **Hunt** for super-admin accounts you did not create (the Gunra advisory names `forticloud-sync`), new local users, config changes and admin logins from unfamiliar IPs. Treat any of them as an incident: the device may already have been used to reach the internal network.

## Non-CVE weaknesses that did more damage

| Weakness | Cases | Control |
| --- | --- | --- |
| Plaintext credentials and keys in files or source | 01, 09, 12 | Secret scanning in CI, vaults/KMS, rotation |
| Default or weak passwords on appliances | 06 | Hardening baseline, MFA, lockout, no internet-facing management |
| One credential shared by a whole device fleet | 02 | Per-device keys, short validity, revocation |
| Credential reuse by customers | 08 | Rate limiting, breached-password checks, MFA |
| File-based certificates copied to personal devices | 04 | Hardware-bound or phishing-resistant credentials, device checks on VPN |
| Sensitive data written to logs | 07 | Masking at the source, DLP on log pipelines |
| Weak key generation or derivation | 10 | Independent review of cryptographic code, HSM-backed signing |

## Sources

- [Oracle Security Alert CVE-2025-61882](https://www.oracle.com/security-alerts/alert-cve-2025-61882.html)
- [CISA/FBI et al., AA26-222A Gunra Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a)
- [Bizwatch: Lotte Card and CVE-2017-10271](https://news.bizwatch.co.kr/article/finance/2025/09/18/0040)
- Case files in [`cases/`](cases/) for incident-specific sources
