# 04. Government Onnara system and GPKI certificate theft (온나라시스템·GPKI 인증서 탈취), 2022–2025

Attackers stole civil servants' government PKI (GPKI, 행정전자서명) certificates and passwords, logged in through the government remote-work VPN (GVPN) as legitimate users, and read documents in Onnara, the government's document and approval system.

| Field | Value |
| --- | --- |
| Disclosed | Phrack "APT Down" article, 8 August 2025. Government confirmation 17 October 2025 |
| Sector | Central government (정부·공공) |
| Impact | About 650 GPKI certificate files leaked; 12 included the private key and password. Some documents were viewed. Source code of a ministry's mail server and an old Onnara authentication API also exposed |
| Initial access | Stolen certificates and passwords used through GVPN |
| Related CVEs | None |
| Attribution | Phrack's authors attributed the dump to Kimsuky. Other researchers raised a China-linked actor. The government did not attribute |
| Public IOCs | None released |

## Timeline

| Date | Event |
| --- | --- |
| 2022 onward | Unauthorized GVPN logins with stolen credentials over roughly three years (reported) |
| Mid-July 2025 | NIS spots access to Onnara through GVPN from an outside internet PC and informs the Ministry of the Interior and Safety |
| 28 Jul 2025 | Login-reuse protection applied to Onnara across ministries and local governments |
| 4 Aug 2025 | Phone (ARS) verification made mandatory, in addition to GPKI, for remote-work logins |
| 8 Aug 2025 | Phrack article published |
| 13 Aug 2025 | The three still-valid leaked certificates revoked |
| 17 Oct 2025 | Government confirms the access and the certificate leak |

## How it worked

1. **Credential theft.** GPKI certificates are files plus a password. Officials copied them to home PCs and USB drives for remote work, where malware or careless handling exposed them. The government named user negligence as a likely cause.
2. **Valid-account access.** With a certificate and its password the attacker passed GVPN authentication and reached Onnara like a normal remote worker.
3. **Collection.** Documents were opened. A ministry's mail server source code was also exposed and later patched.
4. **Phishing support.** About 180 government email accounts appear to have visited attacker-built phishing sites; their passwords were reset.

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |
| Credential Access | T1552.004 Private Keys | Certificate files and keys copied off endpoints |
| Credential Access | T1056 Input Capture / T1566 Phishing | Certificate passwords and mail credentials |
| Initial Access | T1133 External Remote Services | GVPN |
| Initial Access | T1078 Valid Accounts | Logins as real officials |
| Collection | T1213 Data from Information Repositories | Documents in Onnara |

## Detect it with this repo

| Layer | Detection |
| --- | --- |
| Hunting | [VPN new-source and certificate use](../hunting.md#vpn-new-source) |
| SOC | [Alert triage standard](../../../soc-operations/alert-triage-standard.md) for identity alerts |

## Lessons for SOC and CERT

- **File-based certificates are passwords that can be copied.** Prefer hardware-bound or phishing-resistant credentials (FIDO2, smart cards, mobile ID with device binding).
- **Remote access needs a device check**, not only a user check. Unknown devices on the VPN should be a high-priority alert.
- **Baseline remote-work logins**: source ASN, country, time of day, number of IPs per certificate. Valid-account intrusions are found by behaviour, not signatures.

## Sources

- [Newsis: government confirms access, about 650 certificates leaked](https://www.newsis.com/view/NISX20251017_0003366706)
- [Daum/Newsis: 12 certificates with keys and passwords](https://v.daum.net/v/20251017120913925)
- [Digital Daily: 3 valid certificates revoked on 13 August](https://www.ddaily.co.kr/page/view/2025101711501493146)
- [Byline Network: NIS account of GVPN access, mail server source and phishing sites](https://byline.network/2025/10/20-492/)
- [Newsis: login-reuse and ARS measures](https://www.newsis.com/view/NISX20251017_0003367123)
- [Newsis: access over about three years](https://mobile.newsis.com/view/NISX20251018_0003367702)
