# Defensive AI Security

A blue-team toolkit for running a SOC or CERT. It covers detection engineering across IDS, WAF, EDR, NDR, and SIEM, plus incident response, forensics, vulnerability and zero-day response, **defending AI systems** (LLM applications, agents, MCP servers, model infrastructure), and guidelines for using LLMs safely in that work.

**[Awesome Blue Team (블루팀 자료 목록)](blue-team-analyst-resources.md)** — Browse tools, references, and practice data by investigation task.

Maintained by a security operations practitioner with more than ten years in enterprise SOCs, CERT work, and managed security services.

---

## What's here

| Area | Contents |
| --- | --- |
| [**detections/**](detections/) | **Sigma** (21 rules), **Suricata IDS** (31 rules), **ModSecurity WAF** (19 rules), **YARA** (13 rules in 5 files), **Google SecOps YARA-L** (2 reference rules); validation scope below |
| [**ai-security/**](ai-security/) | **Defending AI systems**: OWASP LLM Top 10 **2026**, OWASP Agentic Top 10 2026, and MITRE ATLAS mapped to detections; LLM infrastructure hardening; MCP security checklist; a map of open-source defensive AI tools |
| [**encyclopedia/**](encyclopedia/) | **Blue team, SOC and CERT encyclopedia** (English with Korean terms): categorized list of glossary, concept, framework, tool and technique entries, being filled in |
| [**threat-intel/korea-incidents/**](threat-intel/korea-incidents/) | **12 public Korean breaches (2025–2026)** rewritten for defenders: timeline, root cause, related CVEs, ATT&CK mapping, the detections here that cover each one, and 61 public IOCs with sources |
| [**edr/**](edr/) | EDR operations: measuring coverage, a triage method, response actions and when to use them, tuning without losing coverage |
| [**ndr/**](ndr/) | `zeek_hunt.py` for beaconing and DNS-tunneling detection over Zeek logs, plus a network hunting guide |
| [**hunting/**](hunting/) | Hunting queries for Google SecOps (UDM) and Splunk (SPL) |
| [**ir-manual/**](ir-manual/) | **Incident response manual**: roles, severity, the response process (NIST SP 800-61r3), communication, **Korean legal reporting (Network Act 24h, PIPA 72h)**, readiness |
| [**playbooks/**](playbooks/) | Zero-day / emergency vulnerability response, web shell compromise, ransomware precursors, **LLM application / agent compromise**, AI coding agent incidents |
| [**forensics/**](forensics/) | Windows, Linux, and memory artifact guides, evidence handling and chain of custody, **read-only live-response collection scripts** (Bash, PowerShell) |
| [**soc-operations/**](soc-operations/) | Alert triage standard, detection engineering lifecycle, shift handover and incident report templates |
| [**vuln-triage/**](vuln-triage/) | `cve_triage.py`: CVE prioritization from CISA KEV, EPSS, and exposure |
| [**llm-guidelines/**](llm-guidelines/) | **Instructions for training and operating an LLM as a SOC assistant**: system prompt, agent operating rules, good and bad examples, fine-tuning data, an automated eval set |
| [**ai-assisted-defense/**](ai-assisted-defense/) | Usage principles, data-handling rules, and prompt templates for analysts |
| [**tools/**](tools/) | `ioc_extract.py` (IOC extraction, refanging, and defanging), pre-publication secret scan, CI helpers |

---

## Detection coverage

| Tactic | Technique | Sigma | Suricata | WAF | YARA / YARA-L |
| --- | --- | :---: | :---: | :---: | :---: |
| Initial access | T1190 Exploit public-facing app (JNDI, class-loader, traversal, WebLogic XMLDecoder, Oracle EBS) | ✅ | ✅ | ✅ | |
| Execution | T1059.001 PowerShell (encoded, hidden, cradle) | ✅ | | | |
| Persistence | T1505.003 Web shell | ✅ | ✅ | ✅ | ✅ ✅ |
| Persistence | T1547.001 Run keys, T1053.005 scheduled tasks | ✅ | | | |
| Defense evasion | T1218 LOLBins, T1562.001 Defender tampering | ✅ | ✅ | | ✅ |
| Credential access | T1003.001 LSASS dump, T1552 credential files | ✅ | | ✅ | |
| Lateral movement | T1021.002 / T1569.002 PsExec-style services | ✅ | ✅ | | |
| Command and control | T1071 beaconing / DNS tunneling, T1105 tool transfer | | ✅ | | `zeek_hunt.py` |
| Command and control | T1205.002 passive backdoor (BPFDoor magic packets, pid files, NAT redirect), T1059.004 reverse shell | ✅ | ✅ | | ✅ |
| Exfiltration | T1567 to web services | | ✅ | | |
| Impact | T1490 recovery inhibition, T1486 ransomware notes and extensions, T1496 mining, T1485 destruction | ✅ | ✅ | | ✅ ✅ |
| AI agent misuse | Destructive commands, credential access, control tampering by AI coding agents | ✅ | | | ✅ |
| AI: prompt injection | Instruction overrides, hidden HTML/CSS instructions, Unicode tag smuggling (AML.T0051, AML.T0068) | | | ✅ | ✅ |
| AI: exposed model servers | External access to Ollama/OpenAI-compatible APIs, model tampering, unauthenticated inference (AML.T0040, AML.T0010) | ✅ | ✅ | ✅ | |
| AI: MCP / agent supply chain | MCP servers spawning shells, downloading payloads, reading credentials; malicious pickle model files | ✅ | | | ✅ |

## How everything is tested

Every push runs [CI](.github/workflows/validate.yml):

| Check | What it proves |
| --- | --- |
| pySigma validation + Splunk conversion, duplicate-key check | Sigma YAML parses without duplicate keys and converts to Splunk queries; event matching and production field mappings are not tested |
| YARA tests on generated samples | Every YARA rule has a positive test and benign negatives: web shells, miners, prompt injection (including UTF-16 and invisible Unicode), and malicious pickles for every protocol version (built, never loaded) |
| **Suricata pcap replay** | Each scenario raises exactly its expected SIDs, no more and no fewer, and benign sessions (including an authenticated LLM call) raise none |
| **Live Apache + ModSecurity** | Synthetic requests exercise blocking and scoring rules on a local Apache instance; expected HTTP statuses and rule log entries are checked, and benign requests raise no BLUETEAM alerts |
| Python unit tests | `cve_triage`, `ioc_extract`, `zeek_hunt`, the LLM eval harness, the public-check gate, and the format of the public IOC file; CI does not call an LLM or measure model quality |
| shellcheck, PowerShell parser + PSScriptAnalyzer | Listed shell scripts and the PowerShell collector pass the configured error-level checks; collection behavior is not tested on live endpoints |
| gitleaks (full history) | No findings from the configured secret scanner in the checked Git history |

The two YARA-L rules are reference content. CI currently provides no YARA-L compilation, event replay, or Google SecOps runtime validation. Validate them in the target platform before deployment. Synthetic sample results also do not establish production false-positive rates or complete detection coverage.

All test data is synthetic. It uses documentation IP ranges (RFC 5737), synthetic private addresses (RFC 1918) for internal-network scenarios, example domains, and harmless placeholder payloads. Nothing here contains customer data, internal hostnames, malware, or exploit code. The only real-world indicators are the public, defanged IOCs in [`threat-intel/korea-incidents/iocs/`](threat-intel/korea-incidents/iocs/), each tied to the official advisory that published it.

Before pushing, run [`tools/check-public.sh`](tools/README.md) with a private local denylist (금칙어 목록). It fails on missing or empty configuration, sensitive-term matches, scan errors, and missing dependencies. Private-IP exceptions apply only to documented synthetic-data paths; they never exclude files from the denylist scan. This local gate is separate from CI, which tests it with synthetic terms and does not have the private list.

---

## Quick start

```bash
# Prioritize CVEs
python3 vuln-triage/cve_triage.py CVE-2024-3400 CVE-2021-44228 --exposure internet

# Extract and defang IOCs from a report
python3 tools/ioc_extract.py report.txt --defang --format csv

# Hunt for beaconing and DNS tunneling in Zeek logs
python3 ndr/zeek_hunt.py beacon conn.log --min-conns 20
python3 ndr/zeek_hunt.py dns dns.log

# Live-response collection (read-only)
sudo forensics/collect/collect_linux.sh -o /mnt/usb -c IR-001
#   Windows (elevated): .\forensics\collect\collect_windows.ps1 -OutputPath E:\IR -CaseId IR-001

# Scan a web root for web shells
yara -r detections/yara/webshell_generic.yar /var/www/

# Scan model files before loading them, and documents before RAG ingestion
yara -r detections/yara/malicious_model_pickle.yar /models/
yara -r detections/yara/prompt_injection.yar ./to-ingest/

# Evaluate an LLM against the SOC assistant guidelines
python3 llm-guidelines/eval/run_eval.py llm-guidelines/eval/cases.jsonl responses.jsonl
```

The Python tools use only the standard library (Python 3.9+).

---

## Principles

- **Behavior over indicators.** Process relationships, sequences, and protocol behavior outlast hashes and IPs.
- **Verify against raw logs.** Decisions rest on events an analyst queried directly, and confirmed facts are kept apart from inference.
- **Exploitation evidence over severity scores.** Vulnerabilities are ordered by known exploitation, probability of exploitation, and exposure.
- **Preserve before you act.** Evidence is collected and hashed before containment changes the system.
- **AI assists, people decide.** Model output is checked against primary sources, instructions found in data are never followed, and any change to a system needs explicit human approval.

See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) for the scope of this work and how disclosure is handled.

## License

[MIT](LICENSE)
