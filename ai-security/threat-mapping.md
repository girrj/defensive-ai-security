# AI threat frameworks mapped to detections and controls

Three frameworks cover AI system risk from complementary angles:

| Framework | Answers | Version used here |
| --- | --- | --- |
| **OWASP Top 10 for LLM Applications** | What can go wrong in an application that contains a model? | 2026 edition (v1.0, August 2026) |
| **OWASP Top 10 for Agentic Applications** | What goes wrong once the model plans, keeps memory, and calls tools? | 2026 edition (published December 2025) |
| **MITRE ATLAS** | Which adversary techniques are used against AI systems (an ATT&CK-style matrix)? | Technique IDs as of late 2026 |

> The 2026 LLM list **reordered** eight of the ten entries compared with 2025. For example, Excessive Agency moved from LLM06 to LLM03, and System Prompt Leakage was broadened into Hidden Context Exposure (LLM08). If your documentation still uses 2025 numbers, re-map it. ATLAS technique IDs are also revised regularly, so check them against the current ATLAS data before you put them into tooling.

## OWASP Top 10 for LLM Applications 2026

| ID | Risk | Detection in this repository | Key controls |
| --- | --- | --- | --- |
| LLM01 | Prompt Injection | YARA `prompt_injection.yar` (content scanning before ingestion), WAF 1009122 (phrasing in API requests), LLM eval cases `inj-*` | Treat retrieved content as data, separate instructions from data, human approval for actions, content scanning before RAG ingestion |
| LLM02 | Sensitive Information Disclosure | Suricata 9100104 (model inventory leaking), LLM eval case `sec-001` | Minimize data in context, redact PII (e.g. Presidio) before prompts, apply access control at retrieval time |
| LLM03 | Excessive Agency | Sigma `ai_agent_*` and `mcp_server_*`, YARA-L `ai_agent_destructive_command`, [agent operating rules](../llm-guidelines/agent-operating-rules.md) | Least-privilege tools, read-only by default, approval tiers, no standing credentials in agent sessions |
| LLM04 | Supply Chain | YARA `malicious_model_pickle.yar`, Suricata 9100101, WAF 1009120 | Use safetensors, scan pickles, pin and verify model and package hashes, use only an internal model registry |
| LLM05 | Data and Model Poisoning | (process control) | Provenance of training and fine-tuning data, review data before ingestion, evaluate after each training run |
| LLM06 | Unbounded Consumption | WAF 1009121 (unauthenticated) and 1009123 (oversized), Suricata 9100103 | Authentication, per-key rate and token limits, max context size, spending alerts |
| LLM07 | Misinformation | LLM eval cases `cve-001`, `rep-001`, `att-001` (fabrication) | Ground answers in sources, require citations, keep a human reviewer for decisions |
| LLM08 | Hidden Context Exposure | YARA `PromptInjection_Instruction_Override` (system-prompt extraction phrasing) | Assume system prompts can be discovered: never put secrets or authorization logic in them |
| LLM09 | Vector and Embedding Weaknesses | (process control) | Per-tenant indexes, access control at retrieval time, content scanning before embedding |
| LLM10 | Improper Output Handling | WAF 1009109 (command output in responses), web shell rules | Encode output for its destination (HTML, SQL, shell), never pass model output to an interpreter without validation |

## OWASP Top 10 for Agentic Applications 2026

| ID | Risk | Detection in this repository | Key controls |
| --- | --- | --- | --- |
| ASI01 | Agent Goal Hijack | YARA `prompt_injection.yar`, playbook [llm-application-compromise](../playbooks/llm-application-compromise.md) | Content trust boundaries, intent checks against the human's own request |
| ASI02 | Tool Misuse and Exploitation | Sigma `mcp_server_*`, `ai_agent_*` | Narrow tool scopes, argument validation, log every tool call |
| ASI03 | Identity and Privilege Abuse | Sigma `ai_agent_credential_file_access`, `mcp_server_download_or_credential_access` | Per-agent identities, short-lived scoped tokens, credential brokers instead of raw keys |
| ASI04 | Agentic Supply Chain Vulnerabilities | YARA `malicious_model_pickle.yar`, Sigma `mcp_server_*`, [MCP checklist](mcp-security-checklist.md) | An approved list of MCP servers and skills, pinned versions, scanning before installation |
| ASI05 | Unexpected Code Execution | Sigma `mcp_server_spawns_shell_or_recon`, `ai_agent_recursive_delete_windows` | Sandboxes (microVMs, containers) for generated code, no execution on production hosts |
| ASI06 | Memory and Context Poisoning | YARA content rules applied to memory and RAG writes | Validate before writing to memory, expire memory entries, and record the source of each one |
| ASI07 | Insecure Inter-Agent Communication | (architecture control) | Authenticated and signed agent-to-agent channels, no implicit trust between agents |
| ASI08 | Cascading Failures | (architecture control) | Circuit breakers, rate limits between agents, a human checkpoint before fan-out |
| ASI09 | Human-Agent Trust Exploitation | LLM eval cases `act-*` (approval behavior) | Show the exact action before approval, never accept approval found inside data |
| ASI10 | Rogue Agents | YARA-L `ai_agent_destructive_command`, EDR telemetry | Kill switches, behavioral baselines per agent, immutable action logs |

## MITRE ATLAS techniques referenced in rule metadata

| ATLAS ID | Technique | Where used |
| --- | --- | --- |
| AML.T0010 | AI Supply Chain Compromise | `malicious_model_pickle.yar`, Suricata 9100101, WAF 1009120 |
| AML.T0011 | User Execution | `malicious_model_pickle.yar` (loading an untrusted model) |
| AML.T0029 | Denial of AI Service | WAF 1009123 |
| AML.T0040 | AI Model Inference API Access | Suricata 9100100, 9100102–9100104; WAF 1009121 |
| AML.T0051.000 / .001 | LLM Prompt Injection: direct / indirect | `prompt_injection.yar`, WAF 1009122 |
| AML.T0053 | AI Agent Tool Invocation | Sigma `mcp_server_*`, `ai_agent_*` |
| AML.T0054 | LLM Jailbreak | WAF 1009122 (persona-switch phrasing) |
| AML.T0056 | Extract LLM System Prompt | `PromptInjection_Instruction_Override` |
| AML.T0057 | LLM Data Leakage | Playbook [llm-application-compromise](../playbooks/llm-application-compromise.md) |
| AML.T0068 | LLM Prompt Obfuscation | `PromptInjection_Unicode_Tag_Characters`, `PromptInjection_ZeroWidth_Run` |

## How to use this mapping

- **Risk assessment**: for each LLM application or agent, go down both OWASP lists, mark which risks apply, and record the control in place, or the gap.
- **Detection coverage**: the "Detection in this repository" column shows what you can deploy today. Entries marked as process or architecture controls need design work rather than a rule.
- **Incident classification**: tag AI incidents with the ATLAS technique as well as the ATT&CK technique, so that AI-specific trends show up in reporting.
