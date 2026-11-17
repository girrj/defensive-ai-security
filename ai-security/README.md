# Securing AI systems

How to defend LLM applications, AI agents, MCP servers, and self-hosted model infrastructure. The approach is the one a SOC already uses for everything else: inventory, harden, detect, and respond.

| Document | Contents |
| --- | --- |
| [threat-mapping.md](threat-mapping.md) | OWASP Top 10 for LLM Applications **2026**, OWASP Top 10 for Agentic Applications **2026**, and MITRE ATLAS, mapped to the detections and controls in this repository |
| [llm-infrastructure-hardening.md](llm-infrastructure-hardening.md) | Self-hosted model servers (Ollama, vLLM, llama.cpp), model file supply chain, and LLM gateway logging |
| [mcp-security-checklist.md](mcp-security-checklist.md) | Approving, deploying, and monitoring MCP servers |
| [defensive-tools.md](defensive-tools.md) | Open-source defensive tools for AI systems, grouped by where they sit in the stack |
| [../playbooks/llm-application-compromise.md](../playbooks/llm-application-compromise.md) | Incident response for prompt injection, data leakage, and tool abuse in LLM applications |
| [../playbooks/ai-coding-agent-incident.md](../playbooks/ai-coding-agent-incident.md) | Incident response for harmful actions by AI coding agents |

## Detection content for AI systems

| Layer | Rule | Detects |
| --- | --- | --- |
| Network (IDS) | Suricata SIDs 9100100–9100105 | External access to Ollama, model pull or create from outside, model enumeration, unauthenticated completion requests, model inventory leaking in responses, scanning for LLM endpoints |
| Reverse proxy (WAF) | ModSecurity IDs 1009120–1009124 | Model management endpoints reachable through the proxy, unauthenticated inference, prompt-injection phrasing (scored), oversized prompts |
| Endpoint (Sigma) | `mcp_server_spawns_shell_or_recon` | An MCP server process starting shells or recon tools |
| Endpoint (Sigma) | `mcp_server_download_or_credential_access` | An MCP server process downloading payloads or touching credential stores |
| Endpoint (Sigma) | `llm_server_bound_to_all_interfaces` | Local model servers started on 0.0.0.0 |
| Endpoint (Sigma) | `ai_agent_*` (3 rules) | AI coding agents running destructive commands, reading credentials, or tampering with Defender |
| Content (YARA) | `prompt_injection.yar` (5 rules) | Instruction overrides, hidden HTML and CSS instructions, Unicode tag smuggling, zero-width runs |
| Model files (YARA) | `malicious_model_pickle.yar` (3 rules) | Pickle and PyTorch files that reference code-execution callables |
| SIEM (YARA-L) | `ai_agent_destructive_command` | Agent destructive commands correlated per host and user |

CI checks Sigma parsing and Splunk conversion, compiles and sample-tests YARA, replays synthetic Suricata traffic, and sends synthetic requests to a local Apache + ModSecurity instance. YARA-L is reference content with no automated compilation or runtime test in CI. Validate it in Google SecOps before deployment. See the main [README](../README.md#how-everything-is-tested) for scope and limitations (검증 범위·한계).

## Where AI incidents differ from ordinary ones

1. **The attack is often text.** A document, email, web page, or tool response can carry the attack. There may be no exploit and no malware, just instructions the model followed.
2. **The model's identity is borrowed.** Agents act with the permissions of their user or service account, so the damage is bounded by those permissions, not by the attacker's own.
3. **Evidence lives in new places**: prompt and response logs, tool-call logs, agent transcripts, vector stores, memory stores, and gateway logs. Turn on logging for them *before* an incident.
4. **Containment includes the context.** Poisoned documents in a RAG index or poisoned agent memory keep re-triggering the attack until you remove them.
