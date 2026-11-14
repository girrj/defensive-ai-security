# Open-source defensive tools for AI systems

A blue-team view of the open-source tooling for securing LLM applications, agents, and model infrastructure, grouped by where each tool sits. Descriptions are written for SOC and security engineering use: what the tool gives a defender, and where it fits.

> Being listed here isn't an endorsement, and these tools haven't been tested as part of this repository. Many projects are young: check maintenance status, license, and data flows before you deploy any of them, especially anything that sees prompts or credentials.

## Input and output guardrails

| Tool | What it gives a defender |
| --- | --- |
| [NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) | Programmable rules around a conversational app: topic limits, jailbreak checks, and output moderation, defined in configuration |
| [Guardrails AI](https://github.com/guardrails-ai/guardrails) | Validates model output against a schema and checks. Useful where output feeds other systems (LLM10) |
| [LLM Guard](https://github.com/protectai/llm-guard) | A set of input and output scanners: injection, secrets, PII, toxicity. Can run as a library or a service in front of the model |
| [LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) | Guardrail framework aimed at agents: checks inputs and multi-step agent behavior, plus scanning of generated code |
| [Llama Guard](https://github.com/meta-llama/PurpleLlama/tree/main/Llama-Guard) | Safety classifier models for screening prompts and responses |
| [Llama Prompt Guard 2 (86M)](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) | Small classifier for prompt injection and jailbreak attempts. Cheap enough to run on every input |
| [DeBERTa prompt-injection v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) | Prompt-injection classifier that is widely used as a building block in guardrail pipelines |
| [Vigil](https://github.com/deadbits/vigil-llm) | Injection detection that combines YARA signatures, vector similarity, and canary tokens. A useful model for layering detections |
| [Rebuff](https://github.com/protectai/rebuff) | Multi-layer injection detector with canary tokens (archived, but useful as a design reference) |
| [Presidio](https://github.com/microsoft/presidio) | PII detection and anonymization. Redact data before it reaches a prompt or a log |

## Gateways and monitoring

| Tool | What it gives a defender |
| --- | --- |
| [LiteLLM](https://github.com/BerriAI/litellm) | One proxy in front of many model providers, with keys, budgets, rate limits, and logging. A natural place to enforce policy and collect logs for the SIEM |
| [LangKit](https://github.com/whylabs/langkit) | Extracts monitoring signals from prompts and responses (injection similarity, PII, sentiment) for dashboards and alerts |
| [Alibi Detect](https://github.com/SeldonIO/alibi-detect) | Drift, outlier, and adversarial-input detection for production models |

## Agent runtime: sandboxing, policy, and credentials

| Tool | What it gives a defender |
| --- | --- |
| [E2B](https://github.com/e2b-dev/E2B) | Disposable microVM sandboxes for running code an agent generates |
| [microsandbox](https://github.com/superradcompany/microsandbox) | Self-hosted microVM sandbox for untrusted code |
| [OpenShell](https://github.com/NVIDIA/OpenShell) | Runtime that enforces declarative policy on what an agent can touch: files, network, data |
| [OpenSandbox](https://github.com/opensandbox-group/OpenSandbox) | Sandbox runtime for agents with pluggable isolation backends |
| [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) | Policy enforcement, identity, and sandboxing for autonomous agents, organized around the OWASP agentic risks |
| [OneCLI](https://github.com/onecli/onecli) | Credential gateway with a vault, so agents use services without ever holding the raw keys (ASI03) |
| [Aegis](https://github.com/antropos17/Aegis) | EDR-style monitoring of AI agent processes, files, and network activity |
| [numbat](https://github.com/perplexityai/numbat) | Visibility into agent activity, with local detection, optional blocking, and forensic reconstruction |
| [claude-code-safety-net](https://github.com/kenryu42/claude-code-safety-net) | Pre-execution hook that blocks destructive commands from coding agents |

## MCP and agent supply chain

| Tool | What it gives a defender |
| --- | --- |
| [mcp-context-protector](https://github.com/trailofbits/mcp-context-protector) | Wrapper that guards against injection coming from untrusted MCP servers |
| [mcp-guardian](https://github.com/eqtylab/mcp-guardian) | Lets you see and control which MCP servers an assistant uses |
| [mcpproxy-go](https://github.com/smart-mcp-proxy/mcpproxy-go) | Proxy between clients and MCP servers: one place to filter and log |
| [agent-scan](https://github.com/snyk/agent-scan) | Scans agents, MCP servers, and agent skills for security issues |
| [skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | Scans agent skills for injection, exfiltration, and malicious code before installation |
| [Agentic Radar](https://github.com/splx-ai/agentic-radar) | Static analysis of agent workflows (LangChain, CrewAI, and others) for risky patterns |
| [medusa](https://github.com/Pantheon-Security/medusa) | Repository scanner with a large rule set for AI, agent, and MCP code, including poisoning patterns |
| [MCP Security Checklist](https://github.com/slowmist/MCP-Security-Checklist) | Community checklist for MCP deployments. Compare it with [this repository's checklist](mcp-security-checklist.md) |
| [awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security) | Curated MCP attack, defense, and CVE references |

## Model file security

| Tool | What it gives a defender |
| --- | --- |
| [modelscan](https://github.com/protectai/modelscan) | Scans model files across formats for serialization attacks |
| [picklescan](https://github.com/mmaitre314/picklescan) | Finds suspicious imports in pickle files and archives |
| [fickling](https://github.com/trailofbits/fickling) | Decompiles and statically analyzes pickles, so you can see what a model file would run |

Use them together with `detections/yara/malicious_model_pickle.yar` in this repository.

## AI-assisted security operations

| Tool | What it gives a defender |
| --- | --- |
| [claude-code-security-review](https://github.com/anthropics/claude-code-security-review) | GitHub Action that reviews pull requests for security issues using Claude |
| [Vulnhuntr](https://github.com/protectai/vulnhuntr) | LLM-guided analysis that follows call chains across files to find complex vulnerabilities in your own code |
| [Semgrep](https://github.com/semgrep/semgrep) | Rule-based static analysis. Pairs well with LLM triage of its findings |
| [AiSOC](https://github.com/beenuar/AiSOC) | Self-hosted SOC platform experimenting with LLM-agent triage and ATT&CK-based investigation |
| [Shuffle](https://github.com/Shuffle/Shuffle) | Open-source SOAR, which can host AI steps inside response workflows |
| [Wazuh](https://github.com/wazuh/wazuh) | Open-source SIEM/XDR. A common base for adding AI-assisted triage |
| [OpenCTI](https://github.com/OpenCTI-Platform/opencti) | Threat intelligence platform for structuring and sharing indicators and reports |
| [Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules) | A Sigma-like rule format for AI agent threats. Worth watching as a way to share agent detections |
| [AttackGen](https://github.com/mrwadams/attackgen) | Generates incident-response exercise scenarios from ATT&CK and ATLAS |
| [STRIDE GPT](https://github.com/mrwadams/stride-gpt) | LLM-assisted STRIDE threat modeling and attack trees |
| [Beelzebub](https://github.com/beelzebub-labs/beelzebub) | Honeypot framework that uses an LLM to keep attackers engaged, for collecting attacker behavior |
| [Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct) | Open security-specialized model that can be self-hosted for SOC text tasks, so data stays on-premises |

## Testing your own AI systems before attackers do

Scanners for testing AI systems **that you own or are authorized to assess**, to check that the guardrails above actually hold.

| Tool | What it gives a defender |
| --- | --- |
| [garak](https://github.com/NVIDIA/garak) | LLM vulnerability scanner with a wide set of probes (injection, leakage, jailbreaks) for regression testing |
| [PyRIT](https://github.com/Azure/PyRIT) | Framework for automating risk identification against generative AI systems |
| [promptfoo](https://github.com/promptfoo/promptfoo) | Test harness for prompts and models with security test suites. It fits in CI, like [llm-guidelines/eval](../llm-guidelines/eval/) |

---

**Sources.** The tool selection draws on these community-curated lists, with links checked against them and descriptions written independently for a defensive audience:
[8kSec/awesome-ai-security](https://github.com/8kSec/awesome-ai-security),
[iosec-shekhar/awesome-ai-security](https://github.com/iosec-shekhar/awesome-ai-security) (MIT),
[skyvanguard/awesome-ai-pentesting](https://github.com/skyvanguard/awesome-ai-pentesting) (MIT),
[Threekiii/Awesome-AI-Redteam](https://github.com/Threekiii/Awesome-AI-Redteam).
