# Glossary: AI system security (AI 시스템 보안)

| Term | 한국어 | Definition | See also |
| --- | --- | --- | --- |
| Prompt injection, direct and indirect | 프롬프트 인젝션 | Untrusted input attempts to redirect an AI system; indirect injection arrives through retrieved or tool-provided content. Treat that content as data. | [Prompt-injection rules](../../detections/yara/prompt_injection.yar) |
| Jailbreak | 탈옥 | An attempt to make a model ignore intended behavior or safety constraints; test impact at the application boundary. | [AI security](../../ai-security/README.md) |
| System prompt leakage | 시스템 프롬프트 노출 | Disclosure of hidden instructions or configuration; never place secrets in prompts. | [MCP checklist](../../ai-security/mcp-security-checklist.md) |
| Excessive agency | 과도한 권한 위임 | A tool-using AI system can take actions beyond the minimum needed; constrain scope and require approval for consequential changes. | [Agent rules](../../llm-guidelines/agent-operating-rules.md) |
| Tool / function calling | 도구 호출 | A structured request by a model for an application-controlled action; validate arguments and authorize every operation server-side. | [MCP checklist](../../ai-security/mcp-security-checklist.md) |
| AI agent | AI 에이전트 | A system that uses a model to plan and invoke tools over multiple steps; monitor identity, tool calls and effects. | [Agent incident playbook](../../playbooks/ai-coding-agent-incident.md) |
| MCP (Model Context Protocol) | 모델 컨텍스트 프로토콜 | A protocol for connecting AI clients to tools and data; server trust and permission boundaries remain the application's responsibility. | [MCP checklist](../../ai-security/mcp-security-checklist.md) |
| RAG | 검색 증강 생성 | Retrieval supplies external context to a model; retrieved content is untrusted and needs provenance and access control. | [Data handling](../../ai-assisted-defense/data-handling.md) |
| Vector and embedding weaknesses | 벡터·임베딩 취약점 | Retrieval may expose unauthorized content or rank poisoned material; test tenant separation and source validity. | [AI security](../../ai-security/README.md) |
| Model supply chain | 모델 공급망 | The provenance and integrity of model files, dependencies and deployment artifacts. | [Model hardening](../../ai-security/llm-infrastructure-hardening.md) |
| Pickle vs safetensors | 피클·세이프텐서스 | Pickle loading can execute code; safetensors stores tensor data without that executable deserialization behavior. Verify trusted source and integrity either way. | [Model-file rule](../../detections/yara/malicious_model_pickle.yar) |
| Data and model poisoning | 데이터·모델 오염 | Malicious changes to training, fine-tuning or retrieval data that distort outputs or behavior. | [AI security](../../ai-security/README.md) |
| Unbounded consumption | 무제한 자원 소비 | Lack of quotas or limits lets AI requests consume excessive compute, tokens or tool capacity. | [Infrastructure hardening](../../ai-security/llm-infrastructure-hardening.md) |
| Guardrails | 가드레일 | Application controls that validate inputs, outputs and actions; test them with real workflows and failure cases. | [AI security](../../ai-security/README.md) |
| AI red teaming | AI 레드팀 | Authorized testing of AI system failure modes with documented scope and safe test data. | [Evaluation harness](../../llm-guidelines/eval/run_eval.py) |
| Human-in-the-loop approval | 사람 승인 | A decision gate before a consequential action, with enough context for a person to assess and reject it. | [Agent rules](../../llm-guidelines/agent-operating-rules.md) |
| OWASP LLM Top 10 2026 | OWASP LLM 상위 10대 위험 | OWASP's 2026 risk guide for LLM applications; map each relevant risk to controls and tests, not a compliance score. | [Threat mapping](../../ai-security/threat-mapping.md) |
| OWASP Agentic Top 10 2026 | OWASP 에이전트 상위 10대 위험 | OWASP's agentic risk guide for tool-using systems and delegated actions. | [Threat mapping](../../ai-security/threat-mapping.md) |
| MITRE ATLAS | MITRE 인공지능 위협 지식베이스 | A knowledge base of adversarial AI tactics and techniques for threat modeling and detection planning. | [Threat mapping](../../ai-security/threat-mapping.md) |

## References

- [OWASP LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
- [OWASP Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [Model Context Protocol specification](https://modelcontextprotocol.io/specification/)
