# Playbook: LLM application or agent compromise

**Covers:** prompt injection that made an LLM application or agent leak data, take unintended actions, or mislead users. This includes poisoned RAG content, malicious tool or MCP responses, and abuse of exposed model servers. For harmful actions by AI coding agents on developer machines, see [ai-coding-agent-incident.md](ai-coding-agent-incident.md).

**Triggers:** user reports ("the assistant sent me someone else's data", "it emailed a stranger"), guardrail or moderation alerts, `prompt_injection.yar` hits during ingestion, Suricata 9100100–9100105 or WAF 1009120–1009124 alerts, unusual token use or tool-call volume in gateway logs.

## 1. Triage

Answer four questions quickly:

| Question | Where to look |
| --- | --- |
| **What did the system do?** Which responses, actions, and tool calls | Gateway / prompt-response logs, tool-call logs, agent transcripts |
| **What made it do that?** The text that steered it | The context window for those requests: user input, retrieved documents, tool outputs, memory entries |
| **What could it reach?** | The agent's tools, credentials, data sources, and permissions |
| **Is it still happening?** | Recent requests with the same pattern, the poisoned content still in the index or memory, the same user or API key |

### Correlate agent actions (에이전트 행위 상관분석)

- For each suspected state-changing call, use the run ID (실행 ID) and tool-call ID (도구 호출 ID) to join the orchestration trace, authorization and approval records, and the downstream service audit event. Record the agent's service identity (서비스 계정 ID), model or workflow version, and UTC timestamp.
- Record what the agent requested, what the policy allowed, and the outcome the downstream service actually recorded. Mark the outcome unknown if the audit evidence is missing. Preserve the original records in restricted case storage and use redacted working copies for analysis.

### Classify the event (사고 분류)

| Type | Typical evidence | ATLAS / OWASP |
| --- | --- | --- |
| Direct prompt injection by a user | Malicious instructions in that user's own input | AML.T0051.000, LLM01 |
| Indirect injection via content | Instructions inside a retrieved document, email, web page, or tool output | AML.T0051.001, LLM01 / ASI01 |
| Data leakage | Responses containing data the caller shouldn't see | AML.T0057, LLM02 |
| Tool or agent abuse | Tool calls the user didn't ask for: sending, deleting, purchasing, modifying | AML.T0053, LLM03 / ASI02 |
| Memory or RAG poisoning | The same bad behavior recurring across sessions and users | ASI06, LLM09 |
| Exposed model server abused | External source IPs on inference or management endpoints | AML.T0040, LLM06 |

## 2. Contain

| Situation | Containment |
| --- | --- |
| Agent taking harmful actions | Disable the affected tools, or switch the agent to read-only. Revoke the tokens and credentials the agent holds |
| Poisoned content in RAG or memory | Remove or quarantine the source documents and memory entries, then re-index. Block the source (sender, site, upload account) |
| Data leaking to users | Turn off the affected retrieval source, or the feature. Fix access control at retrieval, not in the prompt |
| Exposed model server | Bind it to localhost or firewall it, rotate any keys it held, and check for models pulled or created by outsiders |
| Malicious MCP server or plugin | Remove it fleet-wide and rotate everything it could reach (see the [MCP checklist](../ai-security/mcp-security-checklist.md)) |

Preserve logs, transcripts, and the poisoned content **before** you delete anything from indexes or memory. Export first, then remove.

### Verify scoped revocation (범위 제한 권한 회수 검증)

1. Identify the affected service identity, delegated sessions, and downstream permissions. Pause new runs on the affected workflow and revoke the smallest authorization scope that stops the harmful action. Invalidate affected sessions and cancel pending actions where supported.
2. Confirm the revocation in the downstream service's audit records. Use a harmless permission check with a test identity or a read-only policy evaluation, and check for successful actions by the affected identity after the recorded cutoff. If actions continue or verification is unavailable, keep the workflow paused and escalate to the service owner for connector isolation.

## 3. Scope

- Search all prompts, retrieved chunks, and tool outputs for the injection text, or for distinctive strings from it, across every application that shares the same index, mailbox, or tool.
- Run `detections/yara/prompt_injection.yar` across the document stores the application retrieves from.
- List every tool call made by the affected agent identity during the exposure window, and review each one that changed state.
- For data leakage: work out which records were returned, to whom, and whether personal data was involved. That decides the legal reporting clock (see the [IR manual §5](../ir-manual/README.md#5-legal-and-regulatory-reporting-korea)).

## 4. Eradicate and recover

- Remove the poisoned content at its source, not only in the index.
- Fix the root cause in **architecture**, not only in the system prompt:
  - separate untrusted content from instructions (mark it as quoted data, and don't let it trigger tools),
  - require human approval for state-changing tools,
  - narrow tool permissions and credentials,
  - enforce authorization at the data layer.
- Add the attack to your regression tests (see `llm-guidelines/eval/`) so a later model or prompt change can't reopen it.
- Re-enable features step by step, with extra monitoring of tool calls and responses.

## 5. Lessons learned

- Which control would have stopped it: content scanning, approval, tool scoping, or access control at retrieval?
- Were prompts, retrieval, and tool calls logged well enough to reconstruct what happened? If not, that's the first corrective action.
- Update the threat model in [threat-mapping.md](../ai-security/threat-mapping.md) for the affected application.

## References (참고 자료)

- [NIST IR 8621, NIST Workshop on SI Incident Management](https://csrc.nist.gov/pubs/ir/8621/final), sections 4.1–4.3 (checked 2026-11-28). The steps above adapt workshop findings on evidence traceability and agent authorization to this playbook.
