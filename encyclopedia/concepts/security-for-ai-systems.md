# Securing AI systems in operation (AI 시스템 운영 보안)

## Definition (정의)

AI system security (AI 시스템 운영 보안) protects models, retrieval data, tools, identities and infrastructure during operation.

## Why it matters

Untrusted content can steer tool use, while broad permissions can turn one model error into a consequential action.

## How to do it / what to check

Enforce tool authorization server-side, isolate retrieval by tenant, verify model provenance, bound resource use, log actions and require human approval for high-impact changes.

## In this repository

[mcp-security-checklist.md](../../ai-security/mcp-security-checklist.md) is the related procedure or implementation.

## Seen in (Korean cases)

No direct example is documented in the current Korean case set; use the linked controls as a general practice.

## References

- [OWASP LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
