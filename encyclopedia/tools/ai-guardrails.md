# LLM guardrails and AI security tooling (AI 가드레일)

## Definition (정의)

LLM guardrails and AI security tooling (AI 가드레일) enforce application-level checks around model inputs, outputs and tool actions.

## Why it matters

A model response alone cannot authorize a tool call or protect hidden data.

## How to do it / what to check

Validate tenant and user permissions server-side, isolate untrusted retrieved text, bound tool scope and resource use, log decisions and test authorized adversarial cases.

## In this repository

[mcp-security-checklist.md](../../ai-security/mcp-security-checklist.md) provides a related guide, rule or workflow.

## Seen in (Korean cases)

No direct example is documented in the current Korean case set; this is a preventive control category.

## References

- [OWASP LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
