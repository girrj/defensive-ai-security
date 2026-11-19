# Prompt injection against LLM applications (프롬프트 인젝션)

## Definition (정의)

Prompt injection (프롬프트 인젝션) is an instruction embedded in lower-trust input that tries to redirect an AI application or agent.

## Why it matters

Retrieved documents, pages and tool outputs can cross the trust boundary if treated as system instructions.

## How to do it / what to check

Mark retrieved content as untrusted, isolate tenant data, authorize tools outside the model, require approval for high-impact actions and test direct and indirect cases.

## In this repository

[prompt_injection.yar](../../detections/yara/prompt_injection.yar) provides a related defensive procedure or detection.

## Seen in (Korean cases)

No direct example is documented in the current Korean case set; apply the control to local risk.

## References

- [OWASP LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
