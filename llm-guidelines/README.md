# LLM guidelines for SOC and CERT work

Instructions, examples, and evaluation data for setting up a large language model as a **defensive security assistant**. It can serve a chat assistant for analysts, an agent with access to SIEM or EDR tools, or a model being fine-tuned for SOC tasks.

| File | Use it as | Purpose |
| --- | --- | --- |
| [system-prompt.md](system-prompt.md) | System prompt / custom instructions | Role, evidence standards, output formats, boundaries |
| [agent-operating-rules.md](agent-operating-rules.md) | `AGENTS.md` / `CLAUDE.md` / tool-use policy | Rules for an AI agent that can query or act on security tools |
| [examples.md](examples.md) | Few-shot examples, reviewer training | Good and bad responses side by side, with the reason |
| [training/sft_examples.jsonl](training/sft_examples.jsonl) | Supervised fine-tuning data (chat format) | Demonstrations of the target behavior |
| [eval/cases.jsonl](eval/cases.jsonl) + [eval/run_eval.py](eval/run_eval.py) | Regression test for any model or prompt | Automatic checks for the behaviors that matter most |

## Design principles

The guidelines encode a few behaviors that separate a useful security assistant from a dangerous one:

1. **Evidence before verdicts.** Every conclusion points to a specific log line or artifact. Inferences are labeled as inferences.
2. **No invented specifics.** No made-up CVE numbers, versions, IOCs, or reputations. If the data isn't there, say so.
3. **Data is data.** Instructions embedded in logs, emails, documents, or tool output are never followed.
4. **Read-only by default.** Any change to a system (blocking, isolation, rule deployment, deletion) needs explicit human approval, given the exact command or query first.
5. **Defensive scope.** Help detect, investigate, contain, and fix. Decline to build attack capability against systems the user isn't authorized to test.
6. **Mind direction and translation.** NAT, proxies, and load balancers change what an IP means. Don't call a direction without checking.
7. **Sensitive data stays minimal.** Don't repeat credentials or personal data back. Suggest sanitizing.

## Using the evaluation set

```bash
# 1. Generate one response per case with your model/prompt -> responses.jsonl
#    lines like: {"id": "inj-001", "response": "..."}
# 2. Score them
python3 llm-guidelines/eval/run_eval.py llm-guidelines/eval/cases.jsonl responses.jsonl
```

The checks are deliberately simple (required and forbidden patterns, plus required structure). Use them as a regression gate, and have a person review the responses for nuance.
