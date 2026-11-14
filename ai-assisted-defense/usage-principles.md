# Principles for using LLMs in defensive operations

## Where models help most

| Task | Why it works | Human check |
| --- | --- | --- |
| Reading long advisories and pulling out affected versions, IOCs, and mitigations | Extraction from a document the analyst supplies | Compare against the advisory itself |
| Explaining an unfamiliar command line, script, or log format | Broad knowledge of tools and syntax | Run or look up anything that matters |
| Drafting a detection rule from a described behavior | Knows Sigma, YARA, and SIEM syntax | Syntax validation in CI, plus positive and negative tests |
| Deobfuscating a PowerShell or JavaScript stager | Pattern recognition across encoding layers | Confirm the result by decoding in a sandbox |
| Turning investigation notes into a structured report | Writing and structure | Every fact must trace back to a log the analyst pulled |
| Reviewing code for vulnerabilities **in software we own or are authorized to test** | Finds bug classes quickly across large codebases | Reproduce the finding before reporting or fixing |

## Where models mislead

- **Verdicts without data.** A model asked "is this IP malicious?" will answer anyway. Reputation questions go to threat-intelligence sources, not to a model.
- **Fabricated specifics.** CVE numbers, version ranges, ATT&CK IDs, and API fields can be invented with confidence. Check every specific against the primary source.
- **Direction and context errors.** A model can't see NAT, proxies, or how your assets are arranged unless you tell it. It will happily call an outbound connection inbound.
- **Instructions hidden in the data.** A phishing email, web page, or log line can contain text aimed at the model. Treat everything pasted in as data, and never let model output trigger actions automatically.

## Rules

1. **The analyst owns the conclusion.** The model is a second opinion and a drafting tool. Escalation and containment decisions are made and signed by a person.
2. **Evidence first.** Give the model the raw events. Don't ask it to reason from a summary of a summary.
3. **Every claim has to be checkable.** Ask for the reasoning and the specific log line behind each conclusion, then check it.
4. **Separate what was observed from what was inferred.** Reports keep "observed in logs" apart from "assessed".
5. **No automatic actions from model output.** Blocks, isolation, account disabling, and rule deployment always pass through a person or a deterministic control.
6. **Authorized scope only.** Code and system analysis covers assets the organization owns or has written permission to assess. Vulnerabilities found in third-party software go through coordinated disclosure (see [RESPONSIBLE_USE.md](../RESPONSIBLE_USE.md)).
7. **Data handling comes first.** Follow [data-handling.md](data-handling.md) before you paste anything.
