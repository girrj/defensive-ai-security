# Hardening self-hosted LLM infrastructure

Self-hosted model servers are a new class of internet-exposed service, and most of them ship **without authentication**. Internet-wide scanning for them is routine. An exposed server can be used for free inference, made to pull or replace models, or used to read whatever the model has access to.

## 1. Inference servers

| Control | Why | Check |
| --- | --- | --- |
| Bind to localhost or a private interface only | Ollama, llama.cpp `llama-server`, vLLM, and LocalAI accept unauthenticated requests by default | Sigma `llm_server_bound_to_all_interfaces`. On Linux, `ss -lntp | grep -E '11434|8000|8080'`, and check that the address isn't `0.0.0.0` or `*` |
| Put an authenticating reverse proxy in front | Adds API keys or OIDC, TLS, logging, and request limits | WAF rules 1009120–1009124 assume this proxy |
| Block model management endpoints at the proxy | `pull`, `create`, `delete`, `copy`, and `push` let an outsider replace a model | WAF 1009120, Suricata 9100101 |
| Restrict outbound traffic from model hosts | A compromised model server shouldn't be able to reach the internet freely | Egress firewall: allow only the model registry and update mirrors |
| Run as an unprivileged user, in a container with read-only model volumes | Limits what code execution in the serving stack can do | |
| Watch for external access | | Suricata 9100100–9100105 |

Quick external exposure check, run from outside your network against your own address ranges only:

```bash
# Ollama
curl -s --max-time 5 http://<your-public-ip>:11434/api/tags
# OpenAI-compatible servers
curl -s --max-time 5 http://<your-public-ip>:8000/v1/models
```

Any JSON response with model names means the server is exposed.

## 2. Model file supply chain

| Control | Why |
| --- | --- |
| **Prefer safetensors** over pickle-based formats (`.pt`, `.pth`, `.bin`, `.pkl`, `.joblib`) | Loading a pickle runs code. Safetensors only stores tensors |
| Scan every pickle-based model before it is loaded | `detections/yara/malicious_model_pickle.yar`, plus a dedicated scanner such as picklescan, modelscan, or fickling |
| Load models from an internal registry, not straight from public hubs | One place to scan, approve, and pin |
| Pin by hash and verify on load | Stops a model being silently replaced upstream or in storage |
| Use `torch.load(..., weights_only=True)` where pickle can't be avoided | Restricts unpickling to tensor data |

```bash
# Sweep a model directory with the YARA rules from this repository
yara -r -s detections/yara/malicious_model_pickle.yar /models/
```

## 3. LLM gateway and logging

Route all model traffic, both to hosted APIs and to self-hosted servers, through one gateway or proxy:

| Log field | Use |
| --- | --- |
| Caller identity (user, service, API key ID) | Attribution and anomaly detection per caller |
| Model, token counts, latency | Cost abuse, unbounded consumption |
| Prompt and response, or hashes plus samples, per your data policy | Investigating prompt injection and data leakage |
| Tool calls with arguments and results | Investigating agents. This is the most valuable log in an agent incident |
| Moderation or guardrail verdicts | Trending attempted attacks |

Ship these logs to the SIEM like any other security log, and set retention before you need it.

Hunting ideas once the logs are in the SIEM:
- Callers whose token use jumps by more than 10× compared with their 7-day baseline.
- Requests whose prompts match the patterns in `prompt_injection.yar`.
- Tool calls that touch credentials, send outbound HTTP, or delete data, grouped by agent identity.
- Responses that contain secrets patterns (keys, tokens) or large blocks of personal data.

## 4. RAG and memory stores

- Scan documents with `prompt_injection.yar` **before** they are embedded, and quarantine any hits for review.
- Keep a separate index per tenant or sensitivity level, and enforce access control at retrieval time, not only in the UI.
- Record the source of every chunk (document, owner, ingestion time) so poisoned content can be found and removed during an incident.
