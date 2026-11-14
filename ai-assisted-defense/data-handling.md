# Data handling when using LLMs for security work

## Classification

| Data | Hosted model with an enterprise data agreement (no training, retention controls) | Public consumer chat | Local / self-hosted model |
| --- | --- | --- | --- |
| Public advisories, CVE text, vendor documentation | ✅ | ✅ | ✅ |
| Detection rules and queries (no environment details) | ✅ | ✅ | ✅ |
| Alert or log samples **after sanitization** | ✅ | ❌ | ✅ |
| Raw logs with internal hostnames, IPs, or usernames | ⚠️ only if policy allows | ❌ | ✅ |
| Malware samples or memory dumps | ❌ (upload hashes or extracted strings instead) | ❌ | ✅ in an isolated analysis environment |
| Credentials, keys, session tokens | ❌ never | ❌ never | ❌ never |
| Personal data (customer records, HR data) | ❌ unless DPO-approved | ❌ | ⚠️ minimize |
| Customer or tenant data in a managed-service context | ❌ unless the contract allows it | ❌ | ⚠️ per contract |

## Sanitization before sharing

Replace each value with a **stable placeholder**, so the model can still see that two events involve the same host or user:

| Original | Placeholder |
| --- | --- |
| Internal hostnames | `HOST-A`, `HOST-B` |
| Internal IPs | `10.0.0.A`, `10.0.0.B` (keep the internal/external distinction) |
| Usernames | `USER-1`, `SVC-1` (keep the human/service distinction) |
| Company and customer names, internal domains | `ORG`, `corp.example` |
| Case and ticket numbers | `CASE-1` |

Keep external attacker indicators (public IPs, domains, hashes) as they are. They are what the analysis is about. Defang them if the output will be emailed.

Keep the mapping table locally and never paste it into the same conversation.

## Retention

- Turn off model-provider history or training settings for security work where the platform allows it.
- Store AI-assisted analysis with the case, labeled as AI-assisted, so a reviewer knows which parts to verify.
