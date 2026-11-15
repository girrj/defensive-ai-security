# WAF rules (ModSecurity, alongside OWASP CRS)

`modsecurity/blue-team-waf.conf`: 19 targeted rules (IDs 1009101–1009109, 1009120–1009124 and 1009130–1009134) meant to run **with** the OWASP Core Rule Set, not instead of it. CRS provides broad generic coverage. These rules add high-confidence blocks for patterns seen in real incidents and response-side inspection.

| ID | Detects | Action |
| --- | --- | --- |
| 1009101 | JNDI lookup expressions anywhere in the request, including nested-lookup obfuscation | Deny 403 |
| 1009102 | Java class-loader binding parameters | Deny 403 |
| 1009103 | Upload of a server-side script, including double extensions and null-byte tricks | Deny 403 |
| 1009104 | OS command passed as a parameter to a script page | Anomaly score |
| 1009105 | Path traversal to sensitive files | Deny 403 |
| 1009106 | `.git`, `.env`, `WEB-INF`, and backup or archive files | Deny 404 |
| 1009107 | Scanner user agents | Log + anomaly score |
| 1009108 | Cloud metadata addresses in parameters (SSRF) | Deny 403 |
| 1009109 | Command output or `/etc/passwd` content in a **response** | Deny 500 |
| 1009120 | LLM model management endpoints (`/api/pull`, `create`, `delete`, …) through the proxy | Deny 403 |
| 1009121 | LLM inference or model-list request without an `Authorization` header | Deny 401 |
| 1009122 | Prompt-injection phrasing in LLM API requests | Log + anomaly score |
| 1009123 | Oversized request body to an LLM endpoint (> 2 MB, tune it) | Deny 413 |
| 1009124 | Helper: exposes JSON bodies of LLM requests as `REQUEST_BODY` (`ctl:forceRequestBodyVariable`) | — |
| 1009130 | Oracle WebLogic `/wls-wsat/` and `/_async/` endpoints (CVE-2017-10271, CVE-2019-2725) | Deny 403 |
| 1009131 | Java XMLDecoder object graph that creates a process, in any request body | Deny 403 |
| 1009132 | Oracle EBS `SyncServlet` and configurator `UiServlet` (CVE-2025-61882 / 61884) | Deny 403 |
| 1009133 | Oracle EBS XDO `TemplatePreviewPG` page | Deny 403 |
| 1009134 | Helper: exposes XML request bodies as `REQUEST_BODY` | — |

Rules 1009130–1009133 come from the [Korean incident cases](../../threat-intel/korea-incidents/). They are virtual patches: deny these paths from the internet and allow-list internal ranges that run legitimate integrations.

Rule 1009109 is the safety net. It catches a web shell that was planted before these rules existed, at the moment it returns output.

## Tests

`tests/run_tests.sh` starts a throwaway Apache + ModSecurity 2 instance on localhost, sends 18 attack requests and 4 benign ones (including an authenticated LLM request), and checks the HTTP status and the rule ID in the log for each.

```bash
sudo apt-get install apache2 libapache2-mod-security2
detections/waf/tests/run_tests.sh
```

## Rollout

1. Deploy with `SecRuleEngine DetectionOnly` for at least a week.
2. Review audit log hits per rule. For each false positive, add a narrow exclusion (`ctl:ruleRemoveTargetById` for a single parameter on a single path), never a global disable.
3. Switch to `On` one rule at a time, starting with 1009101, 1009103, and 1009106.

The same logic carries over to cloud WAFs. Port it into custom rules with the same IDs in the description, so alerts can be traced back to this file.
