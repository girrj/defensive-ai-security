# WAF rules (ModSecurity, alongside OWASP CRS)

`modsecurity/blue-team-waf.conf`: 9 targeted rules (IDs 1009101–1009109) meant to run **with** the OWASP Core Rule Set, not instead of it. CRS provides broad generic coverage. These rules add high-confidence blocks for patterns seen in real incidents and response-side inspection.

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

Rule 1009109 is the safety net. It catches a web shell that was planted before these rules existed, at the moment it returns output.

## Tests

`tests/run_tests.sh` starts a throwaway Apache + ModSecurity 2 instance on localhost, sends 13 attack requests and 3 benign ones, and checks the HTTP status and the rule ID in the log for each.

```bash
sudo apt-get install apache2 libapache2-mod-security2
detections/waf/tests/run_tests.sh
```

## Rollout

1. Deploy with `SecRuleEngine DetectionOnly` for at least a week.
2. Review audit log hits per rule. For each false positive, add a narrow exclusion (`ctl:ruleRemoveTargetById` for a single parameter on a single path), never a global disable.
3. Switch to `On` one rule at a time, starting with 1009101, 1009103, and 1009106.

The same logic carries over to cloud WAFs. Port it into custom rules with the same IDs in the description, so alerts can be traced back to this file.
