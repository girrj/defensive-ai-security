# Automated and AI-assisted attack traffic (자동화·AI 활용 공격)

## Definition (정의)

Automated and AI-assisted attack traffic (자동화·AI 활용 공격) is high-volume or adaptive probing that may use automation; AI involvement requires separate evidence.

## Why it matters

Attribution to AI from timing or volume alone is unreliable, while the traffic can still overwhelm detection and response.

## How to do it / what to check

Baseline request and login rates, apply rate limits, inspect authorization and API paths, cluster requests by behavior and preserve evidence before making claims about tooling.

## In this repository

[README.md](../../detections/waf/README.md) provides a related defensive procedure or detection.

## Seen in (Korean cases)

No direct example is documented in the current Korean case set; apply the control to local risk.

## References

- [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
