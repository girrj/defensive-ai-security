# Suricata (IDS/IPS) rules

`blue-team.rules`: 19 rules (18 alerting rules and 1 flowbit setter) in SID range 9100001–9100999.

| SID | Detects | ATT&CK | Confidence |
| --- | --- | --- | --- |
| 9100001–3 | JNDI lookup in the request line or headers, including nested-lookup obfuscation | T1190 | High / Medium |
| 9100004 | Path traversal to sensitive OS files | T1190 | Medium |
| 9100005 | Java class-loader parameter (Spring4Shell-style) | T1190 | High |
| 9100010 | OS command passed to a script page | T1505.003 | Medium |
| 9100011–12 | Command output (Windows `ipconfig`, Unix `id`) in an HTTP response | T1505.003 | Medium / High |
| 9100020–21 | PowerShell or certutil fetching content | T1105 | Low / Medium |
| 9100022 | Windows executable served by a raw-IP host (with flowbit 9100023) | T1105 | Medium |
| 9100030–32 | Stratum mining login or subscribe, and mining-pool DNS | T1496 | High |
| 9100040 | Long, high-rate DNS query names (possible tunneling) | T1071.004 | Medium |
| 9100041 | TLS to dynamic DNS and tunneling services | T1071.001 | Low |
| 9100042 | Large POST to a paste or file-sharing service | T1567 | Medium |
| 9100050 | Write to the ADMIN$ share (PsExec-style lateral movement) | T1021.002 | Low |

Each rule's `metadata` carries `confidence`, which lets you route alerts. A common setup: High pages the analyst, Medium goes to the queue, Low is hunting-only.

## Tests

`tests/run_tests.sh` builds a synthetic pcap (scapy, documentation-range IPs, harmless placeholder payloads), replays it through Suricata, and compares the alerts that fire against the expected SIDs. It also checks that benign control sessions raise no alerts.

```bash
pip install scapy
detections/suricata/tests/run_tests.sh
```

Covered by replay tests: 9100001–05, 10–12, 20–22, 30–32, 41. The rest are syntax-validated only. Their thresholds (9100040) and size conditions (9100042) are better tuned against your own traffic.

## Deployment notes

- Set `HOME_NET` correctly. Several rules depend on direction.
- 9100011, 9100012, and 9100022 inspect response bodies. Check that `http.response-body.limit` in `suricata.yaml` is large enough.
- In IPS mode, change `alert` to `drop` only for High-confidence rules, and only after a week of review.
