# Suricata (IDS/IPS) rules

`blue-team.rules`: 31 rules (30 alerting rules and 1 flowbit setter) in SID range 9100001–9100999.

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
| 9100060 | WebLogic `wls-wsat` XMLDecoder payload (CVE-2017-10271) | T1190 | High |
| 9100061 | POST to Oracle EBS `/OA_HTML/configurator/UiServlet` | T1190 | Medium |
| 9100062 | POST to Oracle EBS `/OA_HTML/SyncServlet` (CVE-2025-61882 chain) | T1190 | Medium |
| 9100070 | BPFDoor TCP magic packet (`0x5293`) | T1205.002 | Medium |
| 9100071 | BPFDoor UDP magic packet (`0x7255`) | T1205.002 | Medium |
| 9100072 | BPFDoor ICMP echo magic packet (`0x7255`) | T1205.002 | Medium |
| 9100100 | External access to the Ollama API (port 11434) | AML.T0040 | High |
| 9100101 | External model pull, create, delete, copy, or push (model tampering) | AML.T0010 | High |
| 9100102 | External model enumeration (`/v1/models`, `/api/tags`) | AML.T0040, T1595 | Medium |
| 9100103 | Unauthenticated external completion request (OpenAI-compatible API) | AML.T0040 | Medium |
| 9100104 | Model inventory returned to an external client | AML.T0040 | High |
| 9100105 | One source scanning several hosts for LLM endpoints | T1595.002 | Medium |

Each rule's `metadata` carries `confidence`, which lets you route alerts. A common setup: High pages the analyst, Medium goes to the queue, Low is hunting-only.

## Tests

`tests/run_tests.sh` builds a synthetic pcap (scapy, documentation-range IPs, harmless placeholder payloads), replays it through Suricata, and checks the alerts **per scenario**: each scenario's sessions must raise exactly the expected SIDs, no fewer and no more. Benign control sessions (a normal web request, normal TLS, an *authenticated* LLM API call) must raise nothing.

```bash
pip install scapy
detections/suricata/tests/run_tests.sh
```

Covered by replay tests: 9100001–05, 10–12, 20–22, 30–32, 41, 60–62, 70–72, 100–105. The rest are syntax-validated only. Their thresholds (9100040) and size conditions (9100042) are better tuned against your own traffic.

## Deployment notes

- Set `HOME_NET` correctly. Several rules depend on direction.
- 9100011, 9100012, and 9100022 inspect response bodies. Check that `http.response-body.limit` in `suricata.yaml` is large enough.
- 9100060–62 and 9100070–72 come from the Korean incident cases in [`threat-intel/korea-incidents/`](../../threat-intel/korea-incidents/). The BPFDoor rules use packet-level (`tcp-pkt`) matching because BPFDoor reads raw packets with a BPF filter and never needs an established session.
- In IPS mode, change `alert` to `drop` only for High-confidence rules, and only after a week of review.
