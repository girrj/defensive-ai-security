#!/usr/bin/env bash
# Load the rules, replay a synthetic pcap, and compare alerts against expectations.
# Usage: detections/suricata/tests/run_tests.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RULES="$HERE/../blue-team.rules"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/suricata.yaml" <<'EOF'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,192.168.0.0/16,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types: [alert]
app-layer:
  protocols:
    tls: {enabled: yes, detection-ports: {dp: 443}}
    dns: {tcp: {enabled: yes}, udp: {enabled: yes}}
    smb: {enabled: yes}
    http: {enabled: yes}
stream:
  midstream: false
EOF

python3 "$HERE/make_pcap.py" "$WORK/test.pcap" > "$WORK/expected.json"

suricata -T -c "$WORK/suricata.yaml" -S "$RULES" -l "$WORK" >/dev/null
suricata -c "$WORK/suricata.yaml" -S "$RULES" -r "$WORK/test.pcap" -l "$WORK" -k none >/dev/null 2>&1

python3 - "$WORK/expected.json" "$WORK/eve.json" <<'EOF'
import json, sys
from collections import defaultdict
expected = json.load(open(sys.argv[1]))
by_port = defaultdict(set)
for line in open(sys.argv[2]):
    ev = json.loads(line)
    if ev.get("event_type") != "alert":
        continue
    for port in (ev.get("src_port"), ev.get("dest_port")):
        by_port[port].add(ev["alert"]["signature_id"])
fail = 0
for name, spec in expected.items():
    fired = set().union(*(by_port.get(p, set()) for p in spec["ports"])) if spec["ports"] else set()
    want = set(spec["sids"])
    ok = fired == want
    fail += not ok
    detail = "" if ok else f"  -> fired {sorted(fired)}, missing {sorted(want - fired)}, unexpected {sorted(fired - want)}"
    print(f"{'ok  ' if ok else 'FAIL'} {name}: expected {spec['sids'] or 'no alerts'}{detail}")
print("PASS" if not fail else f"FAILED ({fail} scenario(s))")
sys.exit(1 if fail else 0)
EOF
