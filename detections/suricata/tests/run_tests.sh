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
expected = json.load(open(sys.argv[1]))
fired = {json.loads(l)["alert"]["signature_id"] for l in open(sys.argv[2]) if '"alert"' in l}
want = {sid for sids in expected.values() for sid in sids}
missing, unexpected = sorted(want - fired), sorted(fired - want)
for name, sids in expected.items():
    status = "ok  " if set(sids) <= fired else "FAIL"
    print(f"{status} {name}: expected {sids or 'no alerts'}")
print(f"\nfired: {sorted(fired)}")
if missing or unexpected:
    print(f"missing: {missing}  unexpected: {unexpected}")
    sys.exit(1)
print("PASS")
EOF
