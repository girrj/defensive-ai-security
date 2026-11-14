# NDR: network detection and hunting

Network detection sees what endpoint agents can't: unmanaged devices, appliances, and hosts where the EDR was disabled. It also gives an independent record that an attacker on the endpoint can't tamper with.

## Contents

| Item | Purpose |
| --- | --- |
| [`zeek_hunt.py`](zeek_hunt.py) | Hunts over Zeek logs: **beaconing** (regular C2 check-ins) and **DNS tunneling** (high-entropy subdomain floods) |
| [`../detections/suricata/`](../detections/suricata/) | Signature-based IDS rules |
| [hunting guide](#hunting-guide) | What to look for, by technique |

## zeek_hunt.py

Standard library only. Reads Zeek TSV or JSON logs, or stdin.

```bash
# Beaconing: src→dst:port pairs with regular intervals
python3 ndr/zeek_hunt.py beacon conn.log --min-conns 20 --allowlist known-good-ips.txt

# DNS tunneling: parent domains with many long, random-looking subdomains
python3 ndr/zeek_hunt.py dns dns.log --allowlist cdn-domains.txt --format json

# A day of rotated logs
zcat /opt/zeek/logs/2026-11-14/conn.*.log.gz | python3 ndr/zeek_hunt.py beacon -
```

### How beacon scoring works

For each `(src, dst, port, proto)`:

1. Sort the connection timestamps and compute the intervals between them.
2. Trim the 10% most extreme intervals on each side, so a jittering implant or a missed check-in doesn't hide.
3. **Interval coefficient of variation** (stdev / mean): a value near 0 means the connections run like clockwork. Pairs above `--max-cv` (default 0.25) are dropped.
4. **Score from 0 to 100**: interval regularity (60), regularity of bytes sent (25), number of connections (15).

Expect hits from NTP, update checks, monitoring agents, and telemetry. Build an allowlist from your first run, then hunt in the residue.

### How DNS scoring works

Queries are grouped by parent domain, with `.co.kr`-style suffixes handled. A domain becomes a candidate when it has many unique subdomains (≥ 50), a long average label (≥ 20 characters), and high Shannon entropy (≥ 3.5 bits per character). CDNs produce many subdomains, but they are short and low-entropy, so they don't qualify.

Tests: `python3 -m unittest discover -s ndr/tests` (synthetic logs, documentation-range IPs).

## Hunting guide

| Technique | Data | What to look for |
| --- | --- | --- |
| C2 beaconing (T1071) | conn.log | Regular intervals to one destination, especially rare destinations or newly registered domains. See `zeek_hunt.py beacon`. |
| DNS tunneling (T1071.004) | dns.log | High-entropy subdomains, TXT or NULL query spikes, one client sending thousands of queries to one parent domain. See `zeek_hunt.py dns`. |
| Exfiltration (T1041, T1567) | conn.log | `orig_bytes` far larger than `resp_bytes` to an external host, uploads to file-sharing services, transfers outside business hours |
| Lateral movement (T1021) | conn.log, smb_files.log | Workstation-to-workstation SMB, RDP, or WinRM; writes to `ADMIN$` and `C$`; one source touching many hosts in minutes |
| Scanning (T1046) | conn.log | One internal source hitting many ports or hosts with `conn_state` REJ or S0 |
| TLS anomalies | ssl.log, x509.log | Self-signed certificates on external services, certificates valid for only a few days, SNI that doesn't match the certificate, JA3/JA4 fingerprints of known tools |
| Cleartext credentials | http.log, ftp.log | Basic auth or FTP `PASS` over the internet |
| Cryptomining (T1496) | conn.log, dns.log | Stratum ports (3333, 4444, 5555, 14444), mining-pool domains. See the Suricata SIDs 9100030–32. |

## Deployment notes

- Sensor placement: the internet egress, the server segment, and the boundary between user and server networks. East-west visibility is what catches lateral movement.
- Keep at least 30 days of Zeek logs. Most intrusions are found weeks after initial access.
- Encrypted traffic is still useful. Timing, volume, SNI, certificates, and JA3/JA4 fingerprints survive TLS.
