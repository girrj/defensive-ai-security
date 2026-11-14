"""Tests for zeek_hunt.py using synthetic Zeek logs (documentation IP ranges, example domains)."""

import base64
import json
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import zeek_hunt  # noqa: E402

rng = random.Random(7)
T0 = 1_760_000_000.0


def conn(ts, src, dst, port, orig_bytes):
    return {"ts": str(ts), "id.orig_h": src, "id.resp_h": dst, "id.resp_p": str(port),
            "proto": "tcp", "orig_bytes": str(orig_bytes)}


def synthetic_conn_rows():
    rows = []
    # Implant: 60s check-in with ±5% jitter and steady ~300-byte requests, 120 times.
    t = T0
    for _ in range(120):
        t += 60 * rng.uniform(0.95, 1.05)
        rows.append(conn(t, "10.1.1.50", "203.0.113.66", 443, rng.randint(290, 310)))
    # One missed check-in must not hide it.
    rows.append(conn(t + 300, "10.1.1.50", "203.0.113.66", 443, 300))
    # Human browsing: irregular timing and sizes.
    t = T0
    for _ in range(120):
        t += rng.expovariate(1 / 90)
        rows.append(conn(t, "10.1.1.51", "198.51.100.20", 443, rng.randint(200, 90000)))
    # Low volume, under min-conns.
    for i in range(5):
        rows.append(conn(T0 + i * 60, "10.1.1.52", "198.51.100.30", 443, 100))
    rng.shuffle(rows)
    return rows


def synthetic_dns_rows():
    rows = []
    # Tunnel: base32-style encoded chunks under one parent domain.
    for i in range(300):
        chunk = base64.b32encode(rng.randbytes(25)).decode().rstrip("=").lower()
        rows.append({"id.orig_h": "10.1.1.60", "query": f"{chunk[:30]}.{chunk[30:]}.{i}.tunnel-c2.example"})
    # CDN-ish: many short, low-entropy subdomains.
    for i in range(300):
        rows.append({"id.orig_h": f"10.1.2.{i % 50}", "query": f"img{i % 80}.static.cdn-provider.example"})
    # Normal browsing.
    for name in ["www.example.com", "mail.example.org", "api.example.net"] * 50:
        rows.append({"id.orig_h": "10.1.1.61", "query": name})
    # Country-code multi-part suffix: parent must be 3 labels.
    rows.append({"id.orig_h": "10.1.1.62", "query": "www.shop.example.co.kr"})
    return rows


class Beaconing(unittest.TestCase):
    def test_finds_implant_only(self):
        res = zeek_hunt.find_beacons(iter(synthetic_conn_rows()), min_conns=10)
        self.assertEqual([(b.src, b.dst) for b in res], [("10.1.1.50", "203.0.113.66")])
        self.assertAlmostEqual(res[0].mean_interval_s, 60, delta=3)
        self.assertGreater(res[0].score, 70)

    def test_allowlist(self):
        res = zeek_hunt.find_beacons(iter(synthetic_conn_rows()), allow_dst={"203.0.113.66"})
        self.assertEqual(res, [])


class DnsTunneling(unittest.TestCase):
    def test_finds_tunnel_not_cdn(self):
        res = zeek_hunt.find_dns_tunnels(iter(synthetic_dns_rows()))
        self.assertEqual([d.domain for d in res], ["tunnel-c2.example"])
        self.assertGreaterEqual(res[0].unique_subdomains, 300)

    def test_parent_domain(self):
        self.assertEqual(zeek_hunt.parent_domain("a.b.example.com"), "example.com")
        self.assertEqual(zeek_hunt.parent_domain("www.shop.example.co.kr"), "example.co.kr")

    def test_entropy(self):
        self.assertEqual(zeek_hunt.shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(zeek_hunt.shannon_entropy("abcd"), 2.0)


class ZeekFormats(unittest.TestCase):
    def test_tsv_and_json(self):
        tsv = ("#separator \\x09\n#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\torig_bytes\n"
               "1.0\t10.0.0.1\t203.0.113.1\t443\ttcp\t-\n")
        js = json.dumps({"ts": 2.0, "id.orig_h": "10.0.0.2"}) + "\n"
        p = Path(__file__).with_name("_tmp.log")
        try:
            p.write_text(tsv)
            rows = list(zeek_hunt.read_zeek(str(p)))
            self.assertEqual(rows[0]["id.resp_h"], "203.0.113.1")
            self.assertIsNone(rows[0]["orig_bytes"])
            p.write_text(js)
            self.assertEqual(list(zeek_hunt.read_zeek(str(p)))[0]["id.orig_h"], "10.0.0.2")
        finally:
            p.unlink()


if __name__ == "__main__":
    unittest.main()
