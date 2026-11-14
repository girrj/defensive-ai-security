#!/usr/bin/env python3
"""Network threat hunting over Zeek logs: beaconing and DNS tunneling.

Reads Zeek conn.log / dns.log in either TSV (default Zeek format) or JSON
(one object per line). Standard library only.

  beacon   Find src->dst:port pairs whose connections recur at regular
           intervals, a pattern typical of C2 implants checking in. Scores
           regularity of intervals (coefficient of variation), regularity of
           bytes sent, and number of connections.

  dns      Find parent domains with many unique, long, high-entropy
           subdomains, a pattern typical of DNS tunneling and DNS-based
           exfiltration.

Examples:
    zeek_hunt.py beacon conn.log --min-conns 20 --top 25
    zeek_hunt.py dns dns.log --format json
    zcat conn.*.log.gz | zeek_hunt.py beacon -
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from typing import Iterator


# ---------------------------------------------------------------------------
# Zeek log reading
# ---------------------------------------------------------------------------

def read_zeek(path: str) -> Iterator[dict]:
    fh = sys.stdin if path == "-" else open(path, encoding="utf-8", errors="replace")
    try:
        yield from _parse_zeek(fh)
    finally:
        if fh is not sys.stdin:
            fh.close()


def _parse_zeek(fh) -> Iterator[dict]:
    fields: list[str] | None = None
    sep = "\t"
    for line in fh:
        line = line.rstrip("\n")
        if not line:
            continue
        if line.startswith("{"):
            yield json.loads(line)
            continue
        if line.startswith("#separator"):
            sep = bytes(line.split(" ", 1)[1], "utf-8").decode("unicode_escape")
            continue
        if line.startswith("#fields"):
            fields = line.split(sep)[1:]
            continue
        if line.startswith("#"):
            continue
        if fields:
            values = line.split(sep)
            yield {k: (None if v in ("-", "(empty)") else v) for k, v in zip(fields, values)}


def _f(v, default=0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Beaconing
# ---------------------------------------------------------------------------

@dataclass
class Beacon:
    src: str
    dst: str
    port: str
    proto: str
    conns: int
    mean_interval_s: float
    interval_cv: float
    bytes_cv: float
    score: float


def _cv(values: list[float]) -> float:
    if len(values) < 2:
        return 1.0
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean > 0 else 1.0


def find_beacons(rows: Iterator[dict], min_conns: int = 10, max_cv: float = 0.25,
                 allow_dst: set[str] | None = None) -> list[Beacon]:
    times: dict[tuple, list[float]] = defaultdict(list)
    sizes: dict[tuple, list[float]] = defaultdict(list)
    for r in rows:
        dst = r.get("id.resp_h") or ""
        if allow_dst and dst in allow_dst:
            continue
        key = (r.get("id.orig_h"), dst, r.get("id.resp_p"), r.get("proto") or "")
        times[key].append(_f(r.get("ts")))
        sizes[key].append(_f(r.get("orig_bytes")))

    out = []
    for key, ts in times.items():
        if len(ts) < min_conns:
            continue
        ts.sort()
        intervals = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
        if len(intervals) < min_conns - 1:
            continue
        # Trim the 10% most extreme intervals on each side: implants jitter and
        # occasionally miss a check-in, and that shouldn't hide them.
        iv = sorted(intervals)
        k = len(iv) // 10
        trimmed = iv[k: len(iv) - k] if len(iv) - 2 * k >= 3 else iv
        icv = _cv(trimmed)
        if icv > max_cv:
            continue
        bcv = _cv(sizes[key])
        # Score 0-100: interval regularity dominates, size regularity and
        # volume add confidence.
        score = (1 - min(icv / max_cv, 1)) * 60 + (1 - min(bcv, 1)) * 25 + min(len(ts) / 100, 1) * 15
        src, dst, port, proto = key
        out.append(Beacon(src, dst, port, proto, len(ts), round(statistics.fmean(trimmed), 2),
                          round(icv, 3), round(bcv, 3), round(score, 1)))
    return sorted(out, key=lambda b: -b.score)


# ---------------------------------------------------------------------------
# DNS tunneling
# ---------------------------------------------------------------------------

@dataclass
class DnsSuspect:
    domain: str
    queries: int
    unique_subdomains: int
    avg_label_len: float
    avg_entropy: float
    clients: int
    score: float


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


# Second-level labels under which registrable domains sit one level deeper.
MULTI_PART_SUFFIXES = {"co", "com", "net", "org", "ac", "go", "or", "ne", "gov", "edu"}


def parent_domain(name: str) -> str:
    parts = name.rstrip(".").lower().split(".")
    if len(parts) >= 3 and parts[-2] in MULTI_PART_SUFFIXES and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def find_dns_tunnels(rows: Iterator[dict], min_unique: int = 50, min_label_len: float = 20.0,
                     min_entropy: float = 3.5, allow: set[str] | None = None) -> list[DnsSuspect]:
    subs: dict[str, set[str]] = defaultdict(set)
    qcount: Counter = Counter()
    clients: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        q = (r.get("query") or "").rstrip(".").lower()
        if q.count(".") < 2:
            continue
        parent = parent_domain(q)
        if allow and parent in allow:
            continue
        sub = q[: -len(parent) - 1]
        subs[parent].add(sub)
        qcount[parent] += 1
        clients[parent].add(r.get("id.orig_h") or "")

    out = []
    for parent, ss in subs.items():
        if len(ss) < min_unique:
            continue
        labels = [s.replace(".", "") for s in ss]
        avg_len = statistics.fmean(len(s) for s in labels)
        avg_ent = statistics.fmean(shannon_entropy(s) for s in labels)
        if avg_len < min_label_len or avg_ent < min_entropy:
            continue
        score = (min(len(ss) / 500, 1) * 40 + min(avg_len / 50, 1) * 30 + min((avg_ent - 3) / 2, 1) * 30)
        out.append(DnsSuspect(parent, qcount[parent], len(ss), round(avg_len, 1), round(avg_ent, 2),
                              len(clients[parent]), round(score, 1)))
    return sorted(out, key=lambda d: -d.score)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def render(items: list, fmt: str) -> str:
    if fmt == "json":
        return json.dumps([asdict(i) for i in items], indent=2)
    if not items:
        return "no findings"
    cols = list(asdict(items[0]).keys())
    rows = [[str(v) for v in asdict(i).values()] for i in items]
    widths = [max(len(c), *(len(r[n]) for r in rows)) for n, c in enumerate(cols)]
    line = lambda vals: "  ".join(v.ljust(w) for v, w in zip(vals, widths))  # noqa: E731
    return "\n".join([line(cols)] + [line(r) for r in rows])


def _load_list(path: str | None) -> set[str]:
    if not path:
        return set()
    return {l.strip().lower() for l in open(path, encoding="utf-8") if l.strip() and not l.startswith("#")}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("beacon", help="periodic connection detection over conn.log")
    b.add_argument("log")
    b.add_argument("--min-conns", type=int, default=10)
    b.add_argument("--max-cv", type=float, default=0.25, help="max coefficient of variation of intervals")
    b.add_argument("--allowlist", help="file of destination IPs to ignore (NTP, update servers, ...)")

    d = sub.add_parser("dns", help="DNS tunneling detection over dns.log")
    d.add_argument("log")
    d.add_argument("--min-unique", type=int, default=50)
    d.add_argument("--min-label-len", type=float, default=20.0)
    d.add_argument("--min-entropy", type=float, default=3.5)
    d.add_argument("--allowlist", help="file of parent domains to ignore (CDNs, AV cloud lookups, ...)")

    for sp in (b, d):
        sp.add_argument("--top", type=int, default=50)
        sp.add_argument("--format", choices=["table", "json"], default="table")

    a = p.parse_args(argv)
    rows = read_zeek(a.log)
    if a.cmd == "beacon":
        res = find_beacons(rows, a.min_conns, a.max_cv, _load_list(a.allowlist))
    else:
        res = find_dns_tunnels(rows, a.min_unique, a.min_label_len, a.min_entropy, _load_list(a.allowlist))
    print(render(res[: a.top], a.format))
    return 0


if __name__ == "__main__":
    sys.exit(main())
