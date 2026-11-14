#!/usr/bin/env python3
"""Prioritize CVEs using CISA KEV, FIRST EPSS, and asset exposure.

Standard library only. Data comes from the public feeds by default, or from
local files with --kev-file / --epss-file (for offline use and testing).

Examples:
    cve_triage.py CVE-2021-44228 CVE-2023-4966 --exposure internet
    cve_triage.py -i cves.txt --format csv > triage.csv
    cve_triage.py -i assets.csv --format json     # CSV columns: cve,asset,exposure

Priority model (see README.md):
    P1  in KEV and internet-facing
    P2  in KEV (internal), or EPSS >= 0.10
    P3  EPSS >= 0.01
    P4  everything else
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import urllib.request
from dataclasses import asdict, dataclass
from typing import Iterable

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={cves}"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
EPSS_BATCH = 100

SLA = {
    "P1": "mitigate 24h / patch 72h",
    "P2": "patch 7d",
    "P3": "patch 30d",
    "P4": "normal cycle",
}


@dataclass
class Finding:
    cve: str
    asset: str
    exposure: str
    in_kev: bool
    kev_date_added: str
    kev_ransomware: str
    kev_due_date: str
    epss: float | None
    epss_percentile: float | None
    priority: str
    sla: str
    reason: str


def _fetch_json(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "cve-triage/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https URLs)
        return json.load(resp)


def load_kev(path: str | None) -> dict[str, dict]:
    data = json.load(open(path, encoding="utf-8")) if path else _fetch_json(KEV_URL)
    return {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}


def load_epss(cves: list[str], path: str | None) -> dict[str, dict]:
    if path:
        rows = json.load(open(path, encoding="utf-8")).get("data", [])
    else:
        rows = []
        for i in range(0, len(cves), EPSS_BATCH):
            chunk = ",".join(cves[i : i + EPSS_BATCH])
            rows.extend(_fetch_json(EPSS_URL.format(cves=chunk)).get("data", []))
    return {r["cve"].upper(): r for r in rows}


def prioritize(in_kev: bool, exposure: str, epss: float | None) -> tuple[str, str]:
    internet = exposure == "internet"
    if in_kev and internet:
        return "P1", "known exploited + internet-facing"
    if in_kev:
        return "P2", "known exploited (internal)"
    if epss is not None and epss >= 0.10:
        return "P2", f"EPSS {epss:.2f} >= 0.10" + (" + internet-facing" if internet else "")
    if epss is not None and epss >= 0.01:
        return "P3", f"EPSS {epss:.3f} >= 0.01"
    return "P4", "no KEV entry, low EPSS" if epss is not None else "no KEV entry, no EPSS score"


def parse_inputs(args: argparse.Namespace) -> list[tuple[str, str, str]]:
    """Return (cve, asset, exposure) tuples, deduplicated, in input order."""
    items: list[tuple[str, str, str]] = []
    for c in args.cves:
        items.append((c.upper(), "", args.exposure))
    if args.input:
        text = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8").read()
        first = text.lstrip().splitlines()[0].lower() if text.strip() else ""
        if first.startswith("cve,") or first.startswith("cve\t"):
            for row in csv.DictReader(io.StringIO(text)):
                cve = (row.get("cve") or "").strip().upper()
                if CVE_RE.fullmatch(cve):
                    exp = (row.get("exposure") or args.exposure).strip().lower()
                    items.append((cve, (row.get("asset") or "").strip(), exp))
        else:
            for m in CVE_RE.finditer(text):
                items.append((m.group(0).upper(), "", args.exposure))
    seen, out = set(), []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def triage(items: Iterable[tuple[str, str, str]], kev: dict, epss: dict) -> list[Finding]:
    findings = []
    for cve, asset, exposure in items:
        k = kev.get(cve)
        e = epss.get(cve)
        score = float(e["epss"]) if e else None
        pct = float(e["percentile"]) if e else None
        prio, reason = prioritize(k is not None, exposure, score)
        findings.append(
            Finding(
                cve=cve,
                asset=asset,
                exposure=exposure,
                in_kev=k is not None,
                kev_date_added=k.get("dateAdded", "") if k else "",
                kev_ransomware=k.get("knownRansomwareCampaignUse", "") if k else "",
                kev_due_date=k.get("dueDate", "") if k else "",
                epss=score,
                epss_percentile=pct,
                priority=prio,
                sla=SLA[prio],
                reason=reason,
            )
        )
    findings.sort(key=lambda f: (f.priority, -(f.epss or 0.0), f.cve))
    return findings


def render(findings: list[Finding], fmt: str) -> str:
    if fmt == "json":
        return json.dumps([asdict(f) for f in findings], indent=2)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(asdict(findings[0]).keys()) if findings else ["cve"])
        w.writeheader()
        for f in findings:
            w.writerow(asdict(f))
        return buf.getvalue()
    lines = [f"{'PRIO':<5}{'CVE':<18}{'KEV':<5}{'EPSS':>7}  {'EXPOSURE':<9}{'ASSET':<20}REASON"]
    for f in findings:
        ep = f"{f.epss:.3f}" if f.epss is not None else "  -  "
        lines.append(
            f"{f.priority:<5}{f.cve:<18}{'yes' if f.in_kev else 'no':<5}{ep:>7}  {f.exposure:<9}{f.asset[:19]:<20}{f.reason}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cves", nargs="*", help="CVE IDs")
    p.add_argument("-i", "--input", help="file with CVE IDs (any text), or CSV with cve,asset,exposure; '-' for stdin")
    p.add_argument("--exposure", choices=["internet", "internal"], default="internal",
                   help="default exposure for CVEs without one (default: internal)")
    p.add_argument("--kev-file", help="local KEV JSON instead of downloading")
    p.add_argument("--epss-file", help="local EPSS API JSON instead of downloading")
    p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    args = p.parse_args(argv)

    items = parse_inputs(args)
    if not items:
        p.error("no CVE IDs given")
    try:
        kev = load_kev(args.kev_file)
        epss = load_epss(sorted({c for c, _, _ in items}), args.epss_file)
    except (OSError, ValueError) as exc:
        print(f"error: could not load KEV/EPSS data: {exc}\n"
              "hint: download the feeds and pass --kev-file / --epss-file", file=sys.stderr)
        return 2
    print(render(triage(items, kev, epss), args.format))
    return 0


if __name__ == "__main__":
    sys.exit(main())
