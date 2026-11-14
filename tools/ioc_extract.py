#!/usr/bin/env python3
"""Extract, normalize, and defang indicators of compromise from text.

Reads threat reports, alert bodies, emails, or chat logs and returns unique
IPv4 addresses, domains, URLs, email addresses, hashes (MD5/SHA-1/SHA-256),
and CVE IDs. Already-defanged input (hxxp, [.], (dot)) is refanged first, so
indicators copied from reports are recognized.

Standard library only.

Examples:
    ioc_extract.py report.txt
    pbpaste | ioc_extract.py --defang
    ioc_extract.py report.txt --format csv --include-private
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
import sys

REFANG = [
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\s*\[dot\]\s*|\s*\(dot\)\s*", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*@\s*\]|\s*\[at\]\s*|\s*\(at\)\s*", re.I), "@"),
    (re.compile(r"\bhxxp(s?)", re.I), r"http\1"),
    (re.compile(r"\bfxp\b", re.I), "ftp"),
]

TLD = r"(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})"
LABEL = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"

PATTERNS = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`)\]]+", re.I),
    "email": re.compile(rf"\b[a-z0-9._%+-]+@{LABEL}(?:\.{LABEL})*\.{TLD}\b", re.I),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "domain": re.compile(rf"\b{LABEL}(?:\.{LABEL})*\.{TLD}\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I),
}

# File extensions and common false-positive "domains" seen in reports.
NOT_DOMAINS = {
    "exe", "dll", "sys", "bat", "ps1", "vbs", "js", "jar", "zip", "rar", "7z", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "log", "tmp", "dat", "bin", "lnk", "iso", "img",
    "msi", "py", "sh", "php", "jsp", "aspx", "asp", "html", "htm", "json", "xml", "yml", "yaml",
    "png", "jpg", "jpeg", "gif", "csv", "md", "conf", "cfg", "ini", "db", "evtx", "pcap",
}


def refang(text: str) -> str:
    for pat, repl in REFANG:
        text = pat.sub(repl, text)
    return text


def defang(kind: str, value: str) -> str:
    if kind in ("url", "domain", "email", "ipv4"):
        value = re.sub(r"^http", "hxxp", value, flags=re.I)
        value = value.replace("://", "[://]") if kind == "url" else value
        value = value.replace("@", "[@]") if kind == "email" else value
        # Defang the last dot only for domains/IPs/hosts: enough to break auto-linking.
        if kind == "url":
            m = re.match(r"(hxxps?\[://\]|ftp\[://\])([^/]+)(.*)", value, re.I)
            if m:
                host = m.group(2)
                i = host.rfind(".")
                host = host[:i] + "[.]" + host[i + 1:] if i > 0 else host
                value = m.group(1) + host + m.group(3)
        else:
            i = value.rfind(".")
            value = value[:i] + "[.]" + value[i + 1:] if i > 0 else value
    return value


NON_ROUTABLE = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
)]


def is_private_ip(value: str) -> bool:
    """RFC 1918, CGNAT, loopback, link-local, multicast, and reserved space.

    Documentation ranges (TEST-NET) are deliberately kept, so report examples
    and training material still extract.
    """
    ip = ipaddress.ip_address(value)
    return any(ip in net for net in NON_ROUTABLE)


def extract(text: str, include_private: bool = False) -> dict[str, list[str]]:
    text = refang(text)
    found: dict[str, list[str]] = {k: [] for k in PATTERNS}
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        key = (kind, value.lower())
        if key not in seen:
            seen.add(key)
            found[kind].append(value)

    for m in PATTERNS["url"].finditer(text):
        add("url", m.group(0).rstrip(".,;:"))
    for m in PATTERNS["email"].finditer(text):
        add("email", m.group(0).lower())
    for m in PATTERNS["ipv4"].finditer(text):
        if include_private or not is_private_ip(m.group(0)):
            add("ipv4", m.group(0))

    # Hashes: longest first, and don't report substrings of a longer hash.
    hash_spans: list[tuple[int, int]] = []
    for kind in ("sha256", "sha1", "md5"):
        for m in PATTERNS[kind].finditer(text):
            if any(s <= m.start() and m.end() <= e for s, e in hash_spans):
                continue
            hash_spans.append(m.span())
            add(kind, m.group(0).lower())

    email_domains = {e.split("@", 1)[1] for e in found["email"]}
    for m in PATTERNS["domain"].finditer(text):
        d = m.group(0).lower().rstrip(".")
        tld = d.rsplit(".", 1)[-1]
        if tld in NOT_DOMAINS or re.fullmatch(r"[\d.]+", d):
            continue
        if d in email_domains and text.count(d) == sum(e.endswith("@" + d) for e in found["email"]):
            continue  # only appears as part of an email address
        add("domain", d)

    for m in PATTERNS["cve"].finditer(text):
        add("cve", m.group(0).upper())

    return {k: v for k, v in found.items() if v}


def render(iocs: dict[str, list[str]], fmt: str, defanged: bool) -> str:
    rows = [(k, defang(k, v) if defanged else v) for k, vals in iocs.items() for v in vals]
    if fmt == "json":
        out: dict[str, list[str]] = {}
        for k, v in rows:
            out.setdefault(k, []).append(v)
        return json.dumps(out, indent=2)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type", "value"])
        w.writerows(rows)
        return buf.getvalue()
    return "\n".join(f"{k}\t{v}" for k, v in rows)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("file", nargs="?", default="-", help="input file (default: stdin)")
    p.add_argument("--defang", action="store_true", help="defang URLs, domains, IPs, and emails in the output")
    p.add_argument("--include-private", action="store_true", help="keep RFC 1918, loopback, and reserved IPs")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text")
    args = p.parse_args(argv)

    text = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8", errors="replace").read()
    print(render(extract(text, args.include_private), args.format, args.defang))
    return 0


if __name__ == "__main__":
    sys.exit(main())
