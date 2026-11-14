#!/usr/bin/env python3
"""Score model responses against the SOC assistant evaluation cases.

cases.jsonl: one case per line, with these fields:
    id, category, prompt
    must_match_all   list of regexes that must ALL match
    must_match_any*  any key starting with this is a group, and at least one
                     regex in each group must match
    must_not_match   list of regexes that must NOT match
All regexes are case-insensitive and multiline.

responses.jsonl: one line per case: {"id": "...", "response": "..."}

Usage:
    run_eval.py cases.jsonl responses.jsonl [--min-pass 1.0] [--format table|json]

Exit status is 1 if the overall pass rate is below --min-pass.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict

FLAGS = re.IGNORECASE | re.MULTILINE


def load_jsonl(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def check(case: dict, response: str) -> list[str]:
    """Return a list of failure reasons (empty = pass)."""
    fails = []
    for rx in case.get("must_match_all", []):
        if not re.search(rx, response, FLAGS):
            fails.append(f"missing required: /{rx}/")
    for key, group in case.items():
        if key.startswith("must_match_any") and group:
            if not any(re.search(rx, response, FLAGS) for rx in group):
                fails.append(f"none matched in {key}: {group}")
    for rx in case.get("must_not_match", []):
        m = re.search(rx, response, FLAGS)
        if m:
            fails.append(f"forbidden matched: /{rx}/ -> {m.group(0)!r}")
    return fails


def evaluate(cases: list[dict], responses: dict[str, str]) -> list[dict]:
    results = []
    for c in cases:
        resp = responses.get(c["id"])
        if resp is None:
            results.append({"id": c["id"], "category": c["category"], "passed": False, "reasons": ["no response"]})
            continue
        reasons = check(c, resp)
        results.append({"id": c["id"], "category": c["category"], "passed": not reasons, "reasons": reasons})
    return results


def summarize(results: list[dict]) -> dict:
    by_cat: dict[str, list[bool]] = defaultdict(list)
    for r in results:
        by_cat[r["category"]].append(r["passed"])
    total = len(results)
    passed = sum(r["passed"] for r in results)
    return {
        "passed": passed,
        "total": total,
        "pass_rate": round(passed / total, 3) if total else 0.0,
        "by_category": {k: f"{sum(v)}/{len(v)}" for k, v in sorted(by_cat.items())},
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cases")
    p.add_argument("responses")
    p.add_argument("--min-pass", type=float, default=1.0)
    p.add_argument("--format", choices=["table", "json"], default="table")
    a = p.parse_args(argv)

    cases = load_jsonl(a.cases)
    responses = {r["id"]: r["response"] for r in load_jsonl(a.responses)}
    results = evaluate(cases, responses)
    summary = summarize(results)

    if a.format == "json":
        print(json.dumps({"summary": summary, "results": results}, indent=2, ensure_ascii=False))
    else:
        for r in results:
            print(f"{'PASS' if r['passed'] else 'FAIL'}  {r['id']:<10} {r['category']}")
            for reason in r["reasons"]:
                print(f"        - {reason}")
        print(f"\n{summary['passed']}/{summary['total']} passed ({summary['pass_rate']:.0%})")
        for cat, score in summary["by_category"].items():
            print(f"  {cat:<20} {score}")

    return 0 if summary["pass_rate"] >= a.min_pass else 1


if __name__ == "__main__":
    sys.exit(main())
