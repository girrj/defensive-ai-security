import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import cve_triage  # noqa: E402

FIX = HERE / "fixtures"
KEV = str(FIX / "kev.json")
EPSS = str(FIX / "epss.json")


def run(*argv: str) -> list[dict]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cve_triage.main([*argv, "--kev-file", KEV, "--epss-file", EPSS, "--format", "json"])
    assert rc == 0
    return json.loads(out.getvalue())


class PriorityModel(unittest.TestCase):
    def test_kev_internet_is_p1(self):
        self.assertEqual(cve_triage.prioritize(True, "internet", 0.0)[0], "P1")

    def test_kev_internal_is_p2(self):
        self.assertEqual(cve_triage.prioritize(True, "internal", 0.0)[0], "P2")

    def test_high_epss_is_p2(self):
        self.assertEqual(cve_triage.prioritize(False, "internal", 0.15)[0], "P2")

    def test_mid_epss_is_p3(self):
        self.assertEqual(cve_triage.prioritize(False, "internet", 0.02)[0], "P3")

    def test_low_or_missing_epss_is_p4(self):
        self.assertEqual(cve_triage.prioritize(False, "internet", 0.001)[0], "P4")
        self.assertEqual(cve_triage.prioritize(False, "internet", None)[0], "P4")


class EndToEnd(unittest.TestCase):
    def test_positional_cves_sorted_by_priority(self):
        rows = run("CVE-2099-0003", "cve-2021-44228", "CVE-2099-0002", "--exposure", "internet")
        self.assertEqual([r["cve"] for r in rows], ["CVE-2021-44228", "CVE-2099-0002", "CVE-2099-0003"])
        self.assertEqual([r["priority"] for r in rows], ["P1", "P3", "P4"])
        self.assertEqual(rows[0]["kev_ransomware"], "Known")

    def test_csv_input_uses_per_row_exposure(self):
        rows = {r["cve"]: r for r in run("-i", str(FIX / "assets.csv"))}
        self.assertEqual(rows["CVE-2024-3400"]["priority"], "P1")
        self.assertEqual(rows["CVE-2021-44228"]["priority"], "P2")
        self.assertEqual(rows["CVE-2099-0001"]["asset"], "web-02")

    def test_cve_ids_extracted_from_free_text(self):
        text = FIX / "advisory.txt"
        text.write_text("Patch CVE-2024-3400 and cve-2099-0002 now; see also CVE-2024-3400.\n")
        try:
            rows = run("-i", str(text))
        finally:
            text.unlink()
        self.assertEqual(sorted(r["cve"] for r in rows), ["CVE-2024-3400", "CVE-2099-0002"])

    def test_unknown_cve_has_no_scores(self):
        rows = run("CVE-2099-9999")
        self.assertIsNone(rows[0]["epss"])
        self.assertFalse(rows[0]["in_kev"])
        self.assertEqual(rows[0]["priority"], "P4")


if __name__ == "__main__":
    unittest.main()
