"""Format checks for iocs/iocs.csv.

Every row must be well-formed, defanged where it can be clicked or resolved,
attributed to a public source, and tied to a case file that exists.
"""
import csv
import ipaddress
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
CSV = HERE / "iocs" / "iocs.csv"
CASES = HERE / "cases"

FIELDS = ["type", "value", "description", "incident", "scope", "source", "source_url", "published"]
TYPES = {"sha256", "md5", "ipv4", "domain", "onion", "email", "filename", "command"}
HEX = {"sha256": 64, "md5": 32}


def load():
    with CSV.open(newline="") as fh:
        reader = csv.DictReader(fh)
        return reader.fieldnames, list(reader)


class IocFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fields, cls.rows = load()

    def test_header(self):
        self.assertEqual(self.fields, FIELDS)

    def test_rows_present(self):
        self.assertGreater(len(self.rows), 0)

    def test_types_and_required_fields(self):
        for n, r in enumerate(self.rows, 2):
            with self.subTest(line=n):
                self.assertIn(r["type"], TYPES)
                for f in FIELDS:
                    self.assertTrue(r[f].strip(), f"empty {f}")
                self.assertIn(r["scope"], {"incident", "campaign"})
                self.assertTrue(r["source_url"].startswith("https://"))
                self.assertRegex(r["published"], r"^\d{4}-\d{2}-\d{2}$")

    def test_case_file_exists(self):
        names = {p.stem for p in CASES.glob("*.md")}
        for n, r in enumerate(self.rows, 2):
            with self.subTest(line=n):
                self.assertIn(r["incident"], names)

    def test_hashes(self):
        for n, r in enumerate(self.rows, 2):
            if r["type"] in HEX:
                with self.subTest(line=n):
                    self.assertRegex(r["value"], rf"^[0-9a-f]{{{HEX[r['type']]}}}$")

    def test_network_values_are_defanged_and_valid(self):
        for n, r in enumerate(self.rows, 2):
            t, v = r["type"], r["value"]
            with self.subTest(line=n, value=v):
                if t in {"ipv4", "domain", "onion", "email"}:
                    self.assertIn("[.]", v)
                    self.assertNotRegex(v, r"(?<!\[)\.(?!\])")
                refanged = v.replace("[.]", ".").replace("[@]", "@")
                if t == "ipv4":
                    ipaddress.IPv4Address(refanged)
                elif t == "onion":
                    self.assertRegex(refanged, r"^[a-z2-7]{56}\.onion$")
                elif t == "email":
                    self.assertIn("[@]", v)
                    self.assertRegex(refanged, r"^[^@\s]+@[a-z0-9.-]+\.[a-z]+$")
                elif t == "domain":
                    self.assertRegex(refanged, r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")

    def test_no_duplicates(self):
        seen = set()
        for n, r in enumerate(self.rows, 2):
            key = (r["type"], r["value"])
            self.assertNotIn(key, seen, f"duplicate at line {n}")
            seen.add(key)


if __name__ == "__main__":
    unittest.main()
