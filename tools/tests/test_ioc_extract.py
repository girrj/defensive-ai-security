import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ioc_extract import defang, extract, refang  # noqa: E402

SAMPLE = """
Initial access via hxxps://update-check[.]example-cdn[.]net/dl/setup.exe
C2 beacon to 203.0.113.45:443 and backup C2 evil-domain(dot)example
Internal pivot host 10.20.30.40 (should be dropped by default)
Dropper SHA-256: 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
MD5 of payload: 5d41402abc4b2a76b9719d911017c592
Phishing sender: billing[@]invoice-portal[.]example
Payload written to C:\\Users\\Public\\run.dll and config.json
Exploits CVE-2024-3400 and cve-2021-44228.
"""


class Refang(unittest.TestCase):
    def test_common_forms(self):
        self.assertEqual(refang("hxxp://a[.]b(.)c[dot]d"), "http://a.b.c.d")
        self.assertEqual(refang("x[@]y[.]z"), "x@y.z")


class Extract(unittest.TestCase):
    def setUp(self):
        self.iocs = extract(SAMPLE)

    def test_url(self):
        self.assertEqual(self.iocs["url"], ["https://update-check.example-cdn.net/dl/setup.exe"])

    def test_public_ip_only_by_default(self):
        self.assertEqual(self.iocs["ipv4"], ["203.0.113.45"])
        self.assertNotIn("10.20.30.40", self.iocs.get("ipv4", []))

    def test_private_ip_kept_when_asked(self):
        self.assertIn("10.20.30.40", extract(SAMPLE, include_private=True)["ipv4"])

    def test_hashes_normalized_and_not_split(self):
        self.assertEqual(self.iocs["sha256"], ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"])
        self.assertEqual(self.iocs["md5"], ["5d41402abc4b2a76b9719d911017c592"])
        self.assertNotIn("sha1", self.iocs)

    def test_domains_exclude_filenames(self):
        domains = self.iocs["domain"]
        self.assertIn("evil-domain.example", domains)
        self.assertIn("update-check.example-cdn.net", domains)
        self.assertNotIn("run.dll", domains)
        self.assertNotIn("config.json", domains)

    def test_email(self):
        self.assertEqual(self.iocs["email"], ["billing@invoice-portal.example"])

    def test_cves_uppercased(self):
        self.assertEqual(self.iocs["cve"], ["CVE-2024-3400", "CVE-2021-44228"])


class Defang(unittest.TestCase):
    def test_url(self):
        self.assertEqual(defang("url", "https://a.b.example/x.php"), "hxxps[://]a.b[.]example/x.php")

    def test_domain_ip_email(self):
        self.assertEqual(defang("domain", "evil.example"), "evil[.]example")
        self.assertEqual(defang("ipv4", "203.0.113.45"), "203.0.113[.]45")
        self.assertEqual(defang("email", "a@b.example"), "a[@]b[.]example")

    def test_hash_untouched(self):
        self.assertEqual(defang("md5", "5d41402abc4b2a76b9719d911017c592"), "5d41402abc4b2a76b9719d911017c592")


if __name__ == "__main__":
    unittest.main()
