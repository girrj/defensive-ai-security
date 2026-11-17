"""Publication-gate regression tests using disposable Git repos and synthetic data."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid


SCRIPT = Path(__file__).resolve().parents[1] / "check-public.sh"
REAL_GIT = shutil.which("git")


class PublicCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repository with spaces"
        self.repo.mkdir()
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.env.pop("DENYLIST", None)
        self.env.update(GIT_AUTHOR_NAME="girrj", GIT_COMMITTER_NAME="girrj",
                        GIT_AUTHOR_EMAIL="girrj@users.noreply.github.com",
                        GIT_COMMITTER_EMAIL="girrj@users.noreply.github.com")
        self.run_git("init", "-b", "main")
        (self.repo / "tools").mkdir()
        self.write(".gitignore", "tools/denylist.local.txt\n")
        self.write("tools/public-scan-allow.txt", "# synthetic-data paths only\n")
        self.write("README.md", "Public synthetic fixture.\n")
        self.commit()
        self.marker = "synthetic-" + uuid.uuid4().hex
        self.denylist = self.repo / "tools/denylist.local.txt"
        self.denylist.write_text(self.marker + "\n", encoding="utf-8")
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.stub = self.bin / "gitleaks"
        self.set_scanner(0)
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env["PATH"]

    def run_git(self, *args):
        return subprocess.run([REAL_GIT, "-C", str(self.repo), *args], env=self.env,
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def write(self, relative, data):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8")

    def commit(self, message="Synthetic fixture"):
        self.run_git("add", ".")
        self.run_git("-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
                     "commit", "-m", message)

    def set_scanner(self, status):
        self.stub.write_text("#!/bin/sh\nprintf 'scanner output must stay private\\n'\n"
                             f"exit {status}\n", encoding="utf-8")
        self.stub.chmod(0o755)

    def scan(self, ok=False, cwd=None, target=None):
        result = subprocess.run(["/bin/bash", str(SCRIPT), str(target or self.repo)],
                                cwd=cwd or self.repo, env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout + result.stderr
        self.assertNotIn(self.marker, output)
        self.assertNotIn("scanner output must stay private", output)
        if ok:
            self.assertEqual(result.returncode, 0, output)
            self.assertIn("PASS: all public checks completed", output)
        else:
            self.assertNotEqual(result.returncode, 0, output)
            self.assertNotIn("PASS: all public checks completed", output)
        return output

    def test_clean_repo_from_other_directory(self):
        self.scan(ok=True, cwd=self.base)

    def test_missing_empty_and_comment_only_denylist(self):
        self.denylist.unlink()
        self.scan()
        for data in ["", " \n\t\n", "# format only\n  # comment\n"]:
            with self.subTest(data=data):
                self.denylist.write_text(data)
                self.scan()

    def test_unreadable_denylist(self):
        self.denylist.unlink()
        self.denylist.mkdir()
        self.scan()

    def test_tracked_denylist_is_rejected(self):
        self.run_git("add", "-f", "tools/denylist.local.txt")
        self.scan()

    def test_nonignored_override_is_rejected(self):
        self.write("private-list.txt", self.marker)
        self.env["DENYLIST"] = str(self.repo / "private-list.txt")
        self.scan()

    def test_external_denylist(self):
        external = self.base / "private-list.txt"
        self.denylist.rename(external)
        self.env["DENYLIST"] = str(external)
        self.scan(ok=True)

    def test_tools_are_scanned_case_insensitively(self):
        self.write("tools/new.txt", "prefix " + self.marker.upper() + " suffix")
        self.assertIn("working-tree contents", self.scan())

    def test_word_boundaries_preserve_original_matching_semantics(self):
        self.write("tools/new.txt", "prefix" + self.marker + "suffix")
        self.scan(ok=True)
        self.write("tools/new.txt", "https://" + self.marker + ".example/")
        self.scan()

    def test_tracked_working_tree_and_binary_files(self):
        self.write("README.md", self.marker)
        self.scan()
        self.write("README.md", "clean")
        (self.repo / "binary.bin").write_bytes(b"\x00\xff" + self.marker.encode())
        self.scan()

    def test_file_names_are_scanned(self):
        self.write(self.marker + ".txt", "clean")
        self.assertIn("file names", self.scan())

    def test_staged_content_is_scanned_after_working_copy_is_cleaned(self):
        self.write("README.md", self.marker)
        self.run_git("add", "README.md")
        self.write("README.md", "clean")
        self.assertIn("index or Git history", self.scan())

    def test_deleted_historical_content_is_scanned(self):
        self.write("old.txt", self.marker)
        self.commit()
        self.run_git("rm", "old.txt")
        self.commit()
        self.assertIn("Git history", self.scan())

    def test_other_branch_and_commit_metadata_are_scanned(self):
        self.run_git("checkout", "-b", "synthetic-history")
        self.write("old.txt", "clean")
        self.commit(self.marker)
        self.run_git("checkout", "main")
        self.assertIn("Git history", self.scan())

    def test_tracked_deletion_is_handled(self):
        (self.repo / "README.md").unlink()
        self.scan(ok=True)

    def test_private_ip_exceptions_never_exempt_terms(self):
        self.write("tools/public-scan-allow.txt", "fixtures/\n")
        self.write("fixtures/synthetic.txt", "10.20.30.40")
        self.scan(ok=True)
        self.write("fixtures/synthetic.txt", self.marker)
        self.scan()

    def test_private_ip_without_exception_fails(self):
        self.write("new.txt", "10.20.30.40")
        self.assertIn("private IP", self.scan())

    def test_missing_and_broad_ip_exception_configuration_fail(self):
        allow = self.repo / "tools/public-scan-allow.txt"
        allow.unlink()
        self.scan()
        for entry in [".\n", "*\n", "/\n", "../\n", ":(glob)**\n"]:
            with self.subTest(entry=entry):
                allow.write_text(entry)
                self.scan()

    def test_git_error_is_not_treated_as_no_match(self):
        stub_git = self.bin / "git"
        stub_git.write_text("#!/bin/sh\nexit 2\n")
        stub_git.chmod(0o755)
        self.scan()

    def test_scanner_findings_and_errors_fail_without_output(self):
        for status in (1, 2):
            with self.subTest(status=status):
                self.set_scanner(status)
                self.assertIn("gitleaks", self.scan())

    def test_missing_scanner_fails(self):
        self.stub.unlink()
        # A controlled PATH guarantees this test also works on a CI host with gitleaks.
        os.symlink(shutil.which("python3"), self.bin / "python3")
        os.symlink(REAL_GIT, self.bin / "git")
        os.symlink(shutil.which("dirname"), self.bin / "dirname")
        self.env["PATH"] = str(self.bin)
        self.assertIn("gitleaks is required", self.scan())

    def test_shallow_history_fails(self):
        clone = self.base / "shallow"
        self.run_git("clone", "--depth=1", self.repo.as_uri(), str(clone))
        (clone / "tools/denylist.local.txt").write_text(self.marker)
        self.assertIn("complete Git history", self.scan(target=clone))


if __name__ == "__main__":
    unittest.main()
