#!/usr/bin/env python3
"""Private local publication gate (공개 전 검사); never print sensitive input."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys


class ScanError(Exception):
    """A safe, generic diagnostic for a failed or incomplete scan."""


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ).stdout


def text(data: bytes) -> str:
    return data.decode("utf-8", errors="surrogateescape")


def load_terms(path: Path) -> list[str]:
    # Read only inside the scanner. Never include values or paths in diagnostics.
    terms = [line.strip().casefold() for line in path.read_text(encoding="utf-8-sig").splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    if not terms or any("\x00" in term for term in terms):
        raise ScanError("denylist must contain non-empty, valid terms")
    return terms


def reject_terms(data: bytes, terms: re.Pattern[str], scope: str) -> None:
    if terms.search(text(data).casefold()):
        raise ScanError(f"sensitive-term match in {scope}")


def load_ip_allowlist(repo: Path) -> list[str]:
    entries = []
    for line in (repo / "tools/public-scan-allow.txt").read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        parts = entry.rstrip("/").split("/")
        if any(part in {"", ".", ".."} for part in parts) or any(c in entry for c in "*?[:\\"):
            raise ScanError("invalid private-IP exception; use a literal relative file or directory")
        entries.append(entry)
    return entries


PRIVATE_IP = re.compile(
    rb"\b(?:10\.[0-9]{1,3}|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}\b"
)


def check_files(repo: Path, terms: re.Pattern[str], allowed: list[str]) -> set[str]:
    staged_names, objects = set(), set()
    for record in filter(None, git(repo, "ls-files", "--stage", "-z").split(b"\x00")):
        meta, name = record.split(b"\t", 1)
        mode, oid, stage = meta.split()
        if stage != b"0" or mode == b"160000":
            raise ScanError("unmerged index or submodule requires a separate review")
        reject_terms(name, terms, "staged file names")
        staged_names.add(name)
        objects.add(oid.decode("ascii"))

    names = git(repo, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    for name in set(filter(None, names.split(b"\x00"))):
        reject_terms(name, terms, "working-tree file names")
        relative = os.fsdecode(name)
        path = repo / relative
        if path.is_symlink():
            data = os.fsencode(os.readlink(path))
        else:
            try:
                data = path.read_bytes()
            except FileNotFoundError:
                # A tracked deletion is checked through its index blob and history.
                if name not in staged_names:
                    raise
                continue
        reject_terms(data, terms, "working-tree contents")
        exempt = any(relative == item or (item.endswith("/") and relative.startswith(item))
                     for item in allowed)
        if not exempt and PRIVATE_IP.search(data):
            raise ScanError("private IP in working tree outside documented synthetic-data exceptions")
    return objects


def check_objects(repo: Path, terms: re.Pattern[str], staged: set[str]) -> None:
    listing = git(repo, "rev-list", "--objects", "--all")
    objects = staged | {line.split(b" ", 1)[0].decode("ascii") for line in listing.splitlines()}
    # Include commit/tag metadata, file names in trees, and deleted file contents.
    # One request at a time avoids pipe deadlocks; memory is bounded per object.
    with subprocess.Popen(
        ["git", "--no-replace-objects", "-C", str(repo), "cat-file", "--batch"], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ) as proc:
        try:
            for oid in sorted(objects):
                proc.stdin.write(oid.encode("ascii") + b"\n")
                proc.stdin.flush()
                header = proc.stdout.readline().split()
                if len(header) != 3:
                    raise ScanError("could not read every Git object")
                size = int(header[2])
                data = proc.stdout.read(size)
                if len(data) != size or proc.stdout.read(1) != b"\n":
                    raise ScanError("incomplete Git object scan")
                reject_terms(data, terms, "index or Git history")
        except BaseException:
            proc.kill()
            raise
        finally:
            proc.stdin.close()
        if proc.wait() != 0:
            raise ScanError("Git object scan failed")


def main(argv: list[str]) -> int:
    try:
        if len(argv) > 1:
            raise ScanError("usage: check-public.sh [repo-path]")
        repo = Path(argv[0] if argv else ".").resolve()
        root = Path(os.fsdecode(git(repo, "rev-parse", "--show-toplevel")).strip()).resolve()
        if root != repo or git(repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
            raise ScanError("use the repository root with complete Git history")
        if git(repo, "ls-files", "--", "tools/denylist.local.txt").strip():
            raise ScanError("local denylist must not be tracked")
        denylist = Path(os.environ.get("DENYLIST", str(repo / "tools/denylist.local.txt"))).resolve()
        if denylist.is_relative_to(repo):
            relative = str(denylist.relative_to(repo))
            if git(repo, "ls-files", "--", relative).strip():
                raise ScanError("denylist must not be tracked")
            git(repo, "check-ignore", "-q", "--", relative)
        # Preserve the original git-grep -w fixed-term semantics: a short company
        # acronym must not match an unrelated substring of a standard artifact name.
        terms = re.compile(r"(?<!\w)(?:" + "|".join(re.escape(t) for t in load_terms(denylist)) + r")(?!\w)")
        allowed = load_ip_allowlist(repo)
        staged = check_files(repo, terms, allowed)
        check_objects(repo, terms, staged)
    except ScanError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        print("FAIL: required scan input is missing, unreadable, or a scan could not complete", file=sys.stderr)
        return 1
    print("PASS: denylist, working tree, index, history, and private-IP checks completed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
