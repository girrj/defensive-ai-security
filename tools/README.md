# Publication checks (공개 전 검사)

Run `./tools/check-public.sh` from the repository root before every push. Python 3.9+, Git, and `gitleaks` are required. A nonzero exit means **do not push**. The script does not install a Git hook or enforce remote branch protection.

## Private denylist (금칙어 목록)

Maintain `tools/denylist.local.txt` locally, with one sensitive term per line. It is Git-ignored and must never be staged, committed, printed, or shared. Use `tools/denylist.example.txt` only as a format example; replace its examples with the actual private list. An existing list outside the repository can be used without copying it:

```bash
DENYLIST=/absolute/path/to/denylist.local.txt ./tools/check-public.sh
```

An explicit `DENYLIST` path is relative to the invocation directory; the default is under the target repository root. An in-repository list must be ignored and untracked. A missing, unreadable, empty, or comment-only list fails the gate. Matching preserves the previous case-insensitive fixed-term, word-boundary behavior: letters, digits, and underscores are word characters, so a short acronym embedded inside an unrelated identifier does not match. Add the full sensitive hostname or identifier when needed. Blank lines and lines beginning with `#` after whitespace are ignored.

## Scan scope (검사 범위)

- Sensitive terms: tracked working-tree files, non-ignored untracked files, file names, staged blobs, and all Git objects reachable from local refs, including deleted files and commit/tag metadata. `tools/` and private-IP exception paths are included. Symbolic links are checked as link targets without reading files outside the repository.
- Private IPv4 addresses: working-tree files, except the literal synthetic-data paths documented in `public-scan-allow.txt`. Exceptions do not apply to sensitive terms. Ignored local files are outside publication scope; staged files are always included in sensitive-term checks.
- Secrets: `gitleaks detect` across all local refs. Its findings and errors fail the gate. This history scan does not replace review of uncommitted changes for secrets before committing.

Use a complete clone and fetch every branch and tag that will be published before running the gate. Shallow history, unreadable scan inputs, Git failures, unresolved merges, and submodules fail rather than silently reducing coverage. Remote-only refs and unreachable/reflog-only objects are outside the scan.

Diagnostics identify the failed check without printing sensitive terms, matching lines, file names, commit messages, or raw tool errors. Investigate locally with an approved private workflow; do not paste scanner findings into a public issue or PR.

## CI and tests (자동 검증)

`python3 -m unittest discover -s tools/tests -v` exercises the gate in disposable repositories with synthetic terms and a stub secret scanner. Tests cover failure paths and output redaction; the stub does not validate gitleaks detection quality. CI runs these tests and its separate real gitleaks history scan. The actual private-list gate must pass locally before pushing; the private list is never uploaded to CI.
