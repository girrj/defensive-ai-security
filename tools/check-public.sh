#!/usr/bin/env bash
# Fail closed before publishing. See tools/README.md for scope and setup.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="${1:-.}"
if ! command -v python3 >/dev/null 2>&1; then
  echo "FAIL: python3 is required" >&2
  exit 1
fi

python3 "$HERE/ci/check_public.py" "$@"

echo "== gitleaks (all local refs)"
if ! command -v gitleaks >/dev/null 2>&1; then
  echo "FAIL: gitleaks is required" >&2
  exit 1
fi
# Never print findings: file names and commit messages can also be sensitive.
if ! GIT_NO_REPLACE_OBJECTS=1 gitleaks detect --source "$REPO" --log-opts="--all" --redact --no-banner >/dev/null 2>&1; then
  echo "FAIL: gitleaks found a secret or could not complete the scan" >&2
  exit 1
fi
echo "PASS: all public checks completed"
