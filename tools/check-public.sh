#!/usr/bin/env bash
# Pre-publication check for a repository that is about to be made public.
#
# 1. gitleaks over the full git history (all branches)
# 2. A local, NOT committed, denylist of sensitive terms (employer, customer,
#    and internal hostnames, IP ranges, case numbers) checked against the
#    working tree and every commit's diff.
#
# Usage:
#   cp tools/denylist.example.txt tools/denylist.local.txt   # edit it, never commit it
#   tools/check-public.sh [repo-path]

set -euo pipefail

REPO="${1:-.}"
DENYLIST="${DENYLIST:-$(dirname "$0")/denylist.local.txt}"
status=0

cd "$REPO"

echo "== gitleaks (full history)"
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source . --log-opts="--all" --redact --no-banner || status=1
else
  echo "   gitleaks not installed: https://github.com/gitleaks/gitleaks" >&2
  status=1
fi

echo "== private IP ranges in the working tree"
ALLOW="$(dirname "$0")/public-scan-allow.txt"
excludes=()
if [[ -f "$ALLOW" ]]; then
  while IFS= read -r p; do
    [[ -z "$p" || "$p" == \#* ]] && continue
    excludes+=(":!$p")
  done < "$ALLOW"
fi
if git grep -nIE '\b(10\.[0-9]{1,3}|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}\b' -- . "${excludes[@]}"; then
  status=1
fi

if [[ -f "$DENYLIST" ]]; then
  echo "== denylist terms (working tree)"
  if git grep -nIiwF -f <(grep -vE '^\s*(#|$)' "$DENYLIST") -- . ':!tools/'; then
    status=1
  fi

  echo "== denylist terms (all history)"
  if git log --all -p --no-color | grep -niwF -f <(grep -vE '^\s*(#|$)' "$DENYLIST"); then
    status=1
  fi
else
  echo "== no denylist at $DENYLIST (skipping term scan)"
fi

if [[ $status -eq 0 ]]; then
  echo "PASS: nothing found"
else
  echo "REVIEW: findings above. Rewrite history or start a fresh repository before publishing." >&2
fi
exit $status
