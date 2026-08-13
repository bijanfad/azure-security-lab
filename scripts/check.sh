#!/usr/bin/env bash
# scripts/check.sh — repo consistency & safety guardrail.
#
# Exits non-zero if anything unsafe or invalid is found. Run by:
#   * the local git pre-commit hook (blocks bad commits),
#   * GitHub Actions CI (validates every push),
#   * manually / by Claude ("is everything up to date?").
#
# Safety checks always run. Terraform/Python checks are skipped gracefully if
# those tools aren't installed, so the hook never breaks a commit spuriously.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" 2>/dev/null || { echo "not a git repo"; exit 2; }
fail=0
ok()  { printf '✅ %s\n' "$*"; }
err() { printf '❌ %s\n' "$*"; fail=1; }
info(){ printf 'ℹ️  %s\n'  "$*"; }

# A path that must never be tracked or staged? (returns 0 = forbidden)
is_forbidden() {
  case "$1" in
    CLAUDE.md|.env|docs/tutorial.md|docs/tutorial.pdf|docs/ROADMAP.md|docs/build_pdf.py|docs/requirements-docs.txt) return 0 ;;
    .env.example) return 1 ;;
    .env.*) return 0 ;;
    example.tfvars|*/example.tfvars) return 1 ;;
    *.tfvars) return 0 ;;
    *.tfstate|*.tfstate.*) return 0 ;;
  esac
  return 1
}

# ---- 1. Private/secret files must not be tracked or staged ----
bad=""
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if is_forbidden "$f"; then bad="$bad $f"; fi
done < <(printf '%s\n%s\n' "$(git ls-files)" "$(git diff --cached --name-only)" | sort -u)
if [ -n "$bad" ]; then err "private/secret file(s) tracked or staged:$bad"; else ok "no private/secret files tracked or staged"; fi

# ---- 2. Subscription ID (read locally, NEVER hardcoded here) not in tracked files ----
guid_re='[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
subid=$(grep -hoE "$guid_re" terraform/azure/terraform.tfvars .env 2>/dev/null | head -1 || true)
if [ -n "$subid" ]; then
  if git grep -qF "$subid" -- . 2>/dev/null; then err "subscription/tenant GUID leaked into a tracked file"; else ok "subscription ID not in tracked files"; fi
else
  info "no local subscription ID available to scan for (skipping)"
fi

# ---- 3. No AWS / multi-cloud leakage in tracked files (this script excluded) ----
if git grep -nE 'boto3|amazonaws|cloudtrail|aws_injectors|multi-cloud|cross-cloud' -- . ':(exclude)scripts/*' ':(exclude).github/*' >/dev/null 2>&1; then
  err "AWS / multi-cloud references found in tracked files"
else
  ok "no AWS/multi-cloud leakage"
fi

# ---- 4. Terraform: format + validate ----
if command -v terraform >/dev/null 2>&1; then
  if terraform -chdir=terraform/azure fmt -check -recursive >/dev/null 2>&1; then ok "terraform fmt"; else err "terraform not formatted (fix: terraform -chdir=terraform/azure fmt -recursive)"; fi
  if [ -d terraform/azure/.terraform ]; then
    if terraform -chdir=terraform/azure validate >/dev/null 2>&1; then ok "terraform validate"; else err "terraform validate failed"; fi
  else
    info "terraform not initialized locally; skipping validate (CI validates)"
  fi
else
  info "terraform not installed; skipping terraform checks"
fi

# ---- 5. Python compiles ----
if command -v python3 >/dev/null 2>&1; then
  if python3 -m py_compile security_monkey/*.py 2>/dev/null; then ok "python compiles"; else err "python compile failed"; fi
else
  info "python3 not installed; skipping python check"
fi

echo
if [ "$fail" -ne 0 ]; then echo "🚫 check.sh: problems found — see ❌ above"; exit 1; fi
echo "🎉 check.sh: all checks passed"
