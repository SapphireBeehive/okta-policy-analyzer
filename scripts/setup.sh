#!/usr/bin/env bash
# Set up okta-policy-analyzer in this checkout: install the package + z3, run a quick self-test, and report
# whether an Okta tenant is configured. Safe to re-run; use --quiet for a SessionStart hook.
#
#   bash scripts/setup.sh            # full output
#   bash scripts/setup.sh --quiet    # one line unless something is wrong
#   bash scripts/setup.sh --fetch    # also take a snapshot into snapshots/<date> when credentials are set
set -euo pipefail

QUIET=0
FETCH=0
for arg in "$@"; do
  case "$arg" in
    --quiet) QUIET=1 ;;
    --fetch) FETCH=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
say() { if [ "$QUIET" -eq 0 ]; then echo "$@"; fi; }

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "setup: python3 not found" >&2
  exit 1
fi

# --- install (editable) unless already importable with z3 -------------------------------------------
if ! "$PY" -c "import okta_policy_analyzer, z3" >/dev/null 2>&1; then
  say "setup: installing okta-policy-analyzer (editable) with dev extras…"
  "$PY" -m pip install -q -e ".[dev]" || "$PY" -m pip install -q -e .
fi
VERSION="$("$PY" -c "import okta_policy_analyzer as m; print(getattr(m, '__version__', 'dev'))")"

# --- self-test on the bundled synthetic tenant ----------------------------------------------------------
if ! "$PY" -m okta_policy_analyzer.cli check tests/fixtures/acme \
      "Okta Administrators must use phishing-resistant MFA for the Okta Admin Console" >/dev/null 2>&1; then
  echo "setup: self-test failed — run: python3 -m okta_policy_analyzer.cli check tests/fixtures/acme \"Okta Administrators must use phishing-resistant MFA for the Okta Admin Console\"" >&2
  exit 1
fi

# --- tenant configuration -----------------------------------------------------------------------------------
if [ -f .env ] && [ -z "${OKTA_ORG_URL:-}" ]; then
  set -a; # shellcheck disable=SC1091
  source .env; set +a
fi
TENANT="not configured (copy .env.example to .env, or export OKTA_ORG_URL and OKTA_API_TOKEN)"
if [ -n "${OKTA_ORG_URL:-}" ] && { [ -n "${OKTA_API_TOKEN:-}" ] || [ -n "${OKTA_ACCESS_TOKEN:-}" ]; }; then
  TENANT="$OKTA_ORG_URL (credentials present)"
elif [ -n "${OKTA_ORG_URL:-}" ]; then
  TENANT="$OKTA_ORG_URL (no token: set OKTA_API_TOKEN or OKTA_ACCESS_TOKEN)"
fi
LATEST="$(ls -1d snapshots/*/ 2>/dev/null | sort | tail -n1 || true)"

if [ "$FETCH" -eq 1 ] && [[ "$TENANT" == *"credentials present"* ]]; then
  OUT="snapshots/$(date +%Y%m%d-%H%M)"
  say "setup: fetching a read-only snapshot into $OUT…"
  "$PY" -m okta_policy_analyzer.cli fetch -o "$OUT"
  LATEST="$OUT/"
fi

echo "okta-policy-analyzer $VERSION ready · tenant: $TENANT · latest snapshot: ${LATEST:-none}"
say ""
say "next:"
say "  okta-policy-analyzer fetch -o snapshots/\$(date +%Y%m%d)        # take a snapshot (read-only)"
say "  okta-policy-analyzer analyze snapshots/<date> --no-cubes        # findings + who can do what"
say "  okta-policy-analyzer check snapshots/<date> \"<invariant>\"       # prove / refute a sentence"
say "  okta-policy-analyzer propose snapshots/<date> \"<invariant>\" --plan-out plan.json   # make a rule"
