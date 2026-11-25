#!/usr/bin/env bash
# Tier-0 offline invariant checks (CipherLayer review loop, family guide §7).
# Deterministic, no network, no model. Folded into `make ci`; also called
# standalone by the root family-review.sh orchestrator.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fail=0
ok()  { echo "  OK   $1"; }
bad() { echo "  FAIL $1"; fail=1; }

echo "== scam-guard family-invariants =="

# 1. No runtime/secret files tracked in git.
tracked_data="$(git ls-files | grep -E '^data/|(^|/)\.env$' || true)"
if [ -z "$tracked_data" ]; then
  ok "no runtime/.env files tracked (data/, .env)"
else
  bad "runtime files tracked in git: $tracked_data"
fi

# 2. fpl-core declares no network-capable dependency (ADR-001 privacy-first:
# collects nothing; the engine must be structurally incapable of phoning
# home, checked at the dependency-declaration level, not just by grepping
# usage in source).
hit="$(grep -inE '^(reqwest|hyper|ureq|tokio|curl|surf)\b' crates/fpl-core/Cargo.toml 2>/dev/null || true)"
if [ -z "$hit" ]; then
  ok "fpl-core declares no network-capable dependency"
else
  bad "fpl-core declares a network-capable dependency (violates ADR-001 privacy-first):"
  echo "$hit"
fi

# 3. Reason codes are never reused (RFC-003): no duplicate `code` values in
# the registry.
dupes="$(jq -r '.codes[].code' registry/reason-codes.v1.json | sort | uniq -d || true)"
if [ -z "$dupes" ]; then
  ok "no duplicate reason codes in the registry"
else
  bad "duplicate reason codes found (violates RFC-003 never-reused): $dupes"
fi

# 4. No unsafe Rust anywhere in the workspace.
unsafe_hit="$(find crates -name '*.rs' -path '*/src/*' -exec grep -lE '\bunsafe\s*(\{|fn|impl|trait)' {} + 2>/dev/null || true)"
if [ -z "$unsafe_hit" ]; then
  ok "no unsafe Rust in the workspace"
else
  bad "unsafe Rust found in: $unsafe_hit"
fi

if [ "$fail" = "0" ]; then
  echo "scam-guard family-invariants: PASS"
else
  echo "scam-guard family-invariants: FAIL" >&2
fi
exit "$fail"
