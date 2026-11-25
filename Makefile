.PHONY: help fmt lint test ci demo family-check

help:
	@echo "Scam Guard / FPL targets:"
	@echo "  ci             local CI gate: fmt-check + clippy -D warnings + tests"
	@echo "  fmt            format all crates"
	@echo "  lint           clippy with warnings denied"
	@echo "  test           run the full test suite"
	@echo "  demo           run the explainable-warning demo checks"
	@echo "  family-check   Tier-0 offline invariant checks (review loop)"

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

ci:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace
	@./scripts/family-invariants.sh
	@echo "ci gate passed"

family-check:
	@./scripts/family-invariants.sh

demo:
	cargo run -q -p fpl-cli -- check domain breezyhr.us
	@echo "────────────────────────────────────────"
	@echo "Michael SayIor" | cargo run -q -p fpl-cli -- check text -
	@echo "────────────────────────────────────────"
	cargo run -q -p fpl-cli -- capabilities
