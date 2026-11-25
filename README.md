# Scam Guard — Fraud Prevention Layer (FPL)

**Status: first working pass.** This repository is the sibling Fraud Prevention Layer of the CipherLayer family. Its public product skin is **Scam Guard**; its engine is a modular, privacy-preserving, platform-agnostic fraud-detection framework designed to serve social networks, messaging platforms, email, browsers, and wallets alike.

**What exists today:** the versioned detector integration contract (v0.1), the operator's founding docs (`docs/` — concept spec, RFC-001, ADR-001), and the **first-pass MVP engine**: six deterministic detectors (domain intelligence, identity integrity, command detection, high-consequence asks, intent allowance mechanics, Medium-capped crypto promotion), a unified risk engine with unknown/conflict semantics, explainable warnings in the concept spec's exact shape, and the `scam-guard` CLI. Offline and deterministic by design: anything needing network evidence answers `unknown`, never `low`. See `docs/requirements.md` for the honest status table.

```bash
scam-guard check domain breezyhr.us          # lookalike of breezy.hr → High, SG-DOM-001
echo "Michael SayIor" | scam-guard check text -   # homoglyph impersonation → High, SG-IMP-001
cipherlayer-cli decode ... | scam-guard check intent -   # wallet weave: allowance mechanics
scam-guard capabilities                      # what it can and cannot see
```

## This repository owns

- the **detector interface** (contract + schemas) — the one integration surface all consumers share
- the **detector registry** (future)
- the **Reason Code registry** (`registry/reason-codes.v1.json`, operative instance; schema in `schemas/`)
- phishing / impersonation detection (**first pass: domain + identity detectors**)
- malicious-link and command-injection detection (**first pass: command structure**; link sandboxing future)
- wallet-drainer pattern detection (**first pass: allowance mechanics over decoded intents**)
- fraud-mechanics classification (**first pass: high-consequence asks**)
- explainable risk outputs (contract v0.1, normative)
- privacy-preserving platform adapters (future)
- standalone Scam Guard product surfaces (future)

## Design posture (from the unified scope §7)

- Detect **fraud mechanics** (lookalike domains, impersonation, command-injection asks, allowance-drain patterns) with explainable, proportional responses — not "bot/not-bot" account classification.
- Every output carries a **Risk Score, Confidence, and machine-readable Reason Codes** a platform's Trust & Safety and legal teams can defend.
- No opaque AI-only verdicts. Unknown is a first-class answer.
- Platform-agnostic: wallets and browsers are two consumers among many; most fraud happens on Web2 surfaces.

## Consumers and dependency direction

```text
scam-guard ──publishes detector contract──► wallet
scam-guard ──publishes detector contract──► browser
```

Scam Guard **must not depend on wallet or browser internals.** Consumers vendor a pinned copy of `contracts/` + `schemas/` with version, commit hash, and checksum; see `contracts/detector-interface-v0.1.md` §Distribution.

## Layout

```text
contracts/detector-interface-v0.1.md   normative integration contract
schemas/detector-output.v1.json        one detector finding (wire format)
schemas/reason-codes.v1.json           Reason Code registry schema (seed snapshot in examples)
registry/reason-codes.v1.json          operative Reason Code registry (v1.1)
datasets/brand-targets.v1.json         impersonation-target dataset (versioned data)
datasets/adversarial-corpus.v1.json    synthetic adversarial + benign regression corpus
crates/fpl-core                        detectors + risk engine + contract types
crates/fpl-cli                         the `scam-guard` binary
docs/                                  operator founding docs + requirements.md status
```

## License

Apache-2.0 — see [`LICENSE`](LICENSE). Contributions require a DCO `Signed-off-by` line; see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## November offline evidence experiment

A separate `scam-guard-snapshot` binary compares caller-supplied repository
snapshots without executing files, fetching URLs or changing FPL findings.
It reports changed installer/instruction/dependency surfaces and shared public
destinations as observations; technical assessment remains `unknown`.

```sh
cargo run --offline --locked -p fpl-cli --bin scam-guard-snapshot -- datasets/experimental/github-after.v1.json --previous datasets/experimental/github-before.v1.json
```

Add `--json` after `--` for machine-readable output.
Selected X/SMS import formats are design-only, with synthetic fixtures; live
platform access, malware scanners and model assistance remain unimplemented.
