# FPL Requirements — First-Pass Status

**Version:** 0.1 · 2026-07-05 · Derived from the operator-provided founding docs in this directory (concept spec, RFC-001, ADR-001), which supersede the former placeholder. IDs: FPL-REQ-nnn.

| ID | Founding-doc source | Requirement | Status | Notes |
|---|---|---|---|---|
| FPL-REQ-001 | RFC-001 §9, AGENTS #4 | Every decision carries risk, confidence, reason codes, recommended action | **done** | `engine::Assessment` + `render_warning`; enforced by the `finding()` builder |
| FPL-REQ-002 | ADR-001 | Privacy hierarchy: metadata/structure before content; library collects nothing | **done** | Subjects are caller-supplied only; no network calls anywhere |
| FPL-REQ-003 | concept spec MVP | Domain Intelligence: lookalikes, typosquats, brand-in-host, punycode | **done (offline scope)** | vs `datasets/brand-targets.v1.json`; age/WHOIS/DNS/TLS = `unknown` (needs feeds) |
| FPL-REQ-004 | concept spec MVP | Identity Integrity: display-name impersonation | **done (text scope)** | Confusable folding ("Michael SayIor" case); avatar/banner similarity deferred (needs images) |
| FPL-REQ-005 | concept spec §6 | Command detection: structure, not semantics | **done** | 12 structural patterns; talking *about* commands stays silent |
| FPL-REQ-006 | concept spec §4/§5 | Recruiter/social-engineering mechanics | **done (ask-mechanics scope)** | Seed-phrase/prepayment/gift-card/remote-access asks; account-history signals deferred (needs platform data) |
| FPL-REQ-007 | RFC-001 §5, unified scope §3.2 | Risk Engine with unknown/conflict semantics matching the published contract | **done** | RFC-002 implemented: max-severity level (canonical) + derived 0–100 score (null off the severity axis) |
| FPL-REQ-008 | unified scope §7 | Wallet-facing detection over decoded intents | **done** | `intent-allowance` detector; accepts transaction-intent.v1 and the wallet decoder's bare shape (`cipherlayer-cli decode \| scam-guard check intent -`) |
| FPL-REQ-009 | contract §2 | All outputs conform to detector-output.v1; all codes registered | **done** | Schema-validation + registry-coverage tests in CI |
| FPL-REQ-010 | concept spec MVP | Link Reputation (sandboxing, redirects, landing pages) | **deferred** | Needs a sandbox + network; URL host checks folded into Domain Intelligence meanwhile |
| FPL-REQ-011 | concept spec §3 | Behavioral Engine (DM rates, account age, mass follows) | **deferred** | Needs platform telemetry; belongs to a platform adapter RFC |
| FPL-REQ-012 | concept spec §8 | Conversation Risk modes A/B/C with consent framework | **partial** | Mode-B-class checks exist as explicit calls; the consent framework is an integrator obligation, with [RFC-006](RFC-006-Privacy-Consent-Model.md) in draft review |
| FPL-REQ-013 | concept spec §9, RFC track | AI layer | **deferred by design** | Deterministic system first; `model_assisted` provenance class reserved |
| FPL-REQ-014 | RFC-001 §12 | Assume adversarial input | **partial** | Versioned synthetic adversarial corpus is an executable regression floor; evasion-resistance (leet/spacing tricks beyond the confusable table) grows by data and measured corpus coverage |
| FPL-REQ-015 | RFC-001 §12 | Maintain measurable detection quality | **partial** | `datasets/adversarial-corpus.v1.json` covers supported mechanics plus benign controls; CI asserts recall for corpus cases and zero high-severity false positives. It is not a real-world efficacy benchmark yet. |
| FPL-REQ-016 | Operator decision, 2026-07-24 red-team session (real X DM/tweet samples) | Base-rate solicitation flagging: airdrop/presale hype and unsolicited crypto-denominated payout/job offers, flagged on topic rather than mechanic alone | **done (named exception to RFC-001 §2)** | `SG-PROMO-001`/`-002` (`detectors/promo.rs`); risk capped at **Medium**, never High/Critical, to bound false-positive cost against legitimate airdrops and crypto-industry offers. `SG-IMP-002` (false endorsement claim) shipped alongside is an ordinary mechanic, not part of this exception. |

## Named exception: base-rate solicitation flagging (FPL-REQ-016)

RFC-001 §2 commits this tool to detecting fraud *mechanics*, not opinions — the whole design deliberately avoids "this topic is usually a scam" verdicts. The operator overrode that default for two narrow categories after reviewing real, unsolicited X activity: unsolicited crypto job/payout offers and airdrop/presale hype. Real airdrops and real crypto-industry payouts exist, so this is a conscious false-positive trade, not a mechanic discovery — bounded by capping `SG-PROMO-*` at Medium risk (never High/Critical) so it can never alone drive a Critical/High overall assessment, and by keeping the two codes in their own registry family (`PROMO`) so consumers can filter or discount them independently of mechanic-based codes. Extending this exception to other topics (e.g. "any job offer via DM") requires a new operator decision, not silent pattern-matching by analogy.

Response-layer actions beyond warnings (friction, verification, suspension — concept spec "Response Layer") are platform-integration concerns: FPL emits assessments; platforms act.

## Requirements-readiness gate

Before technical planning for an ambiguous, cross-cutting, or materially security-, privacy-, legal-, or protocol-sensitive Scam Guard change:

1. Cite the operator request and the applicable `FPL-REQ-*`, accepted RFC, ADR, contract, or consumer requirement. Do not manufacture missing product requirements.
2. State independently verifiable user or consumer scenarios and measurable acceptance criteria without choosing implementation details prematurely.
3. Mark every material authority gap as `[NEEDS CLARIFICATION: question — decision owner]`.
4. Check that scope boundaries, failure behavior, privacy/data needs, and contract/versioning effects are explicit and mutually consistent.
5. Record `ready` or `not-ready`. A `not-ready` result stops technical planning and implementation until the named authority resolves the blockers; a bounded experiment may continue only when it cannot silently decide them.

Keep this pass inside the task's existing plan or review note. Do not create a parallel specification tree merely to satisfy the gate.

## November 2026 bounded experiment

The [reboot baseline](reviews/2026-11-scam-guard-baseline.md) records the
readiness gate. The separate offline snapshot/diff binary is experimental
observation tooling, outside detector-output.v1 and the risk engine. It does
not promote FPL-REQ-010, 011, 012 or 013 to done. Message import schemas and
synthetic controls do not establish consent or live platform access.
