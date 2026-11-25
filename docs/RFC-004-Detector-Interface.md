# RFC-004 — Detector Interface

**Version:** 0.1 · **Status:** Draft · **Date:** 2026-07-16 · Follows RFC-001 §5/§11, RFC-002 §2, RFC-003, and formalizes `contracts/detector-interface-v0.1.md` (contract v0.1.0) — this RFC restates and extends that contract's normative text; it does not change the wire shape and does not supersede the pinned contract artifact consumers vendor.

## 1. Purpose

RFC-001 §5 names the Detector and Risk Event; RFC-002 defines how findings combine; RFC-003 governs the codes findings cite. This RFC is the missing middle layer: the normative shape of a detector itself — identity, the subjects it accepts, the finding it must emit, and (§9) the one transport binding presently in production use (the wallet's managed subprocess, ADR-018). It is written against a working implementation (`fpl-core`, `fpl-cli`), not ahead of one.

## 2. Detector model

A **detector** is a named, versioned, independent component (RFC-001 §11: detectors operate independently) that:

- declares the `SubjectKind`s it accepts via `accepts(kind) -> bool`;
- examines exactly one `Subject` per call and returns zero or more findings — silence is a legal result and means "no pattern matched," never "safe" (§6);
- carries a stable identity, `DetectorId { name, version }`, echoed on every finding it produces (contract §2 provenance).

**Identity.** `name` is a short kebab-case slug unique within a deployment (e.g. `domain-intelligence`, `intent-allowance`); `version` is the detector's own semver, independent of the dataset version it may read (`fpl-core::dataset` — data changes bump `dataset_version`, not detector `version`) and independent of the wire contract version. Two detectors with the same `name` and different `version` are the same detector at different points in time, not two detectors.

**Registration.** v0.1 has no dynamic discovery or plug-in protocol — an explicit non-commitment carried from contract §6. The reference implementation (`fpl_core::Suite`) is a static, compiled-in registration: a fixed struct field per detector, fanned out by `SubjectKind` in `Suite::evaluate`. A detector registry (install/enable/disable detectors without a rebuild) is future work and would be its own RFC; nothing here should be read as ruling it out.

**Independence.** A detector MUST NOT depend on another detector's output to decide its own. The Risk Engine (RFC-002), not detector-to-detector coupling, is where findings combine. `IntentDetector`, for example, evaluates the decoded intent standalone; it does not consult the domain detector even when both run over data from the same transaction.

## 3. Subject types

Per contract §1, v0.1 recognizes six subject kinds. A `Subject` is `{ kind, value, chain_id? }`; `value` is subject-kind-dependent:

| `kind` | `value` holds | `chain_id` | Detectors accepting it (reference impl) |
|---|---|---|---|
| `domain` | a bare registrable-or-deeper hostname | unused | domain-intelligence |
| `url` | a full URL; the detector extracts the host (stripping scheme, userinfo, path, port) | unused | domain-intelligence |
| `address` | an EVM address string | optional | none offline (needs a reputation feed; reserved) |
| `contract` | an address plus chain context | required | none offline (SG-CON-001 is reserved for when one exists) |
| `transaction_intent` | the consumer-assigned intent id (not the intent itself — see below) | required | intent-allowance |
| `message_text` | text the caller is explicitly entitled to check (ADR-001 privacy hierarchy: the library never collects it) | unused | command-detection, high-consequence-asks, identity-integrity |

`transaction_intent` is the one kind whose evaluation is not a pure function of `Subject` alone: the decoded `transaction-intent.v1` JSON the wallet (or any consumer) already produced is passed as a second argument (`evaluate_intent(subject, intent_json)`), never re-derived by this library from raw calldata. Scam Guard decodes nothing on-chain; it reasons over a decoding the consumer performed and is accountable for. A detector accepting `transaction_intent` MUST read that JSON tolerantly (both the full contract shape and a bare `{kind, allowance}` decoded-action shape, per `IntentDetector::evaluate_intent`) and MUST answer `unknown` (§6), never a severity, when the action `kind` itself is `"unknown"` — an intent this library cannot decode is not evidence of anything.

`address` and `contract` are declared in the contract but have no accepting detector in the current MVP (`docs/requirements.md` FPL-REQ-010/011); a consumer that submits one today gets an empty finding set, which is silence, not a safety claim.

## 4. Wire contract: `detector-output.v1`

Every finding is exactly one instance of the schema at `schemas/detector-output.v1.json` (mirrored at `exports/detector-output.v1.json`, checksum in `exports/SHA256SUMS`). `additionalProperties: false` with a namespaced `ext` object is the only extension point (schema description); a detector MUST NOT invent top-level fields. Required fields, normatively:

- `schema_version` — matches `^1\.[0-9]+$`; the reference implementation currently emits `"1.1"` (`fpl_core::types::SCHEMA_VERSION`).
- `output_id` — a UUID unique per finding (the reference implementation uses UUIDv7 for rough time-ordering; the schema only requires `format: uuid`).
- `detector` — `{ name, version }`, §2.
- `evaluated_at` — RFC3339 timestamp of the evaluation, not of subject creation.
- `subject` — an echo of exactly what was evaluated (§3); consumers MUST be able to reconstruct what triggered a finding from this field alone.
- `risk_level` — §5.
- `confidence` — §5.
- `reason_codes` — non-empty array of `SG-<FAMILY>-<NNN>` codes from the RFC-003 registry; `finding()` (the shared builder every detector uses) panics if called with zero codes, so "a verdict without reasons" is not constructible in the reference implementation.
- `explanation` — human-readable, composed from the reason codes; never a bare verdict.
- `provenance` — §7.

A finding's fields are frozen once emitted; nothing downstream (Risk Engine, consumer aggregation) may rewrite them (contract §3, point 1). Additive optional fields are a schema minor bump; anything that removes a field, narrows a type, or changes a field's meaning is a breaking change and ships as `detector-output.v2.json` with a migration note (contract §4) — the v1 file is never edited to mean something new.

## 5. Severity and confidence semantics

`risk_level ∈ {low, medium, high, critical, unknown}` is the detector's **local**, single-finding assessment — not the aggregate (that is the Risk Engine's `overall`, RFC-002). `low < medium < high < critical` is a total order on the four assessed levels; `unknown` is off that axis entirely (RFC-002 §3, point 4 "Unknown discipline") and MUST NOT be treated as a fifth point below `low` or above `critical` in any comparison a detector or consumer performs.

`confidence ∈ [0, 1]` is how sure the detector is of *its own* finding, not a probability of fraud and not comparable across detectors or detector versions (RFC-002 §4 non-goals: no cross-detector calibration). RFC-002 §3 fixes the one universal threshold: `confidence ≥ 0.7` is *confident*, the only bar that matters for aggregation (severity, conflict) and for a consumer's own weighting (e.g. the wallet's `CONFIDENT_THRESHOLD` in `cipherlayer-risk`, currently `0.5` — a consumer MAY choose a different confident-threshold for its own aggregation logic than the Risk Engine's RFC-002 default, but MUST NOT present a below-threshold finding as if it had cleared the bar).

A detector sets its own `confidence` honestly for what it can actually establish: an exact skeleton match against a known target dataset is high confidence (0.9); an edit-distance-1 guess is lower (0.6–0.75); a decoder that could not classify the input is `unknown` at whatever confidence reflects how sure the detector is that it *couldn't* classify it (frequently still high — being sure you don't know is not the same as not knowing how sure you are).

## 6. Unknown semantics

`unknown` is a legal, expected, first-class `risk_level` — not an error, not a missing value, and never mapped to `low` by a detector or a consumer (contract §2, RFC-002 §3 "Unknown discipline", this is the CL-FPL-003 invariant on the wallet side). A detector emits an explicit `unknown` finding when it can identify that evidence is missing for a dimension it would otherwise assess (domain age/DNS/TLS for an exact known-domain match; an intent action it could not decode). This is distinct from **silence** (returning zero findings), which means the detector found no pattern to report at all — also not a safety claim, but not the same signal: an explicit `unknown` finding says "I looked and could not tell," while silence says "nothing in my scope matched." Both MUST be treated identically by an aggregator that has no other evidence (RFC-002 §3 point 4: no findings at all aggregates to `unknown`), but a detector SHOULD prefer an explicit `unknown` finding over silence whenever it can name what it could not assess, because the explanation carries information silence cannot.

The domain-intelligence detector's exact-match case is the canonical illustration: a `low` finding ("matches the known target") is paired with an `unknown` finding ("age/DNS/TLS not assessed offline") for the same subject, precisely so an aggregator cannot average the pair into a quiet, unearned `low`.

## 7. Provenance

`provenance.data_source_class ∈ {local_heuristic, local_dataset, remote_feed, model_assisted}` records *how* a finding was produced, not how confident the detector is (§5 already carries that). `model_assisted` findings are advisory-grade by definition (contract §2) and MUST be labeled as such wherever they are surfaced — no MVP detector uses this class today; it is reserved (RFC-001 §13, "AI-assisted Detection" is future work, not present capability).

`dataset_version`, when the detector consulted a versioned local dataset (`datasets/brand-targets.v1.json`, `datasets/adversarial-corpus.v1.json`), is the exact version string that dataset carried at evaluation time, so a finding remains interpretable after the dataset is later revised.

`provenance.mock`, when `true`, marks a finding produced by a detector that demonstrates the contract without performing real detection (the SG-MOCK-001 family, RFC-003 §2). Consumers MUST surface `mock: true` distinctly — the wallet's `MockDetector` (`cipherlayer-risk`) and its own `CIPHERLAYER_FPL_MODE=mock` escape hatch (§9) are the reference example of never letting a mock finding pass as a production detection.

## 8. Versioning and deprecation

- **Contract version** `0.1.0` (`contracts/detector-interface-v0.1.md` §4) versions the interface as a whole; **schema instances** carry their own `schema_version` (§4 above). These are independent axes — the contract can gain a new obligation (a minor contract revision) without the wire schema changing, and vice versa.
- **Reason codes** never change meaning, are never renumbered, and are never deleted once published; deprecation is a flag on the registry entry, not a removal (RFC-003 §3, binding on this RFC too — nothing here relaxes it). A detector MAY stop emitting a deprecated code for new findings; it MUST NOT reuse the code for a different meaning.
- **Detector version** bumps are the detector author's own semver; this RFC does not mandate a scheme beyond "two different behaviors MUST NOT share a version string." A **dataset version** bump (data changed, detection logic did not) is not a detector version bump — `fpl_core::dataset`'s doc comment states this convention directly and detector code follows it.
- **Additive vs breaking**, generally: new optional fields, new enum members intended for forward-compatible tolerance (contract §3, consumers must tolerate reason codes they don't recognize — RFC-003 §4), and new detectors are additive. Removing or narrowing a required field, changing a field's meaning, or changing the semantics of an existing enum member is breaking and gets a new major artifact (`detector-output.v2.json`) with a migration note, never an in-place edit of `v1` (contract §4).

## 9. Managed-execution profile (bounded subprocess)

Transport (in-process vs. service vs. subprocess) is an explicit non-commitment of the base contract (contract §6) — this RFC does not mandate one. It does, however, normatively describe the profile actually in production between `scam-guard` and the CipherLayer Wallet (ADR-018), so any consumer choosing the same binding can implement it compatibly rather than reinvent it ad hoc.

**Invocation.** The consumer spawns the `scam-guard` executable per evaluation:

```
scam-guard --json check <subject-subcommand> -
```

where `<subject-subcommand>` is `domain <value>`, `url <value>`, `text -`, or `intent -`; `-` reads the payload from stdin (message text or the decoded `transaction-intent.v1`/bare-decoded-action JSON, §3). `--json` is required in this profile — the human-readable warning rendering is for interactive use, not for a machine consumer.

**Output.** On success the process writes one JSON `Assessment` object to stdout (`{overall, score, rationale, findings, recommended_action}`) and exits `0`. `findings` is an array of `detector-output.v1` instances (§4) — the consumer's obligation is to those instances, not to `overall`/`score`, which are this repository's own Risk Engine (RFC-002) output and MAY be recomputed independently by the consumer over the same `findings` if its own aggregation semantics differ (RFC-002 §3–4 are advisory to a consumer that wants its own engine, normative only for what `scam-guard` itself reports).

**Exit codes.** `0` is the only success code. Any non-zero exit — malformed input, an unreadable file, an intent that fails to parse as JSON — MUST be treated by the consumer as **detector unavailability**, not as a `low`/clean result: the honest response to "the detector couldn't run" is the same `unknown` posture as "the detector ran and found nothing to assess" (§6), surfaced through whatever unavailability channel the consumer's own aggregate carries (the wallet's `detectors_unavailable` list, ADR-018).

**Bounds (consumer-enforced, not scam-guard-enforced).** A consumer running this profile SHOULD bound:

- **input size** — the wallet caps the serialized subject payload at 256 KiB before spawning;
- **output size** — capped at 1 MiB read from the child's stdout, with the excess discarded and the finding treated as detector failure past the cap;
- **wall-clock time** — a configurable timeout (100–30,000 ms, 2,000 ms default in the wallet) after which the child is killed and the call reported as a timeout failure, not a hang. The write-to-stdin path MUST run off the reader thread (or equivalent), because a detector that never reads stdin would otherwise block the write past the pipe buffer and dodge the timeout entirely — this is not a hypothetical, it is exactly the failure the wallet's own subprocess tests reproduce and guard against.

None of these bounds live in `scam-guard` itself — the binary has no self-imposed timeout or output cap; a consumer adopting this profile owns enforcing them, exactly as ADR-018 does.

**Mock escape hatch.** A consumer MAY offer an explicit test/demo-only substitution (the wallet's `CIPHERLAYER_FPL_MODE=mock`, `provenance.mock: true` on every substituted finding, §7). This MUST be operator-invoked and MUST NOT be the behavior when the real binary is merely missing, slow, or erroring — a missing detector is unavailability (above), never a silent downgrade to mock all-clear findings. `CIPHERLAYER_FPL_BIN` (or equivalent) SHOULD let an operator point at a specific managed installation; the default SHOULD be the real detector command, not mock.

**Findings validation.** Before trusting subprocess output, a consumer SHOULD validate: the field surface is exactly the pinned schema's fields (reject unrecognized top-level keys, per `additionalProperties: false`, §4); every `reason_codes` entry exists in the consumer's own pinned copy of the RFC-003 registry (contract §5, RFC-003 §4 — never invent `SG-` codes locally, but also never trust an emitted code the consumer's own pin doesn't recognize as one it can defend); `confidence` is finite and in `[0, 1]`; required strings are non-empty. A finding that fails this check is malformed output, which is detector unavailability (above), not a finding to render.

## 10. Consumer obligations (restated from contract §3, unchanged)

1. Preserve findings verbatim in any aggregate; never drop or rewrite one.
2. Aggregate `unknown` as `unknown` (§6) — absence of evidence is not evidence of safety.
3. Represent confident material disagreement as `conflicting`, both findings visible (RFC-002 §3, point 2 "Conflict").
4. Never present a finding or an aggregate as a guarantee; never use "safe" unqualified.
5. Never let a finding, or its absence, *authorize* anything — findings inform deterministic consumer-side policy (ADR-018's closing line: this is binding on every consumer, not just the wallet).
6. Display or log provenance (§7) alongside the finding it belongs to.

## 11. Relationship to existing artifacts

`contracts/detector-interface-v0.1.md` remains the pinned artifact consumers vendor under `imports/scam-guard/` (its own §4 Distribution procedure is unchanged by this RFC). This RFC is the fuller normative specification the contract file summarizes; where the two could be read as disagreeing, the contract's wire-shape text and the schemas it points to govern the bytes on the wire, and this RFC governs the semantics, lifecycle, and the managed-execution profile around them. Non-commitments carried forward unchanged from contract §6: a detector discovery/registration protocol beyond the static `Suite` (§2), rate limits, dataset *formats* (as opposed to the specific datasets this repo ships), and any transport this RFC does not itself describe.

## 12. Future RFCs

- RFC-005 — Platform Response Policy
- RFC-006 — Privacy & Consent Model
- A detector registry / dynamic discovery protocol (§2)
- `address`/`contract` reputation detectors (needs a network feed; currently silent by design, not by omission)

## 13. Conformance

`fpl-core`'s `contract_conformance` test module is the executable form of §4–§5: `all_detector_outputs_conform_to_published_schema` validates every MVP detector's serialized output against `schemas/detector-output.v1.json`; `registry_invariants_hold` and `emitted_codes_are_registered` enforce RFC-003 §3 against this RFC's §4 reason-codes requirement; `adversarial_corpus_meets_detection_floor` (`datasets/adversarial-corpus.v1.json`) is the regression floor for §5–§6 (a hostile case must reach its asserted minimum severity; a benign case must never raise a medium-or-above finding). The wallet-side subprocess tests (`cipherlayer-risk::tests`, ADR-018) are the executable form of §9.
