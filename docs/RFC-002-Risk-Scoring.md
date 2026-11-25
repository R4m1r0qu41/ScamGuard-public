# RFC-002 — Risk Scoring Engine

**Version:** 0.1 · **Status:** Draft, implemented (fpl-core `engine.rs`) · **Date:** 2026-07-05 · Follows RFC-001 §5 and the RFC track. Written against a working implementation, not ahead of one.

## 1. Purpose

Defines how independent detector findings combine into one assessment: an ordinal **risk level** (canonical), an optional **numeric score** (presentation aid), a rationale, and a recommended action. The wire contract (`detector-output.v1`) is unchanged; scoring is consumer-side semantics.

## 2. Inputs

Findings per subject, each carrying `risk_level ∈ {low, medium, high, critical, unknown}`, `confidence ∈ [0,1]`, reason codes, and provenance (contract §2).

## 3. Canonical output: the level

The ordinal level is authoritative; every downstream decision keys on it, never on the number.

1. **Confidence gate.** A finding is *confident* at `confidence ≥ 0.7`.
2. **Conflict.** If confident findings sit at both ends of the severity axis (some `low`, some `≥ high`), the overall is **`conflicting`** and all findings stay visible. Disagreement is information.
3. **Severity.** Otherwise the overall is the **maximum** assessed level across findings (`critical > high > medium > low`). Fraud evidence does not average away: one critical finding among ten lows is critical.
4. **Unknown discipline.** `unknown` is not on the severity axis. If the only assessed findings are `low` **and** any finding is `unknown`, the overall is **`unknown`** — a lookalike check that passed plus an age check that couldn't run is *not* a pass. No findings at all is also `unknown` (absence of evidence ≠ evidence of safety).

## 4. Numeric score (presentation aid)

Platforms asked for a 0–100 number (concept spec "Risk Engine"). The number is **derived, deterministic, and subordinate** to the level:

```
base(low)=10  base(medium)=40  base(high)=70  base(critical)=90

score = min(100, round( max_i[ base(level_i) · (0.6 + 0.4·confidence_i) ]
                        + 5 · max(0, n_confident_assessed − 1) ))
```

- The dominant finding sets the mass; each *additional* confident assessed finding adds +5 (corroboration matters, but sub-linearly).
- **`unknown` and `conflicting` assessments carry no score** (`null`). A number would fake precision exactly where we have none.
- The score MUST never be compared across different detector sets or versions as if calibrated; it is a display aid, not a probability.

## 5. Non-goals

No probabilistic calibration, no learned weights, no cross-subject accumulation (a user-level reputation score is a future RFC with its own privacy analysis per ADR-001). No score-based automation: platform responses key on the level and reason codes.

## 6. Conformance

`fpl-core::engine` implements §3–§4 verbatim; the unit tests in `engine.rs` are the executable form of the rules above (unknown-never-launders, max-severity, conflict, score bounds and null cases).
