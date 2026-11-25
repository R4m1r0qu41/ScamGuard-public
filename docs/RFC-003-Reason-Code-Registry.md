# RFC-003 — Reason Code Registry

**Version:** 0.1 · **Status:** Draft, enforced (fpl-core registry tests) · **Date:** 2026-07-05 · Follows RFC-001 §5 ("Reason Code") and the RFC track.

## 1. Purpose

Reason Codes are the defensibility layer: a platform must be able to justify any action by citing them (contract §2), and a user must be able to understand any warning through them (RFC-001 §9). This RFC governs their form, lifecycle, and distribution.

## 2. Form

`SG-<FAMILY>-<NNN>` where FAMILY is an uppercase area tag and NNN a zero-padded ordinal. Allocated families:

| Family | Area | Examples |
|---|---|---|
| ALLOW | Token-allowance mechanics | SG-ALLOW-001 unlimited, -003 blanket operator |
| DRAIN | Wallet-drainer patterns | SG-DRAIN-001 |
| DOM | Domain intelligence | SG-DOM-001 lookalike, -003 punycode, -004 brand-in-host |
| IMP | Identity impersonation | SG-IMP-001 display-name, -002 false endorsement claim |
| INJ | Command/injection asks | SG-INJ-001 |
| ASK | High-consequence asks | SG-ASK-001 seed phrase … -004 remote access |
| CON | Contract reputation | SG-CON-001 unverified |
| UNK | Insufficient evidence | SG-UNK-001 |
| MOCK | Labeled test findings | SG-MOCK-001 |
| PROMO | Unsolicited crypto promotion/recruitment — **base-rate exception to RFC-001 §2** (docs/requirements.md FPL-REQ-016), not mechanic evidence; risk capped at Medium | SG-PROMO-001 airdrop/presale, -002 unsolicited payout offer |

New families require a registry minor bump and an entry in this table.

## 3. Lifecycle (invariants, CI-enforced)

1. **Codes are never reused or renumbered.** A meaning, once published, is permanent.
2. **Deprecation is a flag**, not a deletion: deprecated codes stay in the registry with their meaning so historical findings remain interpretable forever.
3. Every code carries `title` (short, human) and `meaning` (one sentence, precise enough to defend an enforcement action).
4. Additions are **additive minor bumps** of the registry instance (`registry/reason-codes.v1.json`, currently 1.1). Removing or changing the meaning of a code is a breaking change and is not done; a corrected concept gets a *new* code and the old one gets deprecated.
5. Detectors may only emit registered codes (CI: `emitted_codes_are_registered`); the registry may only contain well-formed, unique codes (CI: `registry_invariants_hold`).

## 4. Distribution

The **schema** (`schemas/reason-codes.v1.json`) defines the format and freezes the original 1.0 seed in its examples. The **operative instance** is `registry/reason-codes.v1.json`, exported as `exports/reason-codes-registry.v1.json` with checksums; consumers pin it like any contract artifact. Consumers MUST tolerate codes they do not know (render code + title passthrough), and MUST NOT invent codes in the `SG-` namespace.

## 5. Relation to POL-* codes

Wallet policy reason codes (`POL-XXX-nnn`) are a separate namespace with the same philosophy, owned by the wallet repo. The two never mix in one field: detector findings carry SG-*, policy decisions carry POL-*, and an audit trail may show both side by side.
