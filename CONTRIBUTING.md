# Contributing — Scam Guard / FPL

## License and DCO

Contributions are accepted under [Apache-2.0](LICENSE). Every commit must carry a
`Signed-off-by` line (`git commit -s`), certifying the [Developer Certificate of
Origin](https://developercertificate.org). Security findings: see `REVIEW-GUIDE.md`
in the family repo.

## Ground rules

1. This is a sibling product, not a module of wallet or
   browser — never add dependencies on their internals.
2. Changes to `contracts/` or `schemas/` are breaking-change-managed: additive =
   minor bump; breaking = new versioned file + migration note.
3. Every detector output must carry Reason Codes, confidence, and provenance.
   `unknown` is a legal, first-class output — no opaque verdicts.
4. No placeholder engines or mock integrations that could be mistaken for real
   detection capability.

## Workflow

```bash
make fmt lint test   # or: make ci
```

- Small, auditable increments; one logical change per commit.
- Conventional commit messages (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`).
- No history rewriting, no force-push, no new remotes or pushes without operator
  authorization.
- Never commit secrets or datasets with personal data.
