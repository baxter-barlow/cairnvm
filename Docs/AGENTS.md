# Documentation Guide

These rules add to the repository `AGENTS.md` for files under `Docs/`.

- `Architecture-Spec.md` is normative; `Architecture-Draft.md` is historical.
- Keep selected constants, limits, transitions, and recovery contracts that the
  specification explicitly mirrors in `architecture-state-model.toml`
  synchronized with the normative prose and exact contract tests.
- Use MUST, SHOULD, and MAY only for testable requirements. State failure behavior,
  bounds, ownership, and crash points explicitly.
- Put accepted decision changes in `ADRs/`; do not silently rewrite incompatible
  durable formats or trust assumptions.
- Store reproducible, redacted gate results under `evidence/<phase>/`. Record the
  revision, environment, command, outcome, and any blocked prerequisite.
- Never include secrets, account identifiers, OAuth responses, guest plaintext, or
  live Drive object identifiers.
- Independently review architecture, durable-format, recovery, security, and trust-
  boundary edits until the reviewer has no negative finding.
