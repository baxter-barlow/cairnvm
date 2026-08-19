# Launcher Agent Guide

The launcher is a separately reviewed root of trust. These rules are stricter than
the repository-wide guide.

- Never depend on or import `cairnvm-runtime`; verify it as untrusted input.
- Never execute a downloaded artifact unless an independently reviewed
  release-verification and authorization boundary accepts it; fail closed on any
  invalid, ambiguous, or unsupported state.
- Concrete verification and authorization mechanisms are deferred to a Phase 1
  ADR/spec gate with executable acceptance criteria and an independent adversarial
  review that reports no negative finding.
- Do not select or embed release-authority configuration in Phase 0. Never embed
  bearer or user credentials, private keys, or other secrets.
- Use bounded parsing, atomic replacement, explicit timeouts, and fail-closed errors.
- Keep tests offline with synthetic artifacts; cover invalid, truncated, ambiguous,
  unsupported, and interrupted inputs without assigning a deferred mechanism.
- Any executable behavior requires an independent adversarial security review that
  returns no negative finding.
