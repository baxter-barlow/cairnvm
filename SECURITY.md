# Security Policy

CairnVM has no supported release. The repository is an experimental scaffold and
must not be trusted with valuable guest data or production credentials.

## Reporting

Use [GitHub private vulnerability reporting](https://github.com/baxter-barlow/cairnvm/security/advisories/new)
for suspected vulnerabilities. The public repository setup must keep that channel
enabled. Do not post credentials, decrypted blocks, OAuth material, repository
keys, or exploitable Drive object identifiers in a public issue. Include the
affected revision, reproduction steps using synthetic data, and expected impact.

Reports are reviewed as owner availability permits; this experimental project does
not guarantee an acknowledgment deadline. If the private form is temporarily
unavailable, retain sensitive details and retry rather than opening a public issue.

## Development rules

- Use disposable test accounts and least-privilege OAuth scopes for manual trials.
- Keep passphrases, secret or private keys, live credentials, and live account or
  Drive object identifiers out of arguments, source, fixtures, logs, and evidence.
  Phase 0 selects no release-authority configuration; synthetic offline fixtures
  must not assign a deferred verification mechanism.
- Authenticate remote objects before parsing semantics; enforce size and count
  limits before allocation or decompression.
- Treat malformed metadata, ambiguous heads, rollback evidence, and writer conflicts
  as hard stops.
- Never execute a downloaded runtime until an independently trusted launcher has
  enforced an independently reviewed release-verification and authorization boundary.
- Concrete verification and authorization mechanisms are deferred to a Phase 1
  ADR/spec gate with executable acceptance criteria and an independent review that
  reports no negative finding.
- Do not add destructive remote garbage collection in v1.

The detailed threat model and bootstrap requirements are normative in
`Docs/Architecture-Spec.md`.
