# Development and contribution policy

## External contributions

CairnVM is not accepting unsolicited code, documentation, design, patch, or other
contributions. Do not open a pull request or send a patch unless Baxter Barlow has
invited the contribution in writing and a separate signed agreement governing
authorized use and inbound intellectual-property rights is already in place.
Unsolicited submissions will be closed without review or use.

Do not open a public issue. Report suspected vulnerabilities only through the
private channel in `SECURITY.md`, without credentials, personal data, guest data,
or other third-party confidential information.

## Owner-authorized development workflow

The workflow below is for the copyright holder and separately authorized
collaborators. It does not grant any license or permission. CairnVM is
pre-development security-sensitive infrastructure; keep authorized changes small,
reviewable, and honest about their verification scope.

1. Read `AGENTS.md`, `OVERVIEW.md`, and the relevant section of
   `Docs/Architecture-Spec.md`.
2. Add a failing test for changed behavior.
3. Implement the smallest passing change.
4. Update documentation required to describe the implementation.
5. Run `make lint typecheck test`. Run `make security` after dependency changes.
6. Stage only the intended files after reviewing the exact diff.
7. Run `make check` against that exact staged candidate; it rejects tracked drift
   and nonignored untracked files. Then run `make scan-staged` before committing.
   If either requires a correction, restage the exact files and repeat both staged
   gates.
8. For architecture, durable-format, recovery, trust-boundary, security, or agent-
   guide changes, obtain an independent adversarial subagent review of the exact
   staged candidate. Approval requires no negative finding. Otherwise revise, then
   repeat the local checks, staging, both staged gates, and review until it does.
9. Commit the tested and, when required, reviewed implementation. If a Phase 0
   gate was exercised, create a single-parent follow-up evidence/status commit
   that adds exactly one new complete Phase 0 evaluation TOML file and changes
   `ROADMAP.md` only when the aggregate phase status changes. It may change no
   other path. Repeat both staged gates, then obtain an independent review of the
   exact staged evidence/status candidate. The reviewer must manually confirm the
   tested implementation commit's full SHA, that the evaluation's `tested_commit`
   and `exact_parent` both equal the candidate's sole parent, publication-branch
   binding, allowed-path scope, append-only history, timestamp and trusted-clock
   ordering, completeness, aggregation, redaction, and no negative finding.
   Before publication, verify that the remote branch blocks force pushes and
   deletion; do not claim protected or immutable history until that setting is
   confirmed. Evidence must not identify its own commit as the tested revision.

Tests must be offline and deterministic by default. Never use production Drive
data, credentials, or guest plaintext as fixtures. Mark environment-dependent
experiments explicitly and store only redacted results.

Those sensitive changes require an ADR when they alter an accepted decision.

## Owner-authorized commands

```sh
make sync       # install the committed lockfile
make format     # apply formatting
make check      # verify the exact staged candidate; reject drift and untracked files
make scan-staged # scan the exact staged content for secrets
make security   # audit the locked environment
```

Do not commit `.env` files, local CairnVM state, guest images, logs containing account
metadata, or unredacted evidence. CairnVM is source-visible proprietary software;
the `LICENSE` notice reserves all rights. Obtain written permission from the owner
before any use or redistribution.
