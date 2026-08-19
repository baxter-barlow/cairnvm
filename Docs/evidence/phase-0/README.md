# Phase 0 Evidence

Each complete gate attempt adds exactly one append-only file named
`YYYYMMDDTHHMMSSZ-phase-0-evaluation.toml`. While the latest result is not passed,
a later attempt adds a new whole file; it never edits, combines, or replaces an
earlier evaluation.

The criterion itself is the stable result ID. Every evaluation contains the fixed
header and one `[[results]]` row for every Phase 0 criterion in the exact order in
`Docs/Architecture-Spec.md`. There are no subresults or separate summary fields.
No partial evaluation is publishable.

## Exact schema

This illustrative file parses as TOML and shows the entire schema. It is not gate
evidence and must not be copied as an outcome claim.

```toml
schema_version = 1
phase_id = "phase-0"
tested_commit = "0123456789abcdef0123456789abcdef01234567"
exact_parent = "0123456789abcdef0123456789abcdef01234567"
publication_branch = "main"
grant_lineage_id = "grant-lineage-example"
resource_workload_id = "resource-workload-example"
tested_at_utc = "2026-08-19T12:00:00Z"
commands = ["not run: illustrative schema only"]
environment = "Illustrative environment only; no runtime or service was exercised."
synthetic_data = "Illustrative functional workload: 8 GiB virtual disk, 256 MiB working set, 64 synthetic objects, nonzero writes and authenticated reads. Control-path rationale: sparse writes, reference traversal, and authenticated reads exercise the intended Drive-backed VM control path. Predeclared memory ceiling: 512 MiB from the illustrative runtime quota, measured as peak resident bytes; forced value: 513 MiB. Predeclared repository ceilings: 128 objects and 1 GiB from illustrative primary-provider documentation, measured after reconciliation; forced values: 129 objects and 1 GiB plus one byte. Each forced case must exit nonzero."
redactions = "None; this example contains no account, credential, guest, or live provider data."
limitations = "Illustrative schema only; no Phase 0 criterion was exercised."

[[results]]
criterion_id = "phase-0-colab-policy"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the required review was not run."
shared_binding_id = ""

[[results]]
criterion_id = "phase-0-colab-control-path"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the required probe was not run."
shared_binding_id = ""

[[results]]
criterion_id = "phase-0-drive-synthetic-round-trip"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the required probe was not run."
shared_binding_id = "grant-lineage-example"

[[results]]
criterion_id = "phase-0-oauth-authorization"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the required probe was not run."
shared_binding_id = "grant-lineage-example"

[[results]]
criterion_id = "phase-0-oauth-refresh"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the required probe was not run."
shared_binding_id = "grant-lineage-example"

[[results]]
criterion_id = "phase-0-runtime-memory-control"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the functional and forced-limit probes were not run."
shared_binding_id = "resource-workload-example"

[[results]]
criterion_id = "phase-0-repository-geometry"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the functional and forced-limit probes were not run."
shared_binding_id = "resource-workload-example"

[[results]]
criterion_id = "phase-0-recovery-runtime-loss"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the required review was not run."
shared_binding_id = ""

[[results]]
criterion_id = "phase-0-recovery-drive-trust"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the required review was not run."
shared_binding_id = ""

[[results]]
criterion_id = "phase-0-recovery-freshness-refusal"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the required review was not run."
shared_binding_id = ""

[[results]]
criterion_id = "phase-0-qemu-kvm-probe"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the required probe was not run."
shared_binding_id = ""

[[results]]
criterion_id = "phase-0-qemu-tcg-probe"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the required probe was not run."
shared_binding_id = ""

[[results]]
criterion_id = "phase-0-nbdkit-python-compatibility"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the functional synthetic plugin was not run."
shared_binding_id = ""

[[results]]
criterion_id = "phase-0-security-gates"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the required security gates were not run."
shared_binding_id = ""

[[results]]
criterion_id = "phase-0-ci-required-checks"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; the required CI checks were not run."
shared_binding_id = ""

[[results]]
criterion_id = "phase-0-publication-controls"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; publication controls were not verified."
shared_binding_id = ""

[[results]]
criterion_id = "phase-0-zero-negative-charter-review"
outcome = "BLOCKED"
evidence = ""
limitation = "Illustrative only; exact-candidate review was not run."
shared_binding_id = ""
```

The raw bytes are the whole evaluation; fragments are never combined or
substituted. The header and row fields must be present exactly once and in the
displayed order; extra fields are invalid. `schema_version` is integer `1`.
`phase_id` is `phase-0`. Both commit values are lowercase full 40-hex SHAs, must
equal the expected tested implementation commit, and `exact_parent` must be the
evidence/status candidate's sole exact implementation parent.
`publication_branch` must be nonempty, have no leading or trailing whitespace, be
Unicode NFC, and equal the externally supplied expected branch. `tested_at_utc`
uses valid second-precision RFC3339 UTC and must match the filename timestamp.

The header's non-sensitive opaque `grant_lineage_id` binds one grant attempt and
is repeated as `shared_binding_id` only by the Drive round-trip, OAuth
authorization, and OAuth refresh rows. It binds the attempt even if no grant is
issued. `resource_workload_id` is repeated only by the memory-control and
repository-geometry rows. Every other row uses an empty `shared_binding_id`.
These are local evidence links, not provider, account, credential, object, or
subresult IDs. Both header labels are nonempty strings.

The raw file is at most 65,536 bytes. Reject an over-limit byte sequence before
UTF-8 decoding or TOML parsing, then reject invalid UTF-8, invalid TOML, unknown or
missing fields, wrong field order, and wrong types. This whole-file byte limit is
the only size or count cap in the evaluation schema; every free string and array is
bounded by it. `commands` is a nonempty array of nonempty strings.
`environment`, `synthetic_data`, `redactions`, and `limitations` are nonempty
strings. Evidence and limitation are strings; PASS and FAIL require nonempty
`evidence`, and BLOCKED requires a nonempty `limitation`. Record exact commands or
notebook cells. Do not include credentials, account metadata, guest plaintext,
live Drive object identifiers, or other sensitive values.

## Completeness, aggregation, and status

A publishable file has exactly the required Phase 0 criterion IDs, once each and
in specification order, with only PASS, FAIL, or BLOCKED outcomes. Missing, extra,
duplicate, unknown, or reordered results; invalid outcomes; malformed SHAs; or
wrong phase, parent, branch, version, filename, or candidate context reject the
file before publication.

Within one criterion, any conclusive required-check failure means FAIL even if a
different required check is unavailable or unrun. Otherwise any unavailable,
unrun, or inconclusive required check means BLOCKED. Only success of every required
check means PASS. These are outcome inputs within the criterion, not hidden result
IDs.

For a complete file, any FAIL means `failed`, including a mix of FAIL and BLOCKED;
otherwise any BLOCKED means `blocked`; otherwise all results are PASS and status is
`passed`. Every TOML file in this directory belongs to the evaluation universe; a
wrong-name TOML file is invalid, not ignored, and every historical evaluation must
remain valid. Evaluation filenames are unique and strictly increasing. Before
publication, the reviewer supplies a trusted UTC review clock from outside the
evaluated file, corroborates `tested_at_utc` with command logs, confirms it is
later than the current latest evaluation and no later than that clock, and rejects
a future-dated file. The lexicographically last complete evaluation is then the
latest and alone supplies the Phase 0 result in `ROADMAP.md`. Passed is terminal,
so no later evaluation may be added. With no evaluation, status is `not-started`
only if work has not begun and `in-progress` once work has begun.

## Publication policy

The two-commit publication sequence is strict:

1. Commit the reviewed implementation, then run the complete gate against that
   full `tested_commit` SHA.
2. Add exactly one new complete Phase 0 evaluation TOML file and optionally
   `ROADMAP.md` only when the aggregate phase status changes, in a single-parent
   evidence/status candidate whose exact implementation parent is `tested_commit`.
3. Run `make check` and `make scan-staged` against that exact staged candidate.
4. Obtain independent adversarial review. The independent reviewer reports no
   negative finding only after manually confirming the exact schema, result order,
   shared grant and workload bindings, aggregation, commands, outcomes,
   limitations, redaction, allowed conditional path scope, full SHA, exact parent,
   branch, timestamp, and append-only history.
5. Confirm force-push and branch-deletion protection before publishing the
   single-parent evidence/status commit.

Existing evaluation files are never modified, deleted, or renamed. Evidence is a
reviewed claim, not machine-attested history, and never claims to describe its own
commit. This policy defines no custom Git, history, object, or archive verifier.
Do not call history protected or immutable until the remote controls are verified.
