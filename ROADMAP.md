# Roadmap

This file is the sole authority for mutable phase status. Gate criteria are defined only in `Docs/Architecture-Spec.md`; the table below mirrors stable criterion IDs
without restating or amending their meaning.

A valid snapshot is a passed prefix, optionally followed by one failed,
in-progress, or blocked frontier, with every later phase not-started. All phases
may be passed. Passed is terminal by policy and requires the manual full-SHA,
exact-parent, and total-result evidence review defined by the specification.
Phase IDs are stable and unique.

<!-- cairnvm-contract:phase-status -->
| phase | id | status |
|---|---|---|
| 0 | phase-0 | in-progress |
| 1 | phase-1 | not-started |
| 2 | phase-2 | not-started |
| 3 | phase-3 | not-started |
| 4 | phase-4 | not-started |
| 5 | phase-5 | not-started |

<!-- cairnvm-contract:implementation-status -->
| component | status |
|---|---|
| CLI package and cairnvm entry point | implemented-scaffold |
| Read-only preliminary doctor diagnostics | implemented-scaffold |
| Independent launcher package boundary | implemented-scaffold |
| Quality, artifact, and secret-scanning gates | implemented-scaffold |
| Drive, cryptography, formats, and bootstrap | not-implemented-phase-1 |
| Internal block engine and offline checkpoints | not-implemented-phase-2 |
| Live checkpoints and internal backpressure | not-implemented-phase-3 |
| NBD, QEMU, supervision, and guest integration | not-implemented-phase-4 |
| Operational and privacy hardening | not-implemented-phase-5 |

<!-- cairnvm-contract:phase-ownership -->
| phase | owns |
|---|---|
| 0 | feasibility, scaffold boundaries, and honest evidence |
| 1 | formats, cryptography, Drive, bootstrap, and provider primitives |
| 2 | internal block requests, local durability, and offline checkpoint composition |
| 3 | live checkpoints and internal backpressure admission, refusal, and status |
| 4 | NBD wire and errors plus QEMU, supervisor, operator, and guest composition |
| 5 | operational and privacy hardening |

<!-- cairnvm-contract:phase-gate-criterion-refs -->
| phase | criterion_id |
|---|---|
| 0 | phase-0-colab-policy |
| 0 | phase-0-colab-control-path |
| 0 | phase-0-drive-synthetic-round-trip |
| 0 | phase-0-oauth-authorization |
| 0 | phase-0-oauth-refresh |
| 0 | phase-0-runtime-memory-control |
| 0 | phase-0-repository-geometry |
| 0 | phase-0-recovery-runtime-loss |
| 0 | phase-0-recovery-drive-trust |
| 0 | phase-0-recovery-freshness-refusal |
| 0 | phase-0-qemu-kvm-probe |
| 0 | phase-0-qemu-tcg-probe |
| 0 | phase-0-nbdkit-python-compatibility |
| 0 | phase-0-security-gates |
| 0 | phase-0-ci-required-checks |
| 0 | phase-0-publication-controls |
| 0 | phase-0-zero-negative-charter-review |
| 1 | phase-1-reviewed-formats-crypto-drive-bootstrap-primitives |
| 1 | phase-1-trusted-freshness-and-rollback-tests |
| 1 | phase-1-finite-versioned-provider-inventory |
| 1 | phase-1-provider-validation-evidence |
| 1 | phase-1-independent-security-approval |
| 2 | phase-2-reviewed-offline-block-contract |
| 2 | phase-2-fencing-and-fresh-head |
| 2 | phase-2-four-way-remote-composition |
| 2 | phase-2-independent-recovery-approval |
| 3 | phase-3-live-checkpoint-recovery |
| 3 | phase-3-internal-backpressure-contract |
| 3 | phase-3-live-fault-composition |
| 3 | phase-3-independent-live-approval |
| 4 | phase-4-reviewed-external-integration |
| 4 | phase-4-nbd-wire-error-tests |
| 4 | phase-4-qemu-supervisor-operator-guest-tests |
| 4 | phase-4-independent-integration-approval |
| 5 | phase-5-operational-privacy-hardening |
| 5 | phase-5-recovery-drill-and-report-only-gc |
| 5 | phase-5-independent-final-approval |

## Phase 0 — Feasibility scaffold

Implemented today: the CLI and entry point, preliminary read-only doctor, the
independent launcher package boundary, and quality, artifact, and secret-scanning
gates. Release/bootstrap verification and all data-path behavior remain absent.
Phase 0 work has begun and no evaluation exists. Once evaluations exist, only the
latest complete evaluation supplies the status. A partial evaluation is never
publishable. Gate meaning lives only in the specification; the ID projection above
prevents hidden or duplicate work. The KVM probe uses KVM when available, and the
distinct TCG fallback probe remains required.

## Phase 1 — Primitives

Own reviewed formats, cryptography, Drive, bootstrap, recovery, launcher/provider
primitives, and an independently trusted freshness source or anchor. No mechanism,
provider registry, or inventory is selected, populated, or approved in this
snapshot.

## Phase 2 — Offline block engine

Own internal request semantics, local durability, and offline checkpoint
composition. Its fencing, authority, anchor, retry, and four-way mutation criteria
are defined only by the specification IDs above; no Phase 2 behavior is implemented
in this snapshot.

## Phase 3 — Live checkpoints

Own live checkpoint/recovery behavior and the bounded internal backpressure
admission, refusal, and status interface. Recompose approved provider primitives at
every live remote mutation boundary.

## Phase 4 — External integration

Own NBD callbacks, wire behavior, errors, and QEMU, supervisor, operator, and guest
composition through a reviewed Linux design and executable fault injection.

## Phase 5 — Operational and privacy hardening

Own backup/export, fresh-operator recovery drills, privacy and retention review,
and report-only remote reachability. Destructive remote garbage collection remains
out of scope for v1.

Publication is not completed remote durability; completion requires both required
provider objects and the independently trusted anchor to reconcile as
present-as-intended for the authenticated checkpoint identity, parent, references,
and required head relationship.
