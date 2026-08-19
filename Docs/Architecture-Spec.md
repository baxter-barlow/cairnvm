# CairnVM Phase 0 Architecture Charter

**Scope:** Phase 0 scaffold; mutable status lives only in `ROADMAP.md`

This file is the normative design authority. `Docs/Architecture-Draft.md` is
historical context only. This charter deliberately defines boundaries, ownership,
durability language, and promotion criteria without selecting unimplemented wire,
format, cryptographic, provider, or process mechanisms.

## 1. Current boundary

The repository currently implements a CLI package and entry point, read-only
preliminary doctor diagnostics, an independent launcher package boundary, and
quality, artifact, and secret-scanning gates. It does not implement Drive
persistence, cryptography, block service, checkpoints, bootstrap verification,
NBD, QEMU integration, or supervision. Phase approval exists only in the
`ROADMAP.md` phase-status table under the accounting rules below; gate evidence
exists only in complete evaluation files.

The objective is a recoverable virtual disk for an ephemeral runtime whose durable,
client-authenticated checkpoints may eventually reside in Google Drive. Correct
recovery and honest durability reporting take priority over throughput. Phase 0
tests feasibility and freezes only the cross-phase constraints needed to avoid
unsafe implementation.

## 2. Trust boundaries and invariants

Drive and every Drive object, identifier, listing, property, and response are
untrusted for integrity, freshness, ordering, completeness, and availability.
Provider success is not proof that the intended state exists. Local runtime loss,
process crashes, ambiguous responses, revoked authority, concurrent writers, and
malformed remote input are expected conditions.

The launcher is an independent trust boundary. It must not import or depend on the
`cairnvm-runtime` distribution. Its future release and bootstrap verification must
succeed before any downloaded code executes. The runtime, guest, QEMU, NBD peer,
operator input, recovery input, and logs cross separate boundaries and receive only
the authority needed by their reviewed phase design.

A privileged Colab or compute host can observe or modify plaintext memory, keys,
credentials, guest data, and local state, and can subvert client authentication.
Protecting confidentiality or integrity from a malicious host is out of scope and a
non-goal.

<!-- cairnvm-contract:invariants -->
| id | requirement |
|---|---|
| authenticate-before-semantic-use | Authenticate untrusted remote bytes, identity, parent, and references before semantic use. |
| bounds-before-allocation | Enforce reviewed size, count, depth, and resource bounds before allocation or traversal. |
| no-silent-branch-or-rollback | Refuse ambiguous heads, branches, forks, rollback, missing ancestry, and conflicting state rather than selecting silently. |
| trusted-freshness-or-refuse | Recovery and read-write selection require freshness from an independently trusted anchor or source whose trust does not derive solely from repository objects; otherwise refuse, while read-only diagnosis may label unverified candidates. |
| single-writer-requires-fencing | Every checkpoint attempt requires fresh fencing, authenticated parent/head, and independently trusted freshness authority through reconciliation; belief that no peer exists is insufficient. |
| no-destructive-remote-gc-v1 | V1 may report reachability but never deletes remote objects automatically. |
| no-plaintext-remote-blocks-or-credentials | Never upload plaintext guest blocks, plaintext secrets, or credentials; never log plaintext guest data, credentials, tokens, passphrases, secret-envelope plaintext, keys, or derived keys. |
| launcher-verifies-before-downloaded-execution | The independent launcher verifies the approved release and authorization boundary before downloaded execution. |

Authentication failures, unsupported versions, missing references, malformed
state, exceeded bounds, indeterminate provider outcomes, and lost authority fail
closed. If independently trusted freshness cannot be established, recovery and
read-write selection refuse; read-only diagnosis may report candidates only as
unverified. Authorized later deletion remains an availability risk; Drive is not a
WORM store.

## 3. Components and phase ownership

The intended flow is launcher to runtime supervisor to QEMU and the internal block
service, with a checkpoint worker using a Drive client. The launcher remains
independent. The Drive client is the only runtime component with Drive authority.
The NBD adapter receives neither Drive credentials nor repository keys.

<!-- cairnvm-contract:phase-ownership -->
| phase | owns |
|---|---|
| 0 | feasibility, scaffold boundaries, and honest evidence |
| 1 | formats, cryptography, Drive, bootstrap, and provider primitives |
| 2 | internal block requests, local durability, and offline checkpoint composition |
| 3 | live checkpoints and internal backpressure admission, refusal, and status |
| 4 | NBD wire and errors plus QEMU, supervisor, operator, and guest composition |
| 5 | operational and privacy hardening |

Phase 1 selects authenticated durable formats, cryptography, repository creation and
recovery, OAuth and credential custody, launcher verification and authorization
handoff, Drive access, an independently trusted freshness anchor or source, and
finite provider primitives. Phase 1 must test rollback, deletion, and tampering.
This Phase 0 charter selects no freshness mechanism. The Phase 1 candidate must
select and freeze one before testing it; its trust must not derive solely from
repository objects. Its reviewed lifecycle must cover read/compare, stable
checkpoint binding, advance or attestation, idempotency, crash, concurrency,
authorization loss, and lost or ambiguous update reconciliation. All other
mechanisms remain deferred until reviewed and tested.

Phase 2 defines an internal request boundary independent of NBD. It owns block
bounds, concurrency, ordering, local acknowledgment, flush/FUA behavior, restart
semantics, and offline checkpoint composition through deterministic adapters.

Phase 3 adds live checkpoint scheduling and recovery. Its backpressure surface is
an internal, bounded admission, refusal, and status contract. It does not own NBD
errors, QEMU behavior, guest behavior, or operator presentation.

Phase 4 owns NBD callbacks, wire behavior, error mapping, and composition with QEMU,
the supervisor, operator status, and the guest. It selects Linux process, channel,
readiness, deadline, shutdown, and quiescence mechanisms only through a reviewed
design and executable fault injection.

Phase 5 owns backup/export, recovery drills, privacy, retention, report-only remote
reachability, and other operational hardening. Telemetry remains prohibited unless
a reviewed privacy proposal covers minimization, disclosure, retention, and
reproducible evidence.

## 4. Durability and remote mutation rules

The following terms are not interchangeable.

<!-- cairnvm-contract:durability-levels -->
| level | meaning |
|---|---|
| acknowledged | accepted by the block engine; no restart-survival promise |
| local-durable | survives a process restart only on the same runtime |
| published | checkpoint creation returned success or was discovered remotely |
| reconciled | authenticated provider objects and independently trusted freshness anchor both reconciled to checkpoint identity, parent, references, and required head relationship |

Flush and FUA establish only local-durable state under the reviewed Phase 2 local
contract. They do not imply publication or survival of runtime loss. A caller must
request and receive a separately defined checkpoint result for remote progress.

Among provider objects, referenced immutable data and metadata are created before
their checkpoint, and the checkpoint object is published last. No checkpoint is
reconciled or completed remote durability until both its required provider objects
and independently trusted anchor are reconciled as present-as-intended and bind the
same authenticated checkpoint identity, parent, every reference, and required head
relationship. A conflicting or indeterminate result in either domain fails closed.
Publication alone is not completed remote durability.

Remote mutation calls can have four observed outcomes after reconciliation:
absent, present-as-intended, conflicting, or indeterminate. Ambiguous mutation
results require fresh reconciliation before retry or advance. Retrying must use the
reviewed idempotency behavior for that mutation and must never overwrite, merge, or
choose conflicting state silently.

Every Phase 2 or later checkpoint attempt first freshly authenticates its expected
parent/head and revalidates the independently trusted freshness anchor. It then
runs the reviewed fence-acquisition coordination mutation bound to that exact
pre-acquisition context and reconciles its absent, present-as-intended,
conflicting, or indeterminate outcome. Only present-as-intended acquisition yields
authority, and no other mutation may start before that reconciliation.

Every later remote mutation, including anchor, coordinator, fence-renewal, and
fence-release mutations, binds to the acquired authority. That authority must
remain valid through publication and reconciliation of provider-object and anchor
outcomes. Expiry, revocation, loss, indeterminacy, or a conflicting or indeterminate
anchor outcome fails closed and permits no further mutation. Read-only
reconciliation may diagnose but cannot convert an attempt to success. A retry is a
new attempt: reconcile prior provider and anchor outcomes, then freshly validate
parent/head and anchor and acquire a new fence. Phase 2 composes the four-way rule
across fence acquisition and every referenced data, metadata, checkpoint, anchor,
coordinator, renewal, and release mutation. Phase 3 recomposes those approved
primitives at every live mutation boundary under outage, concurrency, authority
loss, and restart.

## 5. Provider validation inventory

No provider assumptions are accepted by this charter. Before provider behavior is
accepted into Phase 1 design or implementation, Phase 1 must approve the finite,
versioned registry and inventory schema; it then freezes and reviews the finite
design and implementation surface and its provider contracts and inventory.
Completeness is relative only to that frozen reviewed surface and approved
registry, never to an open-ended claim about all provider behavior.

The only pre-inventory exception is the five finite Phase 0 feasibility probes
`phase-0-drive-synthetic-round-trip`, `phase-0-oauth-authorization`,
`phase-0-oauth-refresh`, `phase-0-runtime-memory-control`, and
`phase-0-repository-geometry`. Their evidence may decide feasibility but approves
no provider semantic, implementation assumption, registry entry, or later
validation. The Phase 0 surface, registry, and inventory remain empty and
unapproved.

<!-- cairnvm-contract:provider-registry-fields -->
| record | field | binding |
|---|---|---|
| contract | contract_id | Stable unique identifier within the approved registry version. |
| contract | kind | Exactly provider-primitive, provider-operation, provider-assumption, provider-observable-branch, remote-mutation, or provider-injected-fault. |
| contract | semantic_binding | Exact stable reference to one semantic element in the frozen reviewed design and implementation surface. |
| contract | implementation_test_traceability | Exact implementation and test references when implemented; otherwise an explicit not-implemented marker. |
| item | item_id | Stable unique identifier within the approved inventory version. |
| item | kind | Exactly documentation-and-bounds, deterministic-fake, live-disposable-account, or remote-mutation-lost-response. |
| item | covered_contract_ids | Nonempty stable provider contract IDs covered by this item. |
| item | primary_documentation | Primary provider sources that state or constrain the behavior. |
| item | applicability_and_bounds | Operations, environments, versions, and finite limits to which the item applies. |
| item | deterministic_fake_cases | Exhaustive fake-service cases when the item has provider-observable branches. |
| item | expected_outcomes | Allowed result, reconciliation, retry, refusal, and BLOCKED outcomes. |
| item | live_evidence | Disposable-account evidence for provider behavior when applicable. |
| item | blocked_mapping | Missing prerequisites or inconclusive observations map to BLOCKED, never PASS. |

Contract and item IDs are unique. `provider-operation` is nonmutating; every
provider-mutating call is a `remote-mutation`. Every contract binds to one exact
reviewed semantic element and, once implemented, to its implementation and tests.
Review enumerates the frozen surface and proves exact coverage in both directions:
no surface element is omitted, and no contract has an unknown or stale binding.
Every item has nonempty coverage and every covered ID names a known contract.
`set(contract.contract_id) == union(item.covered_contract_ids)`, so no contract or
item is orphaned and no unknown reference is accepted. Item kinds are limited to
the finite list above. The Phase 1 candidate cannot approve an empty surface,
registry, item-kind set, or inventory. Fake cases, expected outcomes, and live
evidence apply where the behavior requires them; an omission needs an explicit
reviewed not-applicable rationale. Every `remote-mutation` contract must prove
absent, present-as-intended, conflicting, and indeterminate lost-response outcomes.
Every claimed provider behavior requires disposable-account live evidence. Live
work must use synthetic data, least privilege, bounded cost, redacted results, and
no gated-traffic replay.

## 6. Phase criteria

The criteria below are the finite, ordered phase gate sets and the only normative
gate descriptions. Each `criterion_id` is also its stable result ID; there is no
separate subresult namespace. `ROADMAP.md` owns mutable status and mirrors only
these IDs. Every result is PASS, FAIL, or BLOCKED. When no required check fails,
a criterion whose required runtime, service, or evidence is unavailable or unrun
is BLOCKED, never PASS.

Before the two resource probes run, the evaluation must declare one functional
representative nonzero synthetic Drive-backed VM control-path workload, including
exact virtual size, working-set size, object count, read/write work, and why it
exercises the intended control path. It also declares before execution: the memory
ceiling in bytes and its runtime-quota source; the repository object-count and byte
ceilings and their primary-provider-document sources; the exact measurement
procedure; and one forced value strictly above each ceiling. Both probes use the
same declared functional representative nonzero synthetic workload. A no-op,
zero-size, or unjustified tiny case cannot PASS. Each probe must complete within
its predeclared ceiling and its paired forced-over-limit case must be rejected by
the harness with a nonzero process exit. Phase 0 selects no throughput threshold.

The header assigns a non-sensitive opaque `grant_lineage_id` to the one grant
attempt shared by `phase-0-drive-synthetic-round-trip`,
`phase-0-oauth-authorization`, and `phase-0-oauth-refresh`; those rows repeat it
as `shared_binding_id`. The label binds the attempt even if it ends before a grant
is issued. One opaque `resource_workload_id` likewise binds the common declared
workload to `phase-0-runtime-memory-control` and
`phase-0-repository-geometry`; those rows repeat it. Every other row has an empty
`shared_binding_id`. These are local evidence links, not provider, account,
credential, object, or subresult IDs.

Composite criteria use one total outcome rule and create no hidden result IDs.

<!-- cairnvm-contract:phase-criterion-outcomes -->
| condition | outcome | meaning |
|---|---|---|
| any-required-check-fails | FAIL | At least one required check produces a conclusive failure, including when another required check is unavailable or unrun. |
| any-required-check-blocked | BLOCKED | No required check fails, and at least one required check is unavailable, unrun, or inconclusive. |
| all-required-checks-pass | PASS | Every required check succeeds. |

<!-- cairnvm-contract:phase-gate-criteria -->
| phase | criterion_id | criterion |
|---|---|---|
| 0 | phase-0-colab-policy | Review current primary Colab policy for the intended use; PASS requires the intended use to be permitted. |
| 0 | phase-0-colab-control-path | Run one paid-runtime operator control-path smoke test; PASS requires successful start, observation, and stop. |
| 0 | phase-0-drive-synthetic-round-trip | Run one synthetic-object Drive round trip in a disposable account; PASS requires successful create, reconcile, and authenticated read. |
| 0 | phase-0-oauth-authorization | Run one least-privilege interactive OAuth authorization probe in a disposable account; PASS requires a usable grant for the Drive round trip. |
| 0 | phase-0-oauth-refresh | Run one OAuth refresh probe from that grant; PASS requires a fresh usable short-lived token without exposing credentials. |
| 0 | phase-0-runtime-memory-control | Run the declared functional representative synthetic workload on the intended runtime; PASS requires nonzero read/write work within the predeclared byte ceiling and the predeclared forced-over-limit case exits nonzero. |
| 0 | phase-0-repository-geometry | Run the declared functional representative synthetic workload's repository probe; PASS requires nonzero object creation, reference traversal, and authenticated reads within the predeclared object/byte ceilings and the predeclared forced-over-limit case exits nonzero. |
| 0 | phase-0-recovery-runtime-loss | Review the runtime-loss assumption; PASS requires later recovery to rely on no local survivor. |
| 0 | phase-0-recovery-drive-trust | Review the Drive trust assumption; PASS requires later recovery to treat Drive objects, identifiers, completeness, freshness, and deletion as untrusted or unavailable. |
| 0 | phase-0-recovery-freshness-refusal | Review the freshness assumption; PASS requires a later independently trusted non-repository anchor or refusal of recovery and read-write selection. |
| 0 | phase-0-qemu-kvm-probe | Run one QEMU probe using KVM when available; PASS requires either a conclusive unavailable result or successful operation when KVM is available, FAIL means KVM is present but operation fails, and an unrun or inconclusive probe is BLOCKED. |
| 0 | phase-0-qemu-tcg-probe | Run one QEMU TCG fallback probe on the intended runtime; PASS requires successful fallback operation. |
| 0 | phase-0-nbdkit-python-compatibility | Run one nbdkit Python compatibility smoke test on the intended runtime; PASS requires a functional synthetic plugin to import, load, and execute one bounded callback without assigning NBD wire semantics. |
| 0 | phase-0-security-gates | Run the repository security gates against the exact candidate; PASS requires `make security` and the staged secret scan to succeed without an unavailable audit. |
| 0 | phase-0-ci-required-checks | Exercise CI on the tested commit; PASS requires all required GitHub Actions checks to complete successfully and to be configured as required checks on the publication branch. |
| 0 | phase-0-publication-controls | Verify the publication repository and branch controls; PASS requires the publication branch to block force pushes and branch deletion. |
| 0 | phase-0-zero-negative-charter-review | PASS requires that an independent adversarial reviewer of the exact candidate reports no negative finding. |
| 1 | phase-1-reviewed-formats-crypto-drive-bootstrap-primitives | Approve formats, cryptography, Drive and bootstrap primitives, repository creation and independent recovery, malformed-input bounds, compatibility, and deterministic tests. |
| 1 | phase-1-trusted-freshness-and-rollback-tests | Select and freeze an independently trusted freshness anchor or source whose trust does not derive solely from repository objects; this Phase 0 charter selects no mechanism; approve and test anchor read/compare, stable checkpoint binding, advance or attestation, idempotency, crash, concurrency, authorization loss, and lost or ambiguous update reconciliation; recovery and read-write selection fail closed when freshness cannot be established, while read-only diagnosis may report unverified candidates; test rollback, deletion, and tampering. |
| 1 | phase-1-finite-versioned-provider-inventory | Before accepting provider behavior into Phase 1 design or implementation, first approve the finite, versioned schema; then review the frozen design and implementation surface to enumerate every provider-dependent primitive, operation, assumption, observable branch, remote mutation, and injected fault under stable semantically bound contract IDs, plus the constrained inventory item set. |
| 1 | phase-1-provider-validation-evidence | Prove unique IDs and reviewed bidirectional closure from the frozen design and implementation surface to semantic provider contracts and from contracts to constrained inventory items, with no omitted or unknown binding, orphan, or unknown reference; require implementation and test traceability when implemented; satisfy every item's documentation, bounds, fake, live, outcome, and BLOCKED obligations; prove absent, present-as-intended, conflicting, and indeterminate outcomes for every remote-mutation contract. |
| 1 | phase-1-independent-security-approval | An independent reviewer of the format, cryptography, provider, bootstrap, launcher, and recovery candidate reports no negative finding. |
| 2 | phase-2-reviewed-offline-block-contract | Approve and test the internal request, bounds, concurrency, ordering, local acknowledgment, flush/FUA, crash/restart, reconstruction, and branch-refusal contract. |
| 2 | phase-2-fencing-and-fresh-head | Every checkpoint attempt first freshly authenticates its expected parent/head and revalidates the independently trusted freshness anchor, then runs and reconciles the reviewed fence-acquisition operation bound to that pre-acquisition context; only a present-as-intended acquisition yields authority. Bind every later mutation, including anchor, coordinator, renewal, and release mutations, to the acquired authority and keep it valid through provider-object and anchor reconciliation; fail closed on any expired, revoked, lost, indeterminate, or conflicting authority or anchor outcome. |
| 2 | phase-2-four-way-remote-composition | For fence acquisition and every referenced data, metadata, checkpoint-node, freshness-anchor, coordinator, renewal, or release mutation, prove lost-response reconciliation for absent, present-as-intended, conflicting, and indeterminate outcomes; before retry, reconcile provider-object and anchor outcomes and begin a new attempt with fresh parent/head, anchor, and fence acquisition. |
| 2 | phase-2-independent-recovery-approval | An independent reviewer of the block-engine, local-durability, fencing, checkpoint-composition, and recovery candidate reports no negative finding. |
| 3 | phase-3-live-checkpoint-recovery | Approve and test live checkpoint scheduling, sealing, publication, reconciliation, restart, outage, capacity, authority-loss, and branch-refusal outcomes. |
| 3 | phase-3-internal-backpressure-contract | Prove bounded internal admission, refusal, and status behavior before capacity exhaustion without assigning NBD or operator semantics. |
| 3 | phase-3-live-fault-composition | Recompose approved provider primitives at every live remote mutation boundary under lost response, outage, concurrency, restart, and authority loss. |
| 3 | phase-3-independent-live-approval | An independent reviewer of the live-checkpoint, recovery, capacity, fencing, and internal-backpressure candidate reports no negative finding. |
| 4 | phase-4-reviewed-external-integration | Approve Linux NBD, QEMU, supervision, operator, guest, readiness, shutdown, authority-loss, and quiescence boundaries without changing prior durability promises. |
| 4 | phase-4-nbd-wire-error-tests | Execute NBD callback, wire, bounds, refusal, and error-translation tests against the Phase 2 and Phase 3 internal contracts. |
| 4 | phase-4-qemu-supervisor-operator-guest-tests | Execute QEMU, supervisor, operator-status, guest, shutdown, orphan, and fault-injection composition tests at every approved external boundary. |
| 4 | phase-4-independent-integration-approval | An independent reviewer of the NBD, QEMU, supervision, operator, guest, and security candidate reports no negative finding. |
| 5 | phase-5-operational-privacy-hardening | Approve backup/export, runbooks, key-rotation proposal, privacy, minimization, disclosure, retention, and any telemetry policy. |
| 5 | phase-5-recovery-drill-and-report-only-gc | Complete a fresh-operator recovery drill and prove remote reachability remains report-only with no destructive remote garbage collection in v1. |
| 5 | phase-5-independent-final-approval | An independent reviewer of the operational, privacy, recovery, and security candidate reports no negative finding. |

One Phase 0 gate attempt is exactly one append-only TOML evaluation file. Its raw
bytes are the whole evaluation: fragments are never combined or substituted. The
file has the exact ordered header `schema_version`, `phase_id`, `tested_commit`,
`exact_parent`, `publication_branch`, `grant_lineage_id`,
`resource_workload_id`, `tested_at_utc`, `commands`, `environment`,
`synthetic_data`, `redactions`, and `limitations`, followed by `results`. It has one
ordered `[[results]]` row for every Phase 0 criterion in specification order. Each
row has exactly `criterion_id`, `outcome`, `evidence`, `limitation`, and
`shared_binding_id`. The criterion is the stable result ID; subresults and summary
status fields are forbidden.

The raw file is at most 65,536 bytes. A reader MUST reject an over-limit byte
sequence before UTF-8 decoding or TOML parsing. It then MUST reject invalid UTF-8,
invalid TOML, unknown or missing fields, wrong field order, or wrong types. This
whole-file byte limit is the only size or count cap in the evaluation schema; every
free string and array is bounded by it.

Schema version is integer `1`; `phase_id` is `phase-0`; both commit values are
lowercase full 40-hex SHAs and equal the expected tested commit and exact sole
parent of the evidence/status candidate. `publication_branch` is nonempty, has no
leading or trailing whitespace, is Unicode NFC, and equals the externally supplied
expected branch. Time is a valid second-precision RFC3339 UTC value and must match
the filename `YYYYMMDDTHHMMSSZ-phase-0-evaluation.toml`. `commands` is a nonempty
array of nonempty strings. Environment, synthetic data, redactions, limitations,
and both shared header labels are nonempty strings. Evidence and limitation are
strings; PASS and FAIL require nonempty evidence, and BLOCKED requires a nonempty
limitation. Shared result bindings must match the header rules above exactly.

<!-- cairnvm-contract:phase-evaluation-accounting -->
| key | value |
|---|---|
| evaluation_schema_version | 1 |
| criterion_result_identity | criterion_id |
| evaluation_scope | one complete append-only raw UTF-8 evaluation TOML bound to phase_id, tested_commit, exact_parent, publication_branch, grant lineage, and resource workload |
| filename_pattern | YYYYMMDDTHHMMSSZ-phase-0-evaluation.toml |
| latest_evaluation_selection | lexicographically last complete evaluation after manual timestamp and externally supplied trusted-clock review; no evaluation after passed |
| max_evaluation_bytes | 65536 |
| evaluation_fields | schema_version, phase_id, tested_commit, exact_parent, publication_branch, grant_lineage_id, resource_workload_id, tested_at_utc, commands, environment, synthetic_data, redactions, limitations, results |
| result_fields | criterion_id, outcome, evidence, limitation, shared_binding_id |
| outcomes | PASS, FAIL, BLOCKED |
| grant_lineage_criteria | phase-0-drive-synthetic-round-trip, phase-0-oauth-authorization, phase-0-oauth-refresh |
| resource_workload_criteria | phase-0-runtime-memory-control, phase-0-repository-geometry |
| representative_resource_workload | one declared functional representative nonzero synthetic Drive-backed VM control-path workload with predeclared byte/object limits and one forced-over-limit nonzero exit per resource criterion |

A publishable evaluation is exact and complete: no missing, extra, duplicate,
unknown, or reordered criterion and no invalid outcome or context. A partial
evaluation is never publishable. While the latest result is not passed, a new
attempt adds a new whole evaluation file; it never edits or combines earlier files.
Only a complete publishable evaluation is aggregated, using the first matching row
below so FAIL precedes BLOCKED.

<!-- cairnvm-contract:phase-result-aggregation -->
| condition | status | meaning |
|---|---|---|
| any-fail | failed | At least one result is FAIL, including when another is BLOCKED. |
| any-blocked | blocked | No result is FAIL and at least one result is BLOCKED. |
| all-pass | passed | Every result is PASS. |

Every TOML file in the Phase 0 evidence directory belongs to the evaluation
universe; a wrong-name TOML file is invalid, not ignored. Every historical file
must remain structurally valid. Evaluation filenames are unique and strictly
increasing by timestamp. Before publication, the reviewer supplies a trusted UTC
review clock from outside the evaluated file, corroborates `tested_at_utc` against
command logs, confirms it is later than the existing latest evaluation and no
later than that clock, and rejects future-dated candidates. Only then is the
lexicographically last complete file the latest complete evaluation and sole
source for `failed`, `blocked`, or `passed` in `ROADMAP.md`. Passed is terminal: no
later evaluation is permitted. If no evaluation exists, status is
`not-started` exactly when Phase 0 work has not begun, or `in-progress` exactly
when work has begun.
Malformed or partial TOML is rejected before publication and never becomes a
separate phase state.

The following finite mapping closes each deferred design through an independent
approval in the same owning phase. Criterion descriptions remain solely in the
table above.

<!-- cairnvm-contract:deferral-approvals -->
| deferred_design_id | target_phase | approval_criterion_id |
|---|---|---|
| phase-1-primitives | 1 | phase-1-independent-security-approval |
| phase-2-offline-block | 2 | phase-2-independent-recovery-approval |
| phase-3-live-checkpoints | 3 | phase-3-independent-live-approval |
| phase-4-external-integration | 4 | phase-4-independent-integration-approval |
| phase-5-operational-hardening | 5 | phase-5-independent-final-approval |

## 7. Status and evidence

`ROADMAP.md` is the sole mutable phase-status authority. Its stable status snapshot
allows a passed prefix, optionally one failed, in-progress, or blocked frontier,
and only not-started phases after that frontier. All phases may be passed. Passed is
terminal by policy and may be recorded only after manual exact-parent evidence
review; this charter does not define a Git-history verifier.

<!-- cairnvm-contract:evidence-policy -->
| rule | requirement |
|---|---|
| gate result when a required runtime or service is unavailable | BLOCKED when no required check fails; never PASS |
| publication sequence | tested implementation commit, then evidence/status commit |
| evidence binding | full tested SHA and exact parent |
| evaluation unit | one complete append-only Phase 0 TOML file |
| review | manual independent exact-candidate review with no negative finding |
| history claim | requires verified force-push and branch-deletion protection |

The tested implementation commit contains the implementation and tests. A
single-parent follow-up evidence/status commit contains exactly one new complete
Phase 0 evaluation TOML file and optionally `ROADMAP.md` only when the aggregate
phase status changes. Its
reviewer manually confirms the full tested SHA, exact-parent and branch binding,
allowed paths, exact schema and result order, shared grant and workload bindings,
total aggregation, append-only file, redaction, and exact candidate. Evidence is a
reviewed claim, never a machine-attested history claim and never a description of
its own commit. This
policy defines no custom Git, history, object, or archive verifier. History is not
called protected or immutable until publication-branch force-push and deletion
protection are verified.

## 8. Identity and deferred decisions

`Docs/ADRs/0001-cairnvm-identity.md` is the sole accepted protocol decision. Its
exact product, repository, distribution, command, import, path, metrics, magic-role,
and discovery-property namespace mappings are selected mirrors in
`Docs/architecture-state-model.toml` and exact structural tests. Phase 1 owns all
runtime and durable protocol encoding, capacity, parser, algorithm, provider-fit,
versioning, and compatibility decisions not explicitly accepted by that ADR. The
Phase 0 gate-evidence schema is administrative release evidence, not a runtime or
durable repository format.

The state model mirrors only the selected status boundary, identity mappings,
invariant IDs, durability vocabulary, phase ownership, provider-inventory schema,
gate IDs, phase-result accounting, deferral approvals, and evidence policy. Prose
in this charter remains authoritative where a detail is not mirrored.
