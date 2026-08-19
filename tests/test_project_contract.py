from __future__ import annotations

import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "Docs/Architecture-Spec.md"
MODEL_PATH = ROOT / "Docs/architecture-state-model.toml"
ADR_PATH = ROOT / "Docs/ADRs/0001-cairnvm-identity.md"
OVERVIEW_PATH = ROOT / "OVERVIEW.md"
ROADMAP_PATH = ROOT / "ROADMAP.md"

EXPECTED_IMPLEMENTATION_STATUS = (
    ("CLI package and cairnvm entry point", "implemented-scaffold"),
    ("Read-only preliminary doctor diagnostics", "implemented-scaffold"),
    ("Independent launcher package boundary", "implemented-scaffold"),
    ("Quality, artifact, and secret-scanning gates", "implemented-scaffold"),
    ("Drive, cryptography, formats, and bootstrap", "not-implemented-phase-1"),
    ("Internal block engine and offline checkpoints", "not-implemented-phase-2"),
    ("Live checkpoints and internal backpressure", "not-implemented-phase-3"),
    ("NBD, QEMU, supervision, and guest integration", "not-implemented-phase-4"),
    ("Operational and privacy hardening", "not-implemented-phase-5"),
)
EXPECTED_IDENTITY_SURFACES = (
    ("product", "CairnVM"),
    ("repository", "baxter-barlow/cairnvm"),
    ("runtime distribution", "cairnvm-runtime"),
    ("launcher distribution", "cairnvm-launcher"),
    ("runtime import", "cairnvm"),
    ("launcher import", "cairnvm_launcher"),
    ("command", "cairnvm"),
    ("environment prefix", "CAIRNVM_"),
    ("local state", ".cairnvm/"),
    ("Colab state", "/content/cairnvm/"),
    ("Drive root", "CairnVM/"),
    ("metrics prefix", "cairnvm_"),
    ("discovery MAC domain", 'ASCII("CAIR-DISCOVERY-v1\\0")'),
)
EXPECTED_MAGIC_ROLES = (
    ("CVIT", "intent"),
    ("CVMP", "mapping"),
    ("CVCH", "commit-header"),
    ("CVSE", "primary-secret-envelope"),
    ("CVRE", "recovery-envelope"),
    ("CVPK", "pack"),
    ("CVRC", "remote-record"),
    ("CVLR", "local-record"),
    ("CVKH", "key-handoff-frame"),
)
EXPECTED_INVARIANTS = (
    "authenticate-before-semantic-use",
    "bounds-before-allocation",
    "no-silent-branch-or-rollback",
    "trusted-freshness-or-refuse",
    "single-writer-requires-fencing",
    "no-destructive-remote-gc-v1",
    "no-plaintext-remote-blocks-or-credentials",
    "launcher-verifies-before-downloaded-execution",
)
EXPECTED_DURABILITY = (
    ("acknowledged", "accepted by the block engine; no restart-survival promise"),
    ("local-durable", "survives a process restart only on the same runtime"),
    ("published", "checkpoint creation returned success or was discovered remotely"),
    (
        "reconciled",
        "authenticated provider objects and independently trusted freshness anchor both "
        "reconciled to checkpoint identity, parent, references, and required head relationship",
    ),
)
EXPECTED_PHASE_OWNERSHIP = (
    ("0", "feasibility, scaffold boundaries, and honest evidence"),
    ("1", "formats, cryptography, Drive, bootstrap, and provider primitives"),
    ("2", "internal block requests, local durability, and offline checkpoint composition"),
    ("3", "live checkpoints and internal backpressure admission, refusal, and status"),
    ("4", "NBD wire and errors plus QEMU, supervisor, operator, and guest composition"),
    ("5", "operational and privacy hardening"),
)
EXPECTED_PROVIDER_CONTRACT_FIELDS = (
    "contract_id",
    "kind",
    "semantic_binding",
    "implementation_test_traceability",
)
EXPECTED_PROVIDER_ITEM_FIELDS = (
    "item_id",
    "kind",
    "covered_contract_ids",
    "primary_documentation",
    "applicability_and_bounds",
    "deterministic_fake_cases",
    "expected_outcomes",
    "live_evidence",
    "blocked_mapping",
)
EXPECTED_PROVIDER_CONTRACT_KINDS = (
    "provider-primitive",
    "provider-operation",
    "provider-assumption",
    "provider-observable-branch",
    "remote-mutation",
    "provider-injected-fault",
)
EXPECTED_PROVIDER_ITEM_KINDS = (
    "documentation-and-bounds",
    "deterministic-fake",
    "live-disposable-account",
    "remote-mutation-lost-response",
)
EXPECTED_PHASE_ZERO_PROVIDER_PROBES = (
    "phase-0-drive-synthetic-round-trip",
    "phase-0-oauth-authorization",
    "phase-0-oauth-refresh",
    "phase-0-runtime-memory-control",
    "phase-0-repository-geometry",
)
EXPECTED_GATE_IDS = {
    "0": (
        "phase-0-colab-policy",
        "phase-0-colab-control-path",
        "phase-0-drive-synthetic-round-trip",
        "phase-0-oauth-authorization",
        "phase-0-oauth-refresh",
        "phase-0-runtime-memory-control",
        "phase-0-repository-geometry",
        "phase-0-recovery-runtime-loss",
        "phase-0-recovery-drive-trust",
        "phase-0-recovery-freshness-refusal",
        "phase-0-qemu-kvm-probe",
        "phase-0-qemu-tcg-probe",
        "phase-0-nbdkit-python-compatibility",
        "phase-0-security-gates",
        "phase-0-ci-required-checks",
        "phase-0-publication-controls",
        "phase-0-zero-negative-charter-review",
    ),
    "1": (
        "phase-1-reviewed-formats-crypto-drive-bootstrap-primitives",
        "phase-1-trusted-freshness-and-rollback-tests",
        "phase-1-finite-versioned-provider-inventory",
        "phase-1-provider-validation-evidence",
        "phase-1-independent-security-approval",
    ),
    "2": (
        "phase-2-reviewed-offline-block-contract",
        "phase-2-fencing-and-fresh-head",
        "phase-2-four-way-remote-composition",
        "phase-2-independent-recovery-approval",
    ),
    "3": (
        "phase-3-live-checkpoint-recovery",
        "phase-3-internal-backpressure-contract",
        "phase-3-live-fault-composition",
        "phase-3-independent-live-approval",
    ),
    "4": (
        "phase-4-reviewed-external-integration",
        "phase-4-nbd-wire-error-tests",
        "phase-4-qemu-supervisor-operator-guest-tests",
        "phase-4-independent-integration-approval",
    ),
    "5": (
        "phase-5-operational-privacy-hardening",
        "phase-5-recovery-drill-and-report-only-gc",
        "phase-5-independent-final-approval",
    ),
}
EXPECTED_PHASE_TWO_CRITERIA = {
    "phase-2-fencing-and-fresh-head": (
        "Every checkpoint attempt first freshly authenticates its expected parent/head and "
        "revalidates the independently trusted freshness anchor, then runs and reconciles the "
        "reviewed fence-acquisition operation bound to that pre-acquisition context; only a "
        "present-as-intended acquisition yields authority. Bind every later mutation, including "
        "anchor, coordinator, renewal, and release mutations, to the acquired authority and keep "
        "it valid through provider-object and anchor reconciliation; fail closed on any expired, "
        "revoked, lost, indeterminate, or conflicting authority or anchor outcome."
    ),
    "phase-2-four-way-remote-composition": (
        "For fence acquisition and every referenced data, metadata, checkpoint-node, "
        "freshness-anchor, coordinator, renewal, or release mutation, prove lost-response "
        "reconciliation for absent, present-as-intended, conflicting, and indeterminate outcomes; "
        "before retry, reconcile provider-object and anchor outcomes and begin a new attempt with "
        "fresh parent/head, anchor, and fence acquisition."
    ),
}
EXPECTED_PHASE_ONE_CRITERIA = {
    "phase-1-trusted-freshness-and-rollback-tests": (
        "Select and freeze an independently trusted freshness anchor or source whose trust does "
        "not derive solely from repository objects; this Phase 0 charter selects no mechanism; "
        "approve and test anchor read/compare, stable checkpoint binding, advance or attestation, "
        "idempotency, crash, concurrency, authorization loss, and lost or ambiguous update "
        "reconciliation; recovery and read-write selection fail closed when freshness cannot be "
        "established, while read-only diagnosis may report unverified candidates; test rollback, "
        "deletion, and tampering."
    ),
    "phase-1-finite-versioned-provider-inventory": (
        "Before accepting provider behavior into Phase 1 design or implementation, first approve "
        "the finite, versioned schema; then review the frozen design and implementation surface "
        "to enumerate "
        "every provider-dependent primitive, operation, assumption, observable branch, remote "
        "mutation, and injected fault under stable semantically bound contract IDs, plus the "
        "constrained inventory item set."
    ),
    "phase-1-provider-validation-evidence": (
        "Prove unique IDs and reviewed bidirectional closure from the frozen design and "
        "implementation surface to semantic provider contracts and from contracts to constrained "
        "inventory items, with no omitted or unknown binding, orphan, or unknown reference; "
        "require implementation and test traceability when implemented; satisfy every item's "
        "documentation, bounds, fake, live, outcome, and BLOCKED obligations; prove absent, "
        "present-as-intended, conflicting, and indeterminate outcomes for every remote-mutation "
        "contract."
    ),
}
EXPECTED_INDEPENDENT_APPROVALS = {
    "phase-0-zero-negative-charter-review": (
        "PASS requires that an independent adversarial reviewer of the exact candidate reports "
        "no negative finding."
    ),
    "phase-1-independent-security-approval": (
        "An independent reviewer of the format, cryptography, provider, bootstrap, launcher, "
        "and recovery candidate reports no negative finding."
    ),
    "phase-2-independent-recovery-approval": (
        "An independent reviewer of the block-engine, local-durability, fencing, "
        "checkpoint-composition, and recovery candidate reports no negative finding."
    ),
    "phase-3-independent-live-approval": (
        "An independent reviewer of the live-checkpoint, recovery, capacity, fencing, and "
        "internal-backpressure candidate reports no negative finding."
    ),
    "phase-4-independent-integration-approval": (
        "An independent reviewer of the NBD, QEMU, supervision, operator, guest, and security "
        "candidate reports no negative finding."
    ),
    "phase-5-independent-final-approval": (
        "An independent reviewer of the operational, privacy, recovery, and security "
        "candidate reports no negative finding."
    ),
}
EXPECTED_DEFERRAL_APPROVALS = (
    ("phase-1-primitives", "1", "phase-1-independent-security-approval"),
    ("phase-2-offline-block", "2", "phase-2-independent-recovery-approval"),
    ("phase-3-live-checkpoints", "3", "phase-3-independent-live-approval"),
    ("phase-4-external-integration", "4", "phase-4-independent-integration-approval"),
    ("phase-5-operational-hardening", "5", "phase-5-independent-final-approval"),
)
EXPECTED_AGGREGATION_RULES = (
    ("any-fail", "failed"),
    ("any-blocked", "blocked"),
    ("all-pass", "passed"),
)
EXPECTED_EVALUATION_FIELDS = (
    "schema_version",
    "phase_id",
    "tested_commit",
    "exact_parent",
    "publication_branch",
    "grant_lineage_id",
    "resource_workload_id",
    "tested_at_utc",
    "commands",
    "environment",
    "synthetic_data",
    "redactions",
    "limitations",
    "results",
)
EXPECTED_RESULT_FIELDS = (
    "criterion_id",
    "outcome",
    "evidence",
    "limitation",
    "shared_binding_id",
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _model() -> dict[str, Any]:
    with MODEL_PATH.open("rb") as handle:
        return tomllib.load(handle)


def _table(
    document: str, tag: str, headers: tuple[str, ...], *, require_rows: bool = True
) -> list[dict[str, str]]:
    marker = f"<!-- cairnvm-contract:{tag} -->"
    assert document.count(marker) == 1
    lines = document.splitlines()
    start = lines.index(marker) + 1
    while start < len(lines) and not lines[start].strip():
        start += 1
    actual_headers = tuple(cell.strip() for cell in lines[start].strip().strip("|").split("|"))
    assert actual_headers == headers
    assert lines[start + 1].startswith("|")
    rows: list[dict[str, str]] = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        cells = tuple(cell.strip() for cell in line.strip().strip("|").split("|"))
        assert len(cells) == len(headers)
        rows.append(dict(zip(headers, cells, strict=True)))
    assert rows or not require_rows
    return rows


def _pairs(rows: Iterable[dict[str, str]], left: str, right: str) -> tuple[tuple[str, str], ...]:
    return tuple((row[left], row[right]) for row in rows)


def _model_pairs(items: list[dict[str, Any]], left: str, right: str) -> tuple[tuple[str, str], ...]:
    return tuple((str(item[left]), str(item[right])) for item in items)


def test_phase_zero_charter_is_intentionally_small() -> None:
    limits = {
        SPEC_PATH: 1_200,
        MODEL_PATH: 250,
        Path(__file__): 750,
        ROOT / "tests/test_workflow_contract.py": 750,
    }
    for path, limit in limits.items():
        assert len(_text(path).splitlines()) <= limit
    assert set(_model()) == {
        "deferral_approval",
        "durability",
        "evidence_policy",
        "historical_document",
        "identity",
        "implementation_status",
        "invariants",
        "normative_document",
        "phase_gate",
        "phase_result_accounting",
        "phase_ownership",
        "provider_inventory",
        "schema_version",
    }
    assert _model()["schema_version"] == 9


def test_authority_and_candidate_status_are_honest() -> None:
    spec = _text(SPEC_PATH)
    model = _model()
    assert model["normative_document"] == "Docs/Architecture-Spec.md"
    assert model["historical_document"] == "Docs/Architecture-Draft.md"
    assert "mutable status lives only in `ROADMAP.md`" in spec
    assert "mutable phase status" in _text(OVERVIEW_PATH)
    assert (
        "does not implement Drive persistence, cryptography, block service, checkpoints, "
        "bootstrap verification, NBD, QEMU integration, or supervision" in " ".join(spec.split())
    )


def test_implementation_status_is_an_exact_structural_mapping() -> None:
    overview_rows = _table(_text(OVERVIEW_PATH), "implementation-status", ("component", "status"))
    roadmap_rows = _table(_text(ROADMAP_PATH), "implementation-status", ("component", "status"))
    model_pairs = _model_pairs(_model()["implementation_status"], "component", "status")
    assert _pairs(overview_rows, "component", "status") == EXPECTED_IMPLEMENTATION_STATUS
    assert _pairs(roadmap_rows, "component", "status") == EXPECTED_IMPLEMENTATION_STATUS
    assert model_pairs == EXPECTED_IMPLEMENTATION_STATUS


def test_identity_is_exact_and_matches_package_metadata() -> None:
    adr = _text(ADR_PATH)
    model = _model()["identity"]
    surfaces = _pairs(
        _table(adr, "identity-surfaces", ("surface", "identifier")), "surface", "identifier"
    )
    magics = _pairs(_table(adr, "magic-roles", ("magic", "role")), "magic", "role")
    properties = _table(adr, "discovery-property-range", ("namespace", "first", "last"))
    assert surfaces == EXPECTED_IDENTITY_SURFACES
    assert magics == EXPECTED_MAGIC_ROLES
    assert properties == [
        {"namespace": "discovery-properties", "first": "cair_d00", "last": "cair_d29"}
    ]
    assert _model_pairs(model["surface"], "name", "identifier") == surfaces
    assert _model_pairs(model["magic_role"], "magic", "role") == magics
    assert model["discovery_property_range"] == {
        "namespace": "discovery-properties",
        "first": "cair_d00",
        "last": "cair_d29",
    }
    root_metadata = tomllib.loads(_text(ROOT / "pyproject.toml"))
    launcher_metadata = tomllib.loads(_text(ROOT / "packages/launcher/pyproject.toml"))
    surface_map = dict(surfaces)
    assert root_metadata["project"]["name"] == surface_map["runtime distribution"]
    assert launcher_metadata["project"]["name"] == surface_map["launcher distribution"]
    assert root_metadata["project"]["scripts"] == {
        surface_map["command"]: f"{surface_map['runtime import']}.cli:main"
    }
    assert root_metadata["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        f"src/{surface_map['runtime import']}"
    ]
    assert launcher_metadata["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        f"src/{surface_map['launcher import']}"
    ]
    repository_url = f"https://github.com/{surface_map['repository']}"
    assert root_metadata["project"]["urls"]["Repository"] == repository_url
    assert launcher_metadata["project"]["urls"]["Repository"] == repository_url


def test_identity_adr_is_the_only_accepted_protocol_decision() -> None:
    adr = " ".join(_text(ADR_PATH).split())
    identity = _model()["identity"]
    assert identity["accepted_adr"] == "Docs/ADRs/0001-cairnvm-identity.md"
    assert identity["other_protocol_decisions"] == "deferred"
    assert "sole accepted protocol decision" in adr
    assert "runtime and durable protocol decisions remain deferred" in adr
    assert "one-time repository scan before publication" in adr


def test_fail_closed_invariants_are_selected_exact_mirrors() -> None:
    rows = _table(_text(SPEC_PATH), "invariants", ("id", "requirement"))
    assert tuple(row["id"] for row in rows) == EXPECTED_INVARIANTS
    assert tuple(_model()["invariants"]) == EXPECTED_INVARIANTS
    requirements = {row["id"]: row["requirement"] for row in rows}
    assert requirements["trusted-freshness-or-refuse"] == (
        "Recovery and read-write selection require freshness from an independently trusted "
        "anchor or source whose trust does not derive solely from repository objects; "
        "otherwise refuse, while read-only diagnosis may label unverified candidates."
    )
    assert requirements["no-plaintext-remote-blocks-or-credentials"] == (
        "Never upload plaintext guest blocks, plaintext secrets, or credentials; never log "
        "plaintext guest data, credentials, tokens, passphrases, secret-envelope plaintext, keys, "
        "or derived keys."
    )
    spec = " ".join(_text(SPEC_PATH).split())
    assert (
        "A privileged Colab or compute host can observe or modify plaintext memory, keys, "
        "credentials, guest data, and local state, and can subvert client authentication. "
        "Protecting confidentiality or integrity from a malicious host is out of scope and a "
        "non-goal." in spec
    )


def test_durability_vocabulary_and_checkpoint_completion_are_exact() -> None:
    spec = _text(SPEC_PATH)
    rows = _table(spec, "durability-levels", ("level", "meaning"))
    assert _pairs(rows, "level", "meaning") == EXPECTED_DURABILITY
    assert _model_pairs(_model()["durability"]["level"], "name", "meaning") == EXPECTED_DURABILITY
    flat_spec = " ".join(spec.split())
    assert "Flush and FUA establish only local-durable state" in flat_spec
    assert "checkpoint object is published last" in flat_spec
    assert (
        "Ambiguous mutation results require fresh reconciliation before retry or advance"
        in flat_spec
    )
    assert "Publication alone is not completed remote durability" in flat_spec
    assert (
        "No checkpoint is reconciled or completed remote durability until both its required "
        "provider objects and independently trusted anchor are reconciled as present-as-intended"
        in flat_spec
    )


def test_phase_ownership_matches_spec_model_and_overview() -> None:
    spec_rows = _table(_text(SPEC_PATH), "phase-ownership", ("phase", "owns"))
    overview_rows = _table(_text(OVERVIEW_PATH), "phase-ownership", ("phase", "owns"))
    roadmap_rows = _table(_text(ROADMAP_PATH), "phase-ownership", ("phase", "owns"))
    model_pairs = _model_pairs(_model()["phase_ownership"], "phase", "owns")
    assert _pairs(spec_rows, "phase", "owns") == EXPECTED_PHASE_OWNERSHIP
    assert _pairs(overview_rows, "phase", "owns") == EXPECTED_PHASE_OWNERSHIP
    assert _pairs(roadmap_rows, "phase", "owns") == EXPECTED_PHASE_OWNERSHIP
    assert model_pairs == EXPECTED_PHASE_OWNERSHIP


def test_provider_inventory_schema_is_finite_versioned_and_unpopulated() -> None:
    spec = _text(SPEC_PATH)
    provider = _model()["provider_inventory"]
    rows = _table(spec, "provider-registry-fields", ("record", "field", "binding"))
    assert tuple(row["field"] for row in rows if row["record"] == "contract") == (
        EXPECTED_PROVIDER_CONTRACT_FIELDS
    )
    assert tuple(row["field"] for row in rows if row["record"] == "item") == (
        EXPECTED_PROVIDER_ITEM_FIELDS
    )
    bindings = {(row["record"], row["field"]): row["binding"] for row in rows}
    assert bindings[("contract", "semantic_binding")] == (
        "Exact stable reference to one semantic element in the frozen reviewed design and "
        "implementation surface."
    )
    assert bindings[("contract", "implementation_test_traceability")] == (
        "Exact implementation and test references when implemented; otherwise an explicit "
        "not-implemented marker."
    )
    assert bindings[("contract", "kind")] == (
        "Exactly provider-primitive, provider-operation, provider-assumption, "
        "provider-observable-branch, remote-mutation, or provider-injected-fault."
    )
    assert bindings[("item", "kind")] == (
        "Exactly documentation-and-bounds, deterministic-fake, live-disposable-account, or "
        "remote-mutation-lost-response."
    )
    assert tuple(provider["contract_required_fields"]) == EXPECTED_PROVIDER_CONTRACT_FIELDS
    assert tuple(provider["item_required_fields"]) == EXPECTED_PROVIDER_ITEM_FIELDS
    assert tuple(provider["contract_kinds"]) == EXPECTED_PROVIDER_CONTRACT_KINDS
    assert tuple(provider["item_kinds"]) == EXPECTED_PROVIDER_ITEM_KINDS
    assert provider["status"] == "not-yet-approved"
    assert provider["approved_schema_version"] == "none"
    assert provider["contracts"] == []
    assert provider["items"] == []
    assert provider["coverage_rule"] == (
        "reviewed-surface-contract-item-exact-bidirectional-no-omissions-or-unknown-bindings"
    )
    assert provider["remote_mutation_outcomes"] == [
        "absent",
        "present-as-intended",
        "conflicting",
        "indeterminate",
    ]
    assert tuple(provider["phase_zero_feasibility_probe_criteria"]) == (
        EXPECTED_PHASE_ZERO_PROVIDER_PROBES
    )
    flat_spec = " ".join(spec.split())
    assert "only pre-inventory exception is the five finite Phase 0 feasibility probes" in flat_spec
    assert all(f"`{criterion_id}`" in spec for criterion_id in EXPECTED_PHASE_ZERO_PROVIDER_PROBES)
    assert (
        "Before provider behavior is accepted into Phase 1 design or implementation, Phase 1 "
        "must approve the finite, versioned registry and inventory schema" in flat_spec
    )
    assert (
        "Every contract binds to one exact reviewed semantic element and, once implemented, to "
        "its implementation and tests" in flat_spec
    )
    assert "Item kinds are limited to the finite list above" in flat_spec
    assert (
        "Completeness is relative only to that frozen reviewed surface and approved registry"
        in flat_spec
    )
    assert "provider behavior requires disposable-account live evidence" in flat_spec


def test_phase_one_criteria_close_freshness_and_provider_registry_gaps() -> None:
    rows = _table(_text(SPEC_PATH), "phase-gate-criteria", ("phase", "criterion_id", "criterion"))
    phase_one = {row["criterion_id"]: row["criterion"] for row in rows if row["phase"] == "1"}
    for criterion_id, description in EXPECTED_PHASE_ONE_CRITERIA.items():
        assert phase_one[criterion_id] == description


def test_gate_ids_are_a_small_exact_projection_owned_by_the_spec() -> None:
    spec_rows = _table(
        _text(SPEC_PATH), "phase-gate-criteria", ("phase", "criterion_id", "criterion")
    )
    roadmap_rows = _table(
        _text(ROADMAP_PATH), "phase-gate-criterion-refs", ("phase", "criterion_id")
    )
    model = _model()
    spec_projection = tuple((row["phase"], row["criterion_id"]) for row in spec_rows)
    roadmap_projection = tuple((row["phase"], row["criterion_id"]) for row in roadmap_rows)
    model_projection = tuple(
        (str(gate["phase"]), criterion_id)
        for gate in model["phase_gate"]
        for criterion_id in gate["criteria_ids"]
    )
    expected_projection = tuple(
        (phase, criterion_id)
        for phase, criterion_ids in EXPECTED_GATE_IDS.items()
        for criterion_id in criterion_ids
    )
    assert spec_projection == expected_projection
    assert roadmap_projection == expected_projection
    assert model_projection == expected_projection
    assert all("PASS requires" in row["criterion"] for row in spec_rows if row["phase"] == "0")
    assert "Gate criteria are defined only in `Docs/Architecture-Spec.md`" in _text(ROADMAP_PATH)

    def projections_are_exact(*projections: tuple[tuple[str, str], ...]) -> bool:
        return all(projection == expected_projection for projection in projections)

    assert projections_are_exact(spec_projection, roadmap_projection, model_projection)
    for omitted in expected_projection:
        coordinated_omission = tuple(item for item in expected_projection if item != omitted)
        assert not projections_are_exact(
            coordinated_omission, coordinated_omission, coordinated_omission
        )


def test_phase_result_aggregation_is_total_and_fail_closed() -> None:
    accounting = _model()["phase_result_accounting"]
    assert tuple(accounting["outcomes"]) == ("PASS", "FAIL", "BLOCKED")
    assert tuple(accounting["evaluation_fields"]) == EXPECTED_EVALUATION_FIELDS
    assert tuple(accounting["result_fields"]) == EXPECTED_RESULT_FIELDS
    assert _model_pairs(accounting["aggregation_rule"], "condition", "status") == (
        EXPECTED_AGGREGATION_RULES
    )
    spec_rules = _table(
        _text(SPEC_PATH), "phase-result-aggregation", ("condition", "status", "meaning")
    )
    assert _pairs(spec_rules, "condition", "status") == EXPECTED_AGGREGATION_RULES


def test_phase_two_criteria_preserve_fencing_and_complete_four_way_composition() -> None:
    rows = _table(_text(SPEC_PATH), "phase-gate-criteria", ("phase", "criterion_id", "criterion"))
    phase_two = {row["criterion_id"]: row["criterion"] for row in rows if row["phase"] == "2"}
    for criterion_id, description in EXPECTED_PHASE_TWO_CRITERIA.items():
        assert phase_two[criterion_id] == description


def test_deferrals_close_through_same_phase_independent_approval() -> None:
    spec = _text(SPEC_PATH)
    criteria = _table(spec, "phase-gate-criteria", ("phase", "criterion_id", "criterion"))
    deferrals = _table(
        spec,
        "deferral-approvals",
        ("deferred_design_id", "target_phase", "approval_criterion_id"),
    )
    actual = tuple(
        (row["deferred_design_id"], row["target_phase"], row["approval_criterion_id"])
        for row in deferrals
    )
    model_actual = tuple(
        (
            item["deferred_design_id"],
            str(item["target_phase"]),
            item["approval_criterion_id"],
        )
        for item in _model()["deferral_approval"]
    )
    assert actual == EXPECTED_DEFERRAL_APPROVALS
    assert model_actual == EXPECTED_DEFERRAL_APPROVALS
    assert len({design_id for design_id, _phase, _approval_id in actual}) == len(actual)
    assert tuple(phase for _design_id, phase, _approval_id in actual) == (
        "1",
        "2",
        "3",
        "4",
        "5",
    )
    criterion_by_id = {row["criterion_id"]: row for row in criteria}
    for _design_id, phase, approval_id in actual:
        assert criterion_by_id[approval_id]["phase"] == phase
    for approval_id, description in EXPECTED_INDEPENDENT_APPROVALS.items():
        assert criterion_by_id[approval_id]["criterion"] == description
        assert "reviewer" in description
        assert "reports no negative finding" in description
        for document in (_text(ROADMAP_PATH), _text(OVERVIEW_PATH), _text(ADR_PATH)):
            assert description not in " ".join(document.split())


def test_roadmap_is_the_only_mutable_status_authority_and_has_a_valid_frontier() -> None:
    roadmap = _text(ROADMAP_PATH)
    statuses = _table(roadmap, "phase-status", ("phase", "id", "status"))
    assert [(row["phase"], row["id"]) for row in statuses] == [
        (str(phase), f"phase-{phase}") for phase in range(6)
    ]
    values = [row["status"] for row in statuses]
    assert all(
        value in {"passed", "failed", "in-progress", "blocked", "not-started"} for value in values
    )
    passed_count = len(tuple(value for value in values if value == "passed"))
    assert values[:passed_count] == ["passed"] * passed_count
    remainder = values[passed_count:]
    if remainder:
        if remainder[0] in {"failed", "in-progress", "blocked"}:
            remainder = remainder[1:]
        assert remainder == ["not-started"] * len(remainder)
    phase_zero_section = roadmap.split("## Phase 0", 1)[1].split("## Phase 1", 1)[0]
    assert "- [ ]" not in phase_zero_section
    for document in (_text(SPEC_PATH), _text(OVERVIEW_PATH), _text(ADR_PATH)):
        assert "cairnvm-contract:phase-status" not in document


def test_phase_zero_status_has_no_duplicate_mutable_prose() -> None:
    spec = " ".join(_text(SPEC_PATH).split())
    roadmap_text = _text(ROADMAP_PATH)
    roadmap = " ".join(roadmap_text.split())
    for document in (spec, roadmap):
        assert "KVM when available" in document
        assert "TCG fallback" in document
    assert "cairnvm-contract:phase-0-current-results" not in roadmap_text
    assert "| criterion_id | outcome | basis |" not in roadmap_text
    assert "work has begun" in roadmap
    assert "partial evaluation" in roadmap
    phase_zero_section = roadmap_text.split("## Phase 0", 1)[1].split("## Phase 1", 1)[0]
    assert "`in-progress`" not in phase_zero_section
    assert all(
        "(" not in line for line in roadmap_text.splitlines() if line.startswith("## Phase ")
    )


def test_phase_zero_resource_and_operational_criteria_are_closed() -> None:
    rows = _table(_text(SPEC_PATH), "phase-gate-criteria", ("phase", "criterion_id", "criterion"))
    criteria = {row["criterion_id"]: row["criterion"] for row in rows if row["phase"] == "0"}
    for criterion_id in (
        "phase-0-runtime-memory-control",
        "phase-0-repository-geometry",
    ):
        description = criteria[criterion_id]
        assert "functional representative synthetic workload" in description
        assert "forced-over-limit case exits nonzero" in description
    assert "functional synthetic plugin" in criteria["phase-0-nbdkit-python-compatibility"]
    assert "make security" in criteria["phase-0-security-gates"]
    assert "required GitHub Actions checks" in criteria["phase-0-ci-required-checks"]
    publication = criteria["phase-0-publication-controls"]
    assert "force pushes" in publication
    assert "branch deletion" in publication


def test_manual_evidence_policy_is_exact_without_a_history_verifier() -> None:
    rows = _table(_text(SPEC_PATH), "evidence-policy", ("rule", "requirement"))
    policy = {row["rule"]: row["requirement"] for row in rows}
    assert policy == _model()["evidence_policy"]
    assert policy["evaluation unit"] == "one complete append-only Phase 0 TOML file"
    assert policy["gate result when a required runtime or service is unavailable"] == (
        "BLOCKED when no required check fails; never PASS"
    )


def test_phase_zero_launcher_surfaces_defer_release_verification_mechanisms() -> None:
    for path in (
        ROOT / "packages/launcher/AGENTS.md",
        ROOT / "packages/launcher/README.md",
        ROOT / "packages/launcher/src/cairnvm_launcher/__init__.py",
        ROOT / "SECURITY.md",
    ):
        document = " ".join(_text(path).split())
        assert "independently reviewed release-verification and authorization boundary" in document
        assert "mechanisms are deferred to a Phase 1 ADR/spec gate" in document
        assert not any(
            term in document.casefold()
            for term in (
                "signing identity",
                "signing identities",
                "signing policy",
                "signature",
                "digest",
                "archive",
            )
        )


def test_overview_and_roadmap_agree_on_publication_and_reconciliation() -> None:
    sentence = (
        "Publication is not completed remote durability; completion requires both required "
        "provider objects and the independently trusted anchor to reconcile as "
        "present-as-intended for the authenticated checkpoint identity, parent, references, "
        "and required head relationship."
    )
    for path in (OVERVIEW_PATH, ROADMAP_PATH):
        assert sentence in " ".join(_text(path).split())


@pytest.mark.parametrize("path", (SPEC_PATH, MODEL_PATH, ADR_PATH, OVERVIEW_PATH, ROADMAP_PATH))
def test_contract_files_have_no_trailing_whitespace(path: Path) -> None:
    assert all(line == line.rstrip() for line in _text(path).splitlines())
