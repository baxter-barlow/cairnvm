from __future__ import annotations

import json
import re
import tomllib
import unicodedata
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_GUIDE = ROOT / "Docs/evidence/phase-0/README.md"
REVIEWED_AT_UTC = "2026-08-20T00:00:00Z"
EVALUATION_SCHEMA_VERSION = 1
MAX_EVALUATION_BYTES = 65_536
EVALUATION_FIELDS = tuple(
    (  # noqa: SIM905 - Compact immutable schema oracle.
        "schema_version phase_id tested_commit exact_parent publication_branch "
        "grant_lineage_id resource_workload_id tested_at_utc commands environment "
        "synthetic_data redactions limitations results"
    ).split()
)
RESULT_FIELDS = ("criterion_id", "outcome", "evidence", "limitation", "shared_binding_id")
GRANT_CRITERIA = tuple(
    "phase-0-drive-synthetic-round-trip phase-0-oauth-authorization phase-0-oauth-refresh".split()  # noqa: SIM905 - Compact immutable schema oracle.
)
RESOURCE_WORKLOAD_CRITERIA = tuple(
    "phase-0-runtime-memory-control phase-0-repository-geometry".split()  # noqa: SIM905 - Compact immutable schema oracle.
)


def _flat(relative_path: str) -> str:
    return " ".join((ROOT / relative_path).read_text(encoding="utf-8").split())


def _model() -> dict[str, Any]:
    with (ROOT / "Docs/architecture-state-model.toml").open("rb") as handle:
        return tomllib.load(handle)


def _toml_example(document: str) -> tuple[str, dict[str, Any]]:
    [block] = document.split("```toml")[1:]
    raw = block.split("```", 1)[0].strip()
    return raw, tomllib.loads(raw)


def _sample_evaluation() -> tuple[str, dict[str, Any]]:
    return _toml_example(EVIDENCE_GUIDE.read_text(encoding="utf-8"))


def _phase_zero_criteria() -> tuple[str, ...]:
    gate = next(item for item in _model()["phase_gate"] if item["phase"] == 0)
    return tuple(gate["criteria_ids"])


def _is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _is_normalized_branch(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and unicodedata.is_normalized("NFC", value)
    )


def _toml_value(value: object) -> str:
    if isinstance(value, (str, int, bool)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return f"[{', '.join(_toml_value(item) for item in value)}]"
    raise TypeError(f"unsupported TOML test value: {type(value).__name__}")


def _render_evaluation(evaluation: dict[str, Any]) -> bytes:
    lines: list[str] = []
    for field, value in evaluation.items():
        if field != "results":
            lines.append(f"{field} = {_toml_value(value)}")
            continue
        if isinstance(value, list) and all(isinstance(result, dict) for result in value):
            for result in value:
                lines.append("")
                lines.append("[[results]]")
                lines.extend(f"{key} = {_toml_value(item)}" for key, item in result.items())
        else:
            lines.append(f"results = {_toml_value(value)}")
    return ("\n".join(lines) + "\n").encode()


def _parse_structurally_publishable_evaluation(raw: bytes) -> dict[str, Any] | None:
    if len(raw) > MAX_EVALUATION_BYTES:
        return None
    try:
        evaluation = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    if tuple(evaluation) != EVALUATION_FIELDS:
        return None
    if type(evaluation["schema_version"]) is not int:  # bool is an int subclass
        return None
    if evaluation["schema_version"] != EVALUATION_SCHEMA_VERSION:
        return None
    if not isinstance(evaluation["phase_id"], str) or evaluation["phase_id"] != "phase-0":
        return None
    sha = re.compile(r"[0-9a-f]{40}\Z")
    if not isinstance(evaluation["tested_commit"], str) or not sha.fullmatch(
        evaluation["tested_commit"]
    ):
        return None
    if not isinstance(evaluation["exact_parent"], str) or not sha.fullmatch(
        evaluation["exact_parent"]
    ):
        return None
    if evaluation["exact_parent"] != evaluation["tested_commit"]:
        return None
    if not _is_normalized_branch(evaluation["publication_branch"]):
        return None
    for field in ("grant_lineage_id", "resource_workload_id"):
        if not _is_nonempty_string(evaluation[field]):
            return None
    if not isinstance(evaluation["tested_at_utc"], str):
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", evaluation["tested_at_utc"]):
        return None
    try:
        datetime.strptime(evaluation["tested_at_utc"], "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return None
    commands = evaluation["commands"]
    if not isinstance(commands, list) or not commands:
        return None
    if not all(_is_nonempty_string(item) for item in commands):
        return None
    for field in ("environment", "synthetic_data", "redactions", "limitations"):
        if not _is_nonempty_string(evaluation[field]):
            return None
    results = evaluation["results"]
    if (
        not isinstance(results, list)
        or len(results) != len(_phase_zero_criteria())
        or not all(isinstance(result, dict) for result in results)
    ):
        return None
    if tuple(result.get("criterion_id") for result in results) != _phase_zero_criteria():
        return None
    for result in results:
        if tuple(result) != RESULT_FIELDS:
            return None
        if not isinstance(result["outcome"], str) or result["outcome"] not in {
            "PASS",
            "FAIL",
            "BLOCKED",
        }:
            return None
        if not isinstance(result["evidence"], str) or not isinstance(result["limitation"], str):
            return None
        if result["outcome"] in {"PASS", "FAIL"} and not result["evidence"]:
            return None
        if result["outcome"] == "BLOCKED" and not result["limitation"]:
            return None
        criterion_id = result["criterion_id"]
        expected_binding = ""
        if criterion_id in GRANT_CRITERIA:
            expected_binding = evaluation["grant_lineage_id"]
        elif criterion_id in RESOURCE_WORKLOAD_CRITERIA:
            expected_binding = evaluation["resource_workload_id"]
        if result["shared_binding_id"] != expected_binding:
            return None
    return evaluation


def _parse_publishable_evaluation(
    raw: bytes,
    *,
    expected_tested_commit: str,
    expected_exact_parent: str,
    expected_branch: str,
    reviewed_at_utc: str,
) -> dict[str, Any] | None:
    evaluation = _parse_structurally_publishable_evaluation(raw)
    if evaluation is None:
        return None
    try:
        tested_at = datetime.strptime(evaluation["tested_at_utc"], "%Y-%m-%dT%H:%M:%SZ")
        reviewed_at = datetime.strptime(reviewed_at_utc, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return None
    if tested_at > reviewed_at:
        return None
    if (
        evaluation["tested_commit"] != expected_tested_commit
        or evaluation["exact_parent"] != expected_exact_parent
        or evaluation["publication_branch"] != expected_branch
    ):
        return None
    return evaluation


def _aggregate(evaluation: dict[str, Any]) -> str:
    outcomes = tuple(result["outcome"] for result in evaluation["results"])
    if "FAIL" in outcomes:
        return "failed"
    if "BLOCKED" in outcomes:
        return "blocked"
    if outcomes and set(outcomes) == {"PASS"}:
        return "passed"
    raise ValueError("evaluation is not complete")


def _filename_for(evaluation: dict[str, Any]) -> str:
    timestamp = re.sub(r"[-:]", "", evaluation["tested_at_utc"])
    return f"{timestamp}-phase-0-evaluation.toml"


def _parse_in_sample_context(raw: bytes, evaluation: dict[str, Any]) -> dict[str, Any] | None:
    return _parse_publishable_evaluation(
        raw,
        expected_tested_commit=evaluation["tested_commit"],
        expected_exact_parent=evaluation["exact_parent"],
        expected_branch=evaluation["publication_branch"],
        reviewed_at_utc=REVIEWED_AT_UTC,
    )


def _valid_in_sample(candidate: dict[str, Any], sample: dict[str, Any]) -> bool:
    return _parse_in_sample_context(_render_evaluation(candidate), sample) is not None


def _with_top(sample: dict[str, Any], field: str, value: object) -> dict[str, Any]:
    candidate = deepcopy(sample)
    candidate[field] = value
    return candidate


def _with_result(sample: dict[str, Any], field: str, value: object) -> dict[str, Any]:
    candidate = deepcopy(sample)
    candidate["results"][0][field] = value
    return candidate


def _project_phase_zero_status(
    evaluations: list[tuple[str, bytes]],
    *,
    work_started: bool,
) -> str:
    if not evaluations:
        return "in-progress" if work_started else "not-started"
    filenames = tuple(filename for filename, _raw in evaluations)
    if filenames != tuple(sorted(filenames)) or len(filenames) != len(set(filenames)):
        raise ValueError("evaluation order is invalid")
    if not all(re.fullmatch(r"\d{8}T\d{6}Z-phase-0-evaluation\.toml", name) for name in filenames):
        raise ValueError("evaluation filename is invalid")
    statuses: list[str] = []
    for filename, raw in evaluations:
        evaluation = _parse_structurally_publishable_evaluation(raw)
        if evaluation is None:
            raise ValueError("evaluation history is invalid")
        if filename != _filename_for(evaluation):
            raise ValueError("evaluation filename is invalid")
        statuses.append(_aggregate(evaluation))
    if "passed" in statuses[:-1]:
        raise ValueError("passed is terminal")
    assert evaluation is not None
    return _aggregate(evaluation)


def test_change_workflow_orders_local_staged_and_secret_gates() -> None:
    for relative_path in ("AGENTS.md", "CONTRIBUTING.md"):
        document = _flat(relative_path)
        local_checks = document.index("Run `make lint typecheck test`")
        stage = document.index("Stage only the intended files")
        artifact_gate = document.index("Run `make check`")
        secret_gate = document.index("`make scan-staged`")
        assert local_checks < stage < artifact_gate < secret_gate
        assert "restage the exact files and repeat both staged gates" in document


def test_sensitive_review_repeats_the_exact_candidate_loop_before_commit() -> None:
    for relative_path in ("AGENTS.md", "CONTRIBUTING.md"):
        document = _flat(relative_path)
        assert document.index("independent adversarial subagent review") < document.index(
            "Commit the tested"
        )
        assert "exact staged candidate" in document
        assert "no negative finding" in document
        assert "repeat the local checks, staging, both staged gates, and review" in document


def test_readme_separates_setup_from_change_verification() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    flat_readme = " ".join(readme.split())
    assert "uv run --locked --all-packages cairnvm --version" in readme
    assert "uv run --locked --all-packages cairnvm doctor --json" in readme
    assert "A fresh clone is already an index-clean snapshot" in flat_readme
    assert (
        "stage only the intended files, then run `make check` and `make scan-staged`" in flat_readme
    )
    assert "restage and repeat both staged gates" in flat_readme


def test_evidence_publication_policy_is_manual_and_two_commit() -> None:
    evidence = _flat("Docs/evidence/phase-0/README.md")
    specification = _flat("Docs/Architecture-Spec.md")
    evaluation_rule = "exactly one new complete Phase 0 evaluation TOML file"
    roadmap_rule = "`ROADMAP.md` only when the aggregate phase status changes"
    conditional_scope = f"{evaluation_rule} and optionally {roadmap_rule}"
    required = (evaluation_rule, roadmap_rule)

    def policy_is_current(document: str) -> bool:
        return all(rule in document for rule in required) and "its index" not in document

    for relative_path in ("AGENTS.md", "CONTRIBUTING.md"):
        document = _flat(relative_path)
        assert "tested implementation commit" in document
        assert "evidence/status commit" in document
        assert policy_is_current(document)
        assert not policy_is_current(
            document.replace(evaluation_rule, "redacted evidence, its index")
        )
    for requirement in (  # noqa: SIM905 - fixed phrases keep this contract within its line cap.
        "two-commit publication sequence is strict|single-parent evidence/status commit|"
        "exact implementation parent|full `tested_commit` SHA|independent reviewer reports no "
        "negative finding|force-push and branch-deletion protection"
    ).split("|"):
        assert requirement in evidence
    for document in (evidence, specification):
        assert conditional_scope in document and "allowed two-file scope" not in document
    for retired_shape in (
        "criterion record",
        "evaluation manifest",
        "optional index",
        "index.toml",
    ):
        assert retired_shape not in evidence.casefold()


def test_phase_evidence_sample_is_one_exact_bounded_whole_evaluation() -> None:
    evidence = (ROOT / "Docs/evidence/phase-0/README.md").read_text(encoding="utf-8")
    raw, evaluation = _toml_example(evidence)
    accounting = _model()["phase_result_accounting"]
    assert len(raw.encode()) <= MAX_EVALUATION_BYTES
    assert tuple(evaluation) == EVALUATION_FIELDS == tuple(accounting["evaluation_fields"])
    assert tuple(evaluation["results"][0]) == RESULT_FIELDS == tuple(accounting["result_fields"])
    assert tuple(result["criterion_id"] for result in evaluation["results"]) == (
        _phase_zero_criteria()
    )
    assert _parse_in_sample_context(raw.encode(), evaluation) == evaluation
    flat = " ".join(evidence.split())
    assert "criterion itself is the stable result ID" in flat
    assert "one `[[results]]` row for every Phase 0 criterion" in flat
    assert "No partial evaluation is publishable" in flat
    assert "Control-path rationale:" in evaluation["synthetic_data"]


def test_evaluation_rejects_schema_and_candidate_context_mutations() -> None:
    evidence = (ROOT / "Docs/evidence/phase-0/README.md").read_text(encoding="utf-8")
    _raw, evaluation = _toml_example(evidence)

    for field in tuple(evaluation):
        missing = deepcopy(evaluation)
        missing.pop(field)
        assert not _valid_in_sample(missing, evaluation)
    assert not _valid_in_sample(_with_top(evaluation, "summary", "PASS"), evaluation)
    for version in (True, 0, 2, "1"):
        assert not _valid_in_sample(_with_top(evaluation, "schema_version", version), evaluation)
    for field, value in (
        ("tested_commit", "abc"),
        ("exact_parent", "ABCDEF0123456789abcdef0123456789abcdef01"),
        ("publication_branch", "release"),
        ("tested_at_utc", "2026-99-19T12:00:00Z"),
    ):
        assert not _valid_in_sample(_with_top(evaluation, field, value), evaluation)
    coordinated_wrong = deepcopy(evaluation)
    coordinated_wrong["tested_commit"] = coordinated_wrong["exact_parent"] = "f" * 40
    assert not _valid_in_sample(coordinated_wrong, evaluation)
    coordinated_wrong["publication_branch"] = "release"
    assert not _valid_in_sample(coordinated_wrong, evaluation)
    future = _with_top(evaluation, "tested_at_utc", "2026-08-21T00:00:00Z")
    assert not _valid_in_sample(future, evaluation)
    unequal_binding = deepcopy(evaluation)
    unequal_binding["exact_parent"] = "f" * 40
    assert (
        _parse_publishable_evaluation(
            _render_evaluation(unequal_binding),
            expected_tested_commit=evaluation["tested_commit"],
            expected_exact_parent="f" * 40,
            expected_branch=evaluation["publication_branch"],
            reviewed_at_utc=REVIEWED_AT_UTC,
        )
        is None
    )
    malformed_values: tuple[tuple[str, Any], ...] = (
        ("phase_id", 0),
        ("tested_commit", 1),
        ("exact_parent", []),
        ("tested_at_utc", 0),
        ("publication_branch", False),
        ("grant_lineage_id", []),
        ("resource_workload_id", 0),
        ("commands", "make test"),
        ("environment", []),
        ("synthetic_data", False),
        ("redactions", 0),
        ("limitations", []),
        ("results", [1]),
    )
    for field, value in malformed_values:
        assert not _valid_in_sample(_with_top(evaluation, field, value), evaluation)
    assert _parse_structurally_publishable_evaluation(b"\xff") is None
    assert _parse_structurally_publishable_evaluation(b"not = [valid") is None


def test_evaluation_rejects_result_set_mutations_and_invalid_outcome() -> None:
    _raw, evaluation = _sample_evaluation()

    mutations: list[dict[str, Any]] = []
    missing = deepcopy(evaluation)
    missing["results"].pop()
    mutations.append(missing)
    extra = deepcopy(evaluation)
    extra["results"].append(deepcopy(extra["results"][-1]))
    mutations.append(extra)
    duplicate = deepcopy(evaluation)
    duplicate["results"][1]["criterion_id"] = duplicate["results"][0]["criterion_id"]
    mutations.append(duplicate)
    unknown = deepcopy(evaluation)
    unknown["results"][0]["criterion_id"] = "phase-0-hidden-result"
    mutations.append(unknown)
    reordered = deepcopy(evaluation)
    reordered["results"][0], reordered["results"][1] = (
        reordered["results"][1],
        reordered["results"][0],
    )
    mutations.append(reordered)
    mutations.append(_with_result(evaluation, "outcome", "UNKNOWN"))
    mutations.append(_with_result(evaluation, "outcome", []))
    mutations.append(_with_result(evaluation, "subresults", ["PASS"]))
    missing_field = deepcopy(evaluation)
    missing_field["results"][0].pop("limitation")
    mutations.append(missing_field)
    mutations.extend(
        (
            _with_top(evaluation, "commands", []),
            _with_top(evaluation, "environment", ""),
            _with_top(evaluation, "publication_branch", f" {evaluation['publication_branch']}"),
            _with_top(evaluation, "publication_branch", "rele\u0301ase"),
            _with_top(evaluation, "commands", [""]),
        )
    )
    for field, value in (
        ("criterion_id", 0),
        ("outcome", 0),
        ("evidence", []),
        ("limitation", False),
        ("shared_binding_id", 0),
    ):
        mutations.append(_with_result(evaluation, field, value))
    assert all(not _valid_in_sample(candidate, evaluation) for candidate in mutations)


def test_free_text_and_arrays_are_bounded_only_by_the_raw_file() -> None:
    _raw, evaluation = _sample_evaluation()
    evaluation["publication_branch"] = "x" * 501
    evaluation["commands"] = ["x" * 501] * 33
    evaluation["environment"] = "x" * 2_001
    evaluation["grant_lineage_id"] = "g" * 501
    for result in evaluation["results"]:
        result["limitation"] = "x" * 501
        if result["criterion_id"] in GRANT_CRITERIA:
            result["shared_binding_id"] = evaluation["grant_lineage_id"]
    raw = _render_evaluation(evaluation)
    assert len(raw) < MAX_EVALUATION_BYTES
    assert _parse_structurally_publishable_evaluation(raw) == evaluation


def test_raw_utf8_boundary_is_preparse(monkeypatch: pytest.MonkeyPatch) -> None:
    _raw, evaluation = _sample_evaluation()
    base = _render_evaluation(evaluation)
    exact_size = base + b"\n#" + b"x" * (MAX_EVALUATION_BYTES - len(base) - 2)
    assert len(exact_size) == MAX_EVALUATION_BYTES
    assert tomllib.loads(exact_size.decode("utf-8")) == evaluation
    assert _parse_in_sample_context(exact_size, evaluation) is not None
    oversized = exact_size + b"x"
    assert tomllib.loads(oversized.decode("utf-8")) == evaluation
    monkeypatch.setattr(tomllib, "loads", lambda _text: pytest.fail("parsed oversized input"))
    assert _parse_in_sample_context(oversized, evaluation) is None


def test_evaluation_rejects_mismatched_shared_grant_and_workload_bindings() -> None:
    _raw, evaluation = _sample_evaluation()

    mutations: list[dict[str, Any]] = []
    for criterion_id in (next(iter(GRANT_CRITERIA)), next(iter(RESOURCE_WORKLOAD_CRITERIA))):
        mismatch = deepcopy(evaluation)
        next(result for result in mismatch["results"] if result["criterion_id"] == criterion_id)[
            "shared_binding_id"
        ] = "different-binding"
        mutations.append(mismatch)
    unrelated = deepcopy(evaluation)
    unrelated["results"][0]["shared_binding_id"] = unrelated["grant_lineage_id"]
    mutations.append(unrelated)
    for field in ("grant_lineage_id", "resource_workload_id"):
        mutations.append(_with_top(evaluation, field, ""))
    assert all(not _valid_in_sample(candidate, evaluation) for candidate in mutations)


def test_total_aggregation_and_latest_complete_evaluation_projection() -> None:
    raw, evaluation = _sample_evaluation()
    all_pass = deepcopy(evaluation)
    for result in all_pass["results"]:
        result["outcome"] = "PASS"
        result["evidence"] = "Synthetic gate evidence reference."
        result["limitation"] = "None."
    blocked_from_raw = _parse_structurally_publishable_evaluation(raw.encode())
    passed_from_raw = _parse_structurally_publishable_evaluation(_render_evaluation(all_pass))
    assert blocked_from_raw is not None and _aggregate(blocked_from_raw) == "blocked"
    assert passed_from_raw is not None and _aggregate(passed_from_raw) == "passed"
    mixed = deepcopy(all_pass)
    mixed["results"][0]["outcome"] = "BLOCKED"
    mixed["results"][0]["limitation"] = "Required service unavailable."
    mixed["results"][1]["outcome"] = "FAIL"
    assert _aggregate(mixed) == "failed"

    def status(history: list[tuple[str, bytes]], *, work_started: bool = True) -> str:
        return _project_phase_zero_status(history, work_started=work_started)

    assert status([], work_started=False) == "not-started"
    assert status([]) == "in-progress"

    earlier = deepcopy(evaluation)
    earlier["tested_at_utc"] = "2026-08-18T12:00:00Z"
    later = deepcopy(all_pass)
    later["tested_at_utc"] = "2026-08-19T12:00:00Z"
    history = [
        (_filename_for(earlier), _render_evaluation(earlier)),
        (_filename_for(later), _render_evaluation(later)),
    ]
    assert status(history) == "passed"
    with pytest.raises(ValueError, match="order"):
        status(list(reversed(history)))
    malformed_earlier = deepcopy(earlier)
    malformed_earlier["schema_version"] = 999
    with pytest.raises(ValueError, match="history is invalid"):
        status(
            [
                (_filename_for(earlier), _render_evaluation(malformed_earlier)),
                (_filename_for(later), _render_evaluation(later)),
            ]
        )
    passed_first = deepcopy(all_pass)
    passed_first["tested_at_utc"] = "2026-08-18T12:00:00Z"
    blocked_later = deepcopy(evaluation)
    blocked_later["tested_at_utc"] = "2026-08-19T12:00:00Z"
    terminal_regression = [
        (_filename_for(passed_first), _render_evaluation(passed_first)),
        (_filename_for(blocked_later), _render_evaluation(blocked_later)),
    ]
    with pytest.raises(ValueError, match="passed is terminal"):
        status(terminal_regression)
    with pytest.raises(ValueError, match="filename"):
        _project_phase_zero_status(
            [("wrong-evaluation.toml", _render_evaluation(earlier))],
            work_started=True,
        )


def test_checked_in_phase_zero_evaluations_project_the_only_roadmap_status() -> None:
    evidence_dir = ROOT / "Docs/evidence/phase-0"
    paths = sorted(path for path in evidence_dir.iterdir() if path.name != "README.md")
    status = _project_phase_zero_status(
        [(path.name, path.read_bytes()) for path in paths], work_started=True
    )
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    row = re.search(r"\| 0 \| phase-0 \| ([a-z-]+) \|", roadmap)
    assert row is not None and row.group(1) == status
    flat_roadmap = " ".join(roadmap.split())
    assert ("no evaluation exists" in flat_roadmap) is (not paths)


def test_status_resource_and_evaluation_boundaries_are_single_and_exact() -> None:
    spec = (ROOT / "Docs/Architecture-Spec.md").read_text(encoding="utf-8")
    overview = (ROOT / "OVERVIEW.md").read_text(encoding="utf-8")
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    with (ROOT / "Docs/architecture-state-model.toml").open("rb") as handle:
        model = tomllib.load(handle)
    for document in (spec, overview):
        assert "review-pending" not in document
    assert "candidate_status" not in model
    assert "## Phase 0 — Feasibility scaffold\n" in roadmap
    assert "At this snapshot" not in roadmap
    accounting = model["phase_result_accounting"]
    expected_keys = (  # noqa: SIM905 - Compact immutable schema oracle.
        "aggregation_rule criterion_outcome_rule criterion_result_identity evaluation_fields "
        "evaluation_schema_version evaluation_scope filename_pattern grant_lineage_criteria "
        "latest_evaluation_selection max_evaluation_bytes outcomes "
        "representative_resource_workload resource_workload_criteria result_fields"
    ).split()
    assert set(accounting) == set(expected_keys)
    assert accounting["evaluation_scope"] == (
        "one complete append-only raw UTF-8 evaluation TOML bound to phase_id, tested_commit, "
        "exact_parent, publication_branch, grant lineage, and resource workload"
    )
    assert accounting["representative_resource_workload"] == (
        "one declared functional representative nonzero synthetic Drive-backed VM "
        "control-path workload with predeclared byte/object limits and one forced-over-limit "
        "nonzero exit per resource criterion"
    )
    assert tuple(accounting["grant_lineage_criteria"]) == GRANT_CRITERIA
    assert tuple(accounting["resource_workload_criteria"]) == RESOURCE_WORKLOAD_CRITERIA
    expected_caps = {
        "evaluation_schema_version": EVALUATION_SCHEMA_VERSION,
        "max_evaluation_bytes": MAX_EVALUATION_BYTES,
    }
    assert {key: accounting[key] for key in expected_caps} == expected_caps
    flat_spec = " ".join(spec.split())
    flat_overview = " ".join(overview.split())
    assert "fence acquisition bound to that pre-acquisition context" in flat_overview
    assert "before any other remote mutation" in flat_overview
    assert "same declared functional representative nonzero synthetic workload" in flat_spec
    assert "partial evaluation is never publishable" in flat_spec.casefold()
    assert "latest complete evaluation" in flat_spec
    criterion_rules = (
        ("any-required-check-fails", "FAIL"),
        ("any-required-check-blocked", "BLOCKED"),
        ("all-required-checks-pass", "PASS"),
    )
    assert (
        tuple((item["condition"], item["outcome"]) for item in accounting["criterion_outcome_rule"])
        == criterion_rules
    )
    assert all(f"| {condition} | {outcome} |" in spec for condition, outcome in criterion_rules)
    criterion_table = spec.split("<!-- cairnvm-contract:phase-criterion-outcomes -->", 1)[1].split(
        "\n\n", 1
    )[0]
    assert sum(line.startswith("|") for line in criterion_table.splitlines()) == 5
    mirrored = {
        "evaluation_schema_version": str(accounting["evaluation_schema_version"]),
        "criterion_result_identity": accounting["criterion_result_identity"],
        "evaluation_scope": accounting["evaluation_scope"],
        "filename_pattern": accounting["filename_pattern"],
        "latest_evaluation_selection": accounting["latest_evaluation_selection"],
        "max_evaluation_bytes": str(accounting["max_evaluation_bytes"]),
        "evaluation_fields": ", ".join(accounting["evaluation_fields"]),
        "result_fields": ", ".join(accounting["result_fields"]),
        "outcomes": ", ".join(accounting["outcomes"]),
        "grant_lineage_criteria": ", ".join(accounting["grant_lineage_criteria"]),
        "resource_workload_criteria": ", ".join(accounting["resource_workload_criteria"]),
        "representative_resource_workload": accounting["representative_resource_workload"],
    }
    assert all(f"| {key} | {value} |" in spec for key, value in mirrored.items())
    accounting_table = spec.split("<!-- cairnvm-contract:phase-evaluation-accounting -->", 1)[
        1
    ].split("\n\n", 1)[0]
    assert sum(line.startswith("|") for line in accounting_table.splitlines()) == len(mirrored) + 2
    retired_caps = (  # noqa: SIM905 - Compact retired-name oracle.
        "max_commands,max_command_chars,max_context_chars,max_publication_branch_chars,"
        "max_result_reference_chars,max_link_id_chars"
    ).split(",")
    evidence = (ROOT / "Docs/evidence/phase-0/README.md").read_text(encoding="utf-8")
    assert all(cap not in accounting for cap in retired_caps)
    assert all(cap not in spec for cap in retired_caps)
    assert "characters each" not in evidence


def test_custom_evidence_history_verifier_remains_retired() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    pre_commit = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert not (ROOT / "scripts/verify_evidence.py").exists()
    assert not (ROOT / "tests/unit/test_evidence_verifier.py").exists()
    for workflow in (makefile, pre_commit, ci):
        assert "verify_evidence" not in workflow
        assert "verify-evidence" not in workflow
    assert "check: lint typecheck test verifier-coverage" in makefile
    assert "make verify-evidence-postcommit" not in ci


def test_secret_and_dependency_gates_remain_enabled() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    pre_commit = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert (
        "env -u SKIP -u CAIRNVM_GITLEAKS_BOOTSTRAPPED CAIRNVM_SECRET_SCAN_SCOPE=staged "
        "uv run --locked --all-packages python scripts/verify_secret_scanner.py" in makefile
    )
    gitleaks_hook = pre_commit.split("- id: gitleaks", 1)[1]
    assert "entry: python3 scripts/verify_secret_scanner.py" in gitleaks_hook
    assert "pass_filenames: false" in gitleaks_hook
    assert "always_run: true" in gitleaks_hook
    secret_job = ci.split("  secret-scan:", 1)[1].split("  dependency-audit:", 1)[0]
    audit_job = ci.split("  dependency-audit:", 1)[1]
    assert "fetch-depth: 0" in secret_job
    assert (
        "env -u SKIP -u CAIRNVM_GITLEAKS_BOOTSTRAPPED CAIRNVM_SECRET_SCAN_SCOPE=history "
        "uv run --locked --all-packages python scripts/verify_secret_scanner.py" in secret_job
    )
    assert "pre-commit run" not in secret_job
    assert "pip-audit" in audit_job


def test_status_and_user_visible_scope_have_distinct_doc_updates() -> None:
    agent_guide = _flat("AGENTS.md")
    assert "Update `README.md` and `OVERVIEW.md` when user-visible scope changes" in agent_guide
    assert "Update `ROADMAP.md` when execution or phase status changes" in agent_guide


def test_staged_gate_and_optional_hooks_have_honest_boundaries() -> None:
    verifier = (ROOT / "scripts/verify_artifacts.py").read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert 'f"--exclude-from={ignore_file}"' in verifier
    assert "nonignored untracked paths are present" in verifier
    assert not (ROOT / "scripts/install_hooks.py").exists()
    assert not (ROOT / "tests/unit/test_hook_installer.py").exists()
    assert "\nhooks:" not in makefile
    assert "does not install Git hooks automatically" in readme
    assert "defense in depth, not an enforcement boundary" in " ".join(readme.split())


def test_repository_authorities_and_security_promises_are_precise() -> None:
    agent_guide = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    docs_guide = (ROOT / "Docs/AGENTS.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    security = _flat("SECURITY.md")
    for document in (agent_guide, docs_guide, readme):
        flat_document = " ".join(document.split()).casefold()
        assert "selected constants, limits, transitions, and recovery contracts" in flat_document
        assert "explicitly mirrors" in flat_document
    assert "secret or private keys" in security
    assert "independently reviewed release-verification and authorization boundary" in security
    assert "mechanisms are deferred to a Phase 1 ADR/spec gate" in security
    premature = ("signing identity", "signing identities", "signature", "digest", "archive")
    assert not any(term in security.casefold() for term in premature)
    assert "does not guarantee an acknowledgment deadline" in security


def test_publication_and_local_state_guardrails_are_preserved() -> None:
    roadmap = _flat("ROADMAP.md")
    patterns = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "phase-0-ci-required-checks" in roadmap
    assert "phase-0-publication-controls" in roadmap
    assert "/state/" in patterns and "/secrets/" in patterns
    assert "**/state/" not in patterns and "**/secrets/" not in patterns
