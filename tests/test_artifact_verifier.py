"""Regression tests for the ordinary developer/CI artifact release gate."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from scripts import verify_artifacts
from scripts.verify_artifacts import (
    BUILD_CONSTRAINTS,
    EXPECTED_RELEASES,
    Release,
    VerificationError,
    collect_artifacts,
    finish_staged_index,
    materialize_staged_index,
    rebuild_wheel,
    smoke_test_wheel,
)


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    git = shutil.which("git")
    assert git is not None
    return subprocess.run(  # noqa: S603 - test helper invokes Git with test-owned arguments
        [git, *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def clean_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    (repository / "build-constraints.txt").write_text(
        "backend==1.0 --hash=sha256:" + ("a" * 64) + "\n",
        encoding="utf-8",
    )
    (repository / ".gitignore").write_text("dist/\n", encoding="utf-8")
    (repository / "tracked.txt").write_text("original\n", encoding="utf-8")
    _git(repository, "add", "build-constraints.txt", ".gitignore", "tracked.txt")
    return repository


def test_release_gate_states_its_limited_trust_boundary() -> None:
    assert "authorized developer and CI" in verify_artifacts.__doc__
    assert "malicious local Git object storage" in verify_artifacts.__doc__
    assert "concurrent hostile processes" in verify_artifacts.__doc__


def test_make_targets_run_the_real_gate_once_before_verifier_coverage() -> None:
    makefile = (verify_artifacts.ROOT / "Makefile").read_text(encoding="utf-8")

    assert "rm -f dist/.gitignore" in makefile
    assert "verify-artifacts: build" not in makefile
    assert (
        'verify-artifacts:\n\tenv -i HOME="$$HOME" PATH="$$PATH" LANG=C LC_ALL=C '
        "uv run --no-config --no-env-file --locked --all-packages "
        "python scripts/verify_artifacts.py" in (makefile)
    )
    assert "verifier-coverage: verify-artifacts" in makefile
    assert "verifier-coverage: build" not in makefile


def test_materialized_index_ignores_only_ignored_build_output(
    clean_repository: Path,
    tmp_path: Path,
) -> None:
    ignored = clean_repository / "dist" / "pyproject.toml"
    ignored.parent.mkdir()
    ignored.write_text("[build-system]\nrequires = ['injected']\n", encoding="utf-8")
    snapshot = tmp_path / "snapshot"

    tree = materialize_staged_index(clean_repository, snapshot)

    assert tree == _git(clean_repository, "write-tree").stdout.strip()
    assert (snapshot / "tracked.txt").read_text(encoding="utf-8") == "original\n"
    assert not (snapshot / "dist").exists()
    finish_staged_index(clean_repository, tree)


@pytest.mark.parametrize("drift", ["content", "mode", "untracked"])
def test_materializer_rejects_tracked_drift_and_nonignored_untracked_paths(
    clean_repository: Path,
    tmp_path: Path,
    drift: str,
) -> None:
    tracked = clean_repository / "tracked.txt"
    if drift == "content":
        tracked.write_text("unstaged injection\n", encoding="utf-8")
    elif drift == "mode":
        tracked.chmod(tracked.stat().st_mode | 0o111)
    else:
        (clean_repository / "unexpected.txt").write_text("injection\n", encoding="utf-8")

    with pytest.raises(VerificationError, match=r"worktree|untracked"):
        materialize_staged_index(clean_repository, tmp_path / "snapshot")


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_materializer_rejects_index_visibility_flags(
    clean_repository: Path,
    tmp_path: Path,
    flag: str,
) -> None:
    _git(clean_repository, "update-index", flag, "tracked.txt")

    with pytest.raises(VerificationError, match="index flags"):
        materialize_staged_index(clean_repository, tmp_path / "snapshot")


def test_worktree_comparison_reads_bytes_instead_of_trusting_git_stat_cache(
    clean_repository: Path,
) -> None:
    entries = verify_artifacts._parse_index_entries(
        verify_artifacts._git_bytes(clean_repository, "ls-files", "--stage", "-z")
    )
    _git(clean_repository, "update-index", "--assume-unchanged", "tracked.txt")
    (clean_repository / "tracked.txt").write_text("injected\n", encoding="utf-8")

    with pytest.raises(VerificationError, match="worktree bytes"):
        verify_artifacts._require_exact_worktree(clean_repository, entries)


@pytest.mark.parametrize("location", ["info", "local", "home", "xdg"])
def test_materializer_rejects_untracked_paths_hidden_by_ambient_ignores(
    clean_repository: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    hidden_name = "ambient-hidden.txt"
    (clean_repository / hidden_name).write_text("injection\n", encoding="utf-8")
    if location == "info":
        (clean_repository / ".git/info/exclude").write_text(f"{hidden_name}\n", encoding="utf-8")
    elif location == "local":
        excludes = tmp_path / "local-excludes"
        excludes.write_text(f"{hidden_name}\n", encoding="utf-8")
        _git(clean_repository, "config", "--local", "core.excludesFile", str(excludes))
    elif location == "home":
        home = tmp_path / "home"
        excludes = home / ".config/git/ignore"
        excludes.parent.mkdir(parents=True)
        excludes.write_text(f"{hidden_name}\n", encoding="utf-8")
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    else:
        xdg = tmp_path / "xdg"
        excludes = xdg / "git/ignore"
        excludes.parent.mkdir(parents=True)
        excludes.write_text(f"{hidden_name}\n", encoding="utf-8")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))

    with pytest.raises(VerificationError, match="nonignored untracked"):
        materialize_staged_index(clean_repository, tmp_path / "snapshot")


def _write_self_hiding_untracked_test(repository: Path) -> None:
    injected = repository / "tests/injected"
    injected.mkdir(parents=True)
    (injected / ".gitignore").write_text("*\n", encoding="utf-8")
    (injected / "test_injected.py").write_text(
        "def test_injected():\n    assert False\n",
        encoding="utf-8",
    )


def test_materializer_rejects_an_untracked_ignore_file_that_hides_its_directory(
    clean_repository: Path,
    tmp_path: Path,
) -> None:
    _write_self_hiding_untracked_test(clean_repository)
    assert not verify_artifacts._git_bytes(
        clean_repository,
        "ls-files",
        "--others",
        "--exclude-per-directory=.gitignore",
        "-z",
    )

    with pytest.raises(VerificationError, match="nonignored untracked"):
        materialize_staged_index(clean_repository, tmp_path / "snapshot")


def test_trusted_ignore_policy_allows_no_ignore_file_and_rejects_nested_controls(
    clean_repository: Path,
) -> None:
    assert verify_artifacts._trusted_root_ignore(clean_repository, ()) == b""
    nested = verify_artifacts.IndexEntry(b"100644", b"a" * 40, b"nested/.GITIGNORE")

    with pytest.raises(VerificationError, match="only the staged root"):
        verify_artifacts._trusted_root_ignore(clean_repository, (nested,))


def test_ignore_policy_materialization_failure_is_redacted(
    clean_repository: Path,
) -> None:
    entries = verify_artifacts._parse_index_entries(
        verify_artifacts._git_bytes(clean_repository, "ls-files", "--stage", "-z")
    )
    with (
        patch("scripts.verify_artifacts.Path.write_bytes", side_effect=OSError("private path")),
        pytest.raises(VerificationError, match="materialize the staged ignore policy") as raised,
    ):
        verify_artifacts._require_clean_worktree(clean_repository, entries)

    assert "private path" not in str(raised.value)


def test_verifier_reruns_quality_without_ignored_live_pytest_plugins(
    clean_repository: Path,
) -> None:
    (clean_repository / ".gitignore").write_text(
        "dist/\n*.log\n__pycache__/\n.pytest_cache/\n",
        encoding="utf-8",
    )
    (clean_repository / "pyproject.toml").write_text(
        """\
[tool.ruff.lint]
select = ["E", "F"]

[tool.mypy]
strict = true
files = ["tests"]

[tool.pytest.ini_options]
testpaths = ["tests"]
""",
        encoding="utf-8",
    )
    tests = clean_repository / "tests"
    tests.mkdir()
    (tests / "test_staged.py").write_text(
        "def test_staged_failure() -> None:\n    assert False\n",
        encoding="utf-8",
    )
    _git(clean_repository, "add", ".gitignore", "pyproject.toml", "tests/test_staged.py")
    injected = tests / "injected.log"
    injected.mkdir()
    (injected / "conftest.py").write_text(
        "def pytest_sessionfinish(session):\n    session.exitstatus = 0\n",
        encoding="utf-8",
    )
    (injected / "test_injected.py").write_text(
        "def test_injected():\n    assert True\n",
        encoding="utf-8",
    )
    live = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=clean_repository,
        check=False,
        capture_output=True,
        text=True,
    )
    assert live.returncode == 0

    with (
        patch("scripts.verify_artifacts.build_staged_snapshot") as build,
        pytest.raises(VerificationError, match=r"python\d* failed"),
    ):
        verify_artifacts.verify(clean_repository)

    build.assert_not_called()


@pytest.mark.parametrize("drift", ["content", "untracked"])
def test_final_guard_rejects_worktree_drift_and_nonignored_untracked_paths(
    clean_repository: Path,
    tmp_path: Path,
    drift: str,
) -> None:
    tree = materialize_staged_index(clean_repository, tmp_path / "snapshot")
    if drift == "content":
        (clean_repository / "tracked.txt").write_text("late injection\n", encoding="utf-8")
    else:
        (clean_repository / "late-injection.txt").touch()

    with pytest.raises(VerificationError, match=r"worktree|untracked"):
        finish_staged_index(clean_repository, tree)


def test_final_guard_rejects_a_late_untracked_ignore_file_that_hides_its_directory(
    clean_repository: Path,
    tmp_path: Path,
) -> None:
    tree = materialize_staged_index(clean_repository, tmp_path / "snapshot")
    _write_self_hiding_untracked_test(clean_repository)
    assert not verify_artifacts._git_bytes(
        clean_repository,
        "ls-files",
        "--others",
        "--exclude-per-directory=.gitignore",
        "-z",
    )

    with pytest.raises(VerificationError, match="nonignored untracked"):
        finish_staged_index(clean_repository, tree)


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_final_guard_rejects_late_index_visibility_flags(
    clean_repository: Path,
    tmp_path: Path,
    flag: str,
) -> None:
    tree = materialize_staged_index(clean_repository, tmp_path / "snapshot")
    _git(clean_repository, "update-index", flag, "tracked.txt")

    with pytest.raises(VerificationError, match="index flags"):
        finish_staged_index(clean_repository, tree)


def test_final_guard_rejects_an_index_tree_change(clean_repository: Path, tmp_path: Path) -> None:
    original_tree = materialize_staged_index(clean_repository, tmp_path / "snapshot")
    (clean_repository / "tracked.txt").write_text("replacement\n", encoding="utf-8")
    _git(clean_repository, "add", "tracked.txt")

    with pytest.raises(VerificationError, match="index tree changed"):
        finish_staged_index(clean_repository, original_tree)


def test_materializer_requires_the_repository_root(clean_repository: Path, tmp_path: Path) -> None:
    child = clean_repository / "child"
    child.mkdir()

    with pytest.raises(VerificationError, match="repository root"):
        materialize_staged_index(child, tmp_path / "snapshot")


def test_index_identity_must_be_a_git_object_id(clean_repository: Path, tmp_path: Path) -> None:
    with (
        patch("scripts.verify_artifacts._require_repository_root"),
        patch("scripts.verify_artifacts._reject_attribute_controls"),
        patch("scripts.verify_artifacts._git") as git,
        pytest.raises(VerificationError, match="invalid object identity"),
    ):
        git.return_value = subprocess.CompletedProcess([], 0, "not-an-object\n", "")
        materialize_staged_index(clean_repository, tmp_path / "snapshot")


@pytest.mark.parametrize("mode", ["120000", "160000"])
def test_materializer_rejects_symlinks_and_special_modes(
    clean_repository: Path,
    tmp_path: Path,
    mode: str,
) -> None:
    unsafe = clean_repository / "unsafe-entry"
    if mode == "120000":
        unsafe.symlink_to("tracked.txt")
        _git(clean_repository, "add", "unsafe-entry")
    else:
        unsafe.mkdir()
        _git(unsafe, "init", "--quiet")
        (unsafe / "tracked").touch()
        _git(unsafe, "add", "tracked")
        _git(
            unsafe,
            "-c",
            "user.name=Artifact Test",
            "-c",
            "user.email=artifact@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        )
        object_id = _git(unsafe, "rev-parse", "HEAD").stdout.strip()
        _git(
            clean_repository,
            "update-index",
            "--add",
            "--cacheinfo",
            f"{mode},{object_id},unsafe-entry",
        )

    with pytest.raises(VerificationError, match="regular files"):
        materialize_staged_index(clean_repository, tmp_path / "snapshot")


@pytest.mark.parametrize(
    "location",
    [
        "repository",
        "repository-case",
        "repository-config",
        "info",
        "global",
        "global-config",
        "xdg",
    ],
)
def test_materializer_rejects_git_attribute_controls(
    clean_repository: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    if location == "repository":
        (clean_repository / ".gitattributes").write_text("* export-ignore\n", encoding="utf-8")
        _git(clean_repository, "add", ".gitattributes")
    elif location == "repository-case":
        (clean_repository / ".GITATTRIBUTES").write_text("* export-ignore\n", encoding="utf-8")
        _git(clean_repository, "add", ".GITATTRIBUTES")
    elif location == "repository-config":
        _git(clean_repository, "config", "--local", "core.attributesFile", "attributes")
    elif location == "info":
        (clean_repository / ".git/info/attributes").write_text(
            "* filter=injected\n", encoding="utf-8"
        )
    elif location == "global":
        home = tmp_path / "home"
        attributes = home / ".config/git/attributes"
        attributes.parent.mkdir(parents=True)
        attributes.write_text("* filter=injected\n", encoding="utf-8")
        monkeypatch.setenv("HOME", str(home))
    elif location == "global-config":
        home = tmp_path / "home"
        home.mkdir()
        (home / ".gitconfig").write_text(
            "[core]\n\tattributesFile = /configured/elsewhere\n", encoding="utf-8"
        )
        monkeypatch.setenv("HOME", str(home))
    else:
        xdg = tmp_path / "xdg"
        attributes = xdg / "git/attributes"
        attributes.parent.mkdir(parents=True)
        attributes.write_text("* filter=injected\n", encoding="utf-8")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))

    with pytest.raises(VerificationError, match="Git attributes"):
        materialize_staged_index(clean_repository, tmp_path / "snapshot")


def test_materializer_ignores_alternate_index_and_config_environment(
    clean_repository: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = _git(clean_repository, "write-tree").stdout.strip()
    alternate_index = tmp_path / "alternate-index"
    alternate_environment = {
        **verify_artifacts._git_environment(),
        "GIT_INDEX_FILE": str(alternate_index),
    }
    verify_artifacts.run(
        [shutil.which("git") or "git", "read-tree", "--empty"],
        cwd=clean_repository,
        env=alternate_environment,
    )
    injected_config = tmp_path / "injected.gitconfig"
    injected_config.write_text(
        "[core]\n\tattributesFile = /definitely/not/trusted\n", encoding="utf-8"
    )
    monkeypatch.setenv("GIT_INDEX_FILE", str(alternate_index))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(injected_config))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.attributesFile")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/also/not/trusted")
    snapshot = tmp_path / "snapshot"

    captured = materialize_staged_index(clean_repository, snapshot)

    assert captured == tree
    assert (snapshot / "tracked.txt").read_text(encoding="utf-8") == "original\n"


def test_git_environment_removes_every_ambient_git_control(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostile = {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/hostile/objects",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_GLOBAL": "/hostile/config",
        "GIT_CONFIG_KEY_0": "core.attributesFile",
        "GIT_CONFIG_VALUE_0": "/hostile/attributes",
        "GIT_DIR": "/hostile/repository",
        "GIT_INDEX_FILE": "/hostile/index",
        "GIT_OBJECT_DIRECTORY": "/hostile/object-directory",
        "GIT_WORK_TREE": "/hostile/worktree",
    }
    for name, value in hostile.items():
        monkeypatch.setenv(name, value)
    private_index = tmp_path / "private-index"

    environment = verify_artifacts._git_environment(index_file=private_index)

    assert all(environment.get(name) != value for name, value in hostile.items())
    assert environment["GIT_INDEX_FILE"] == str(private_index)
    assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"


def test_materializer_is_independent_of_the_process_cwd(
    clean_repository: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)
    snapshot = tmp_path / "snapshot"

    materialize_staged_index(clean_repository, snapshot)

    assert Path.cwd() == unrelated
    assert (snapshot / "build-constraints.txt").is_file()


@pytest.mark.parametrize("existing", ["directory", "symlink"])
def test_materializer_requires_a_new_isolated_destination(
    clean_repository: Path,
    tmp_path: Path,
    existing: str,
) -> None:
    destination = tmp_path / "snapshot"
    if existing == "directory":
        destination.mkdir()
    else:
        destination.symlink_to(tmp_path / "missing-target", target_is_directory=True)

    with pytest.raises(VerificationError, match="isolated staged build root"):
        materialize_staged_index(clean_repository, destination)


@pytest.mark.parametrize(
    ("parser", "output", "message"),
    [
        (verify_artifacts._parse_index_entries, b"100644 bad 1\tpath\0", "stage-zero"),
        (verify_artifacts._parse_tree_entries, b"not-a-tree-entry\0", "Git tree"),
    ],
)
def test_git_entry_parsers_fail_closed_on_malformed_plumbing(
    parser: object,
    output: bytes,
    message: str,
) -> None:
    assert callable(parser)
    with pytest.raises(VerificationError, match=message):
        parser(output)


@pytest.mark.parametrize(
    "failure",
    [
        subprocess.CalledProcessError(9, ["git", "ls-tree"]),
        OSError("private local path"),
    ],
)
def test_binary_git_failures_are_redacted(
    clean_repository: Path,
    failure: subprocess.CalledProcessError | OSError,
) -> None:
    with (
        patch("scripts.verify_artifacts.subprocess.run", side_effect=failure),
        pytest.raises(VerificationError, match=r"git failed|tool git") as raised,
    ):
        verify_artifacts._git_bytes(clean_repository, "ls-tree")

    assert "private local path" not in str(raised.value)


def test_materialized_file_set_must_exactly_match_the_tree(tmp_path: Path) -> None:
    destination = tmp_path / "snapshot"
    destination.mkdir()
    (destination / "unexpected").touch()

    with pytest.raises(VerificationError, match="exactly match"):
        verify_artifacts._verify_materialized_files(destination, ())


def test_materialized_file_modes_must_exactly_match_the_tree(tmp_path: Path) -> None:
    destination = tmp_path / "snapshot"
    destination.mkdir()
    materialized = destination / "script"
    materialized.touch(mode=0o644)
    entry = verify_artifacts.IndexEntry(b"100755", b"a" * 40, b"script")

    with pytest.raises(VerificationError, match="exactly match"):
        verify_artifacts._verify_materialized_files(destination, (entry,))


def _write_expected_artifacts(directory: Path) -> None:
    directory.mkdir()
    for release in EXPECTED_RELEASES:
        (directory / release.wheel_filename).touch()
        (directory / release.sdist_filename).touch()


def test_collect_artifacts_requires_the_exact_release_set(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _write_expected_artifacts(dist)

    artifacts = collect_artifacts(dist)

    assert set(artifacts) == {release.name for release in EXPECTED_RELEASES}
    assert artifacts["cairnvm-runtime"].wheel.name == ("cairnvm_runtime-0.1.0-py3-none-any.whl")


def test_collect_artifacts_reports_an_unavailable_directory(tmp_path: Path) -> None:
    with pytest.raises(VerificationError, match="dist directory is unavailable"):
        collect_artifacts(tmp_path / "missing")


def test_collect_artifacts_rejects_an_inconsistent_release_declaration(tmp_path: Path) -> None:
    release = Release(
        "cairnvm-runtime",
        "9.9.9",
        "cairnvm",
        "cairnvm_runtime-0.1.0-py3-none-any.whl",
        "cairnvm_runtime-0.1.0.tar.gz",
        "cairnvm=cairnvm.cli:main",
    )
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / release.wheel_filename).touch()
    (dist / release.sdist_filename).touch()

    with (
        patch.object(verify_artifacts, "EXPECTED_RELEASES", (release,)),
        pytest.raises(VerificationError, match="invalid expected artifact declaration"),
    ):
        collect_artifacts(dist)


@pytest.mark.parametrize("mutation", ["missing", "extra", "directory"])
def test_collect_artifacts_rejects_any_nonexact_set(tmp_path: Path, mutation: str) -> None:
    dist = tmp_path / "dist"
    _write_expected_artifacts(dist)
    if mutation == "missing":
        (dist / EXPECTED_RELEASES[0].wheel_filename).unlink()
    elif mutation == "extra":
        (dist / "unexpected.txt").touch()
    else:
        wheel = dist / EXPECTED_RELEASES[0].wheel_filename
        wheel.unlink()
        wheel.mkdir()

    with pytest.raises(VerificationError, match=r"exactly|regular file"):
        collect_artifacts(dist)


def test_rebuild_uses_the_committed_hash_constrained_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = EXPECTED_RELEASES[0]
    sdist = tmp_path / release.sdist_filename
    sdist.touch()
    output = tmp_path / "rebuilt"
    monkeypatch.setenv("UV_NO_BUILD_ISOLATION", "1")
    monkeypatch.setenv("UV_BUILD_CONSTRAINT", "/hostile/constraints")
    monkeypatch.setenv("PIP_CONFIG_FILE", "/hostile/pip.conf")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        output.mkdir(exist_ok=True)
        (output / release.wheel_filename).touch()
        assert "--no-config" in command
        assert "--build-constraints" in command
        assert command[command.index("--build-constraints") + 1] == str(BUILD_CONSTRAINTS)
        assert "--require-hashes" in command
        assert "--no-build-isolation" not in command
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        assert all(not name.startswith(("UV_", "PIP_")) for name in environment)
        return subprocess.CompletedProcess(command, 0, "", "")

    with patch("scripts.verify_artifacts.run", side_effect=fake_run):
        rebuilt = rebuild_wheel(
            release,
            sdist,
            output,
            constraints=BUILD_CONSTRAINTS,
        )

    assert rebuilt == output / release.wheel_filename


def test_rebuild_rejects_an_unexpected_wheel(tmp_path: Path) -> None:
    release = EXPECTED_RELEASES[0]
    sdist = tmp_path / release.sdist_filename
    sdist.touch()
    output = tmp_path / "rebuilt"

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        output.mkdir(exist_ok=True)
        (output / "wrong-1.0-py3-none-any.whl").touch()
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch("scripts.verify_artifacts.run", side_effect=fake_run),
        pytest.raises(VerificationError, match="rebuilt wheel"),
    ):
        rebuild_wheel(release, sdist, output, constraints=BUILD_CONSTRAINTS)


def test_staged_snapshot_build_uses_the_exact_hashed_constraints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "dist/.gitignore"
    marker.parent.mkdir()
    marker.touch()
    monkeypatch.setenv("UV_NO_BUILD_ISOLATION", "1")
    monkeypatch.setenv("UV_BUILD_CONSTRAINT", "/hostile/constraints")
    monkeypatch.setenv("PIP_CONFIG_FILE", "/hostile/pip.conf")
    monkeypatch.setenv("PYTHONPATH", "/hostile/python")

    with patch("scripts.verify_artifacts.run") as run:
        verify_artifacts.build_staged_snapshot(tmp_path, constraints=BUILD_CONSTRAINTS)

    command = run.call_args.args[0]
    assert command[1:] == [
        "build",
        "--no-config",
        "--all-packages",
        "--clear",
        "--build-constraints",
        str(BUILD_CONSTRAINTS),
        "--require-hashes",
    ]
    environment = run.call_args.kwargs["env"]
    assert environment is not None
    assert all(not name.startswith(("UV_", "PIP_")) for name in environment)
    assert "PYTHONPATH" not in environment
    assert not marker.exists()


def test_staged_quality_uses_isolated_tools_and_controlled_snapshot_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "quality"
    root.mkdir()
    monkeypatch.setenv("PYTHONPATH", "/hostile/python")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    monkeypatch.setenv("MYPY_CONFIG_FILE", "/hostile/mypy.ini")
    monkeypatch.setenv("RUFF_OUTPUT_FORMAT", "json")

    with patch("scripts.verify_artifacts.run") as run:
        verify_artifacts.verify_staged_quality(root)

    assert run.call_count == 4
    commands = [call.args[0] for call in run.call_args_list]
    assert commands[:3] == [
        [sys.executable, "-I", "-m", "ruff", "check", "."],
        [sys.executable, "-I", "-m", "ruff", "format", "--check", "."],
        [sys.executable, "-I", "-m", "mypy"],
    ]
    assert commands[3][:3] == [sys.executable, "-I", "-c"]
    assert commands[3][-1] == str(root)
    for call in run.call_args_list:
        assert call.kwargs["cwd"] == root
        environment = call.kwargs["env"]
        assert environment["PYTHONPATH"] == os.pathsep.join(
            (str(root), str(root / "src"), str(root / "packages/launcher/src"))
        )
        assert "PYTEST_ADDOPTS" not in environment
        assert "MYPY_CONFIG_FILE" not in environment
        assert "RUFF_OUTPUT_FORMAT" not in environment


def test_hostile_no_isolation_cannot_bypass_a_false_backend_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    package = project / "src/example"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('__version__ = "0.1.0"\n', encoding="utf-8")
    (project / "pyproject.toml").write_text(
        """\
[build-system]
requires = ["hatchling==1.32.0"]
build-backend = "hatchling.build"

[project]
name = "artifact-gate-hash-probe"
version = "0.1.0"
""",
        encoding="utf-8",
    )
    constraints = project / "false-constraints.txt"
    constraints.write_text(
        "hatchling==1.32.0 --hash=sha256:" + ("0" * 64) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("UV_NO_BUILD_ISOLATION", "1")

    with pytest.raises(VerificationError, match="uv failed"):
        verify_artifacts.build_staged_snapshot(project, constraints=constraints)


def test_smoke_test_uses_a_fresh_isolated_dependency_free_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = EXPECTED_RELEASES[1]
    wheel = tmp_path / release.wheel_filename
    wheel.touch()
    monkeypatch.setenv("UV_NO_BUILD_ISOLATION", "1")
    monkeypatch.setenv("PIP_CONFIG_FILE", "/hostile/pip.conf")
    monkeypatch.setenv("PYTHONPATH", "/hostile/python")
    calls: list[tuple[list[str], dict[str, str] | None]] = []

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        calls.append((command, env))
        return subprocess.CompletedProcess(command, 0, "", "")

    with patch("scripts.verify_artifacts.run", side_effect=fake_run):
        smoke_test_wheel(wheel, release)

    assert len(calls) == 3
    assert "--no-config" in calls[0][0]
    install = calls[1][0]
    assert "--no-config" in install
    assert "--no-deps" in install
    assert "--no-index" in install
    assert str(wheel) == install[-1]
    isolated = calls[2][0]
    assert isolated[1:3] == ["-I", "-c"]
    assert release.console_script is None
    for _, environment in calls:
        assert environment is not None
        assert "PYTHONPATH" not in environment
        assert "PYTHONHOME" not in environment
        assert environment["PYTHONNOUSERSITE"] == "1"
        assert set(environment) <= {
            "HOME",
            "LANG",
            "LC_ALL",
            "PATH",
            "PYTHONDONTWRITEBYTECODE",
            "PYTHONNOUSERSITE",
            "SYSTEMROOT",
            "TMPDIR",
            "UV_CACHE_DIR",
            "WINDIR",
        }


@pytest.mark.parametrize("valid_output", [True, False])
def test_runtime_smoke_exercises_the_isolated_cli(tmp_path: Path, valid_output: bool) -> None:
    release = EXPECTED_RELEASES[0]
    wheel = tmp_path / release.wheel_filename
    wheel.touch()

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        output = "cairnvm 0.1.0\n" if valid_output and "--version" in command else ""
        return subprocess.CompletedProcess(command, 0, output, "")

    with patch("scripts.verify_artifacts.run", side_effect=fake_run):
        if valid_output:
            smoke_test_wheel(wheel, release)
        else:
            with pytest.raises(VerificationError, match="unexpected version output"):
                smoke_test_wheel(wheel, release)


def test_verify_checks_separate_materialized_quality_and_build_snapshots(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    releases = (
        Release("runtime", "0.1.0", "runtime", "runtime.whl", "runtime.tar.gz", "run"),
        Release("launcher", "0.1.0", "launcher", "launcher.whl", "launcher.tar.gz", None),
    )
    materialized_roots: list[Path] = []

    def materialize(root: Path, destination: Path) -> str:
        assert root == source
        destination.mkdir()
        (destination / "build-constraints.txt").touch()
        materialized_roots.append(destination)
        return "a" * 40

    def collect(directory: Path) -> dict[str, verify_artifacts.Artifacts]:
        assert directory == materialized_roots[1] / "dist"
        return {
            release.name: verify_artifacts.Artifacts(
                directory / release.wheel_filename,
                directory / release.sdist_filename,
            )
            for release in releases
        }

    def rebuild(
        release: Release,
        _sdist: Path,
        output: Path,
        *,
        constraints: Path,
    ) -> Path:
        assert output.parent.parent == materialized_roots[1].parent
        assert constraints == materialized_roots[1] / "build-constraints.txt"
        return output / release.wheel_filename

    def quality(root: Path) -> None:
        assert root == materialized_roots[0]
        (root / ".pytest_cache").mkdir()

    def build_snapshot(root: Path, *, constraints: Path) -> None:
        assert root == materialized_roots[1]
        assert constraints == root / "build-constraints.txt"
        assert not (root / ".pytest_cache").exists()

    with (
        patch.object(verify_artifacts, "EXPECTED_RELEASES", releases),
        patch("scripts.verify_artifacts.materialize_staged_index", side_effect=materialize),
        patch(
            "scripts.verify_artifacts.verify_staged_quality", side_effect=quality
        ) as quality_mock,
        patch(
            "scripts.verify_artifacts.build_staged_snapshot", side_effect=build_snapshot
        ) as build,
        patch("scripts.verify_artifacts.collect_artifacts", side_effect=collect),
        patch("scripts.verify_artifacts.check_wheel") as check_wheel,
        patch("scripts.verify_artifacts.rebuild_wheel", side_effect=rebuild) as rebuild_mock,
        patch("scripts.verify_artifacts.smoke_test_wheel") as smoke,
        patch("scripts.verify_artifacts.finish_staged_index") as finish,
    ):
        verify_artifacts.verify(source)

    assert check_wheel.call_count == 4
    quality_mock.assert_called_once_with(materialized_roots[0])
    build.assert_called_once_with(
        materialized_roots[1],
        constraints=materialized_roots[1] / "build-constraints.txt",
    )
    assert rebuild_mock.call_count == 2
    assert smoke.call_count == 4
    finish.assert_called_once_with(source.resolve(), "a" * 40)
    assert len(materialized_roots) == 2
    assert all(not root.exists() for root in materialized_roots)


def test_verify_rejects_quality_and_build_snapshots_from_different_trees(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()

    with (
        patch(
            "scripts.verify_artifacts.materialize_staged_index",
            side_effect=("a" * 40, "b" * 40),
        ),
        patch("scripts.verify_artifacts.verify_staged_quality") as quality,
        patch("scripts.verify_artifacts.finish_staged_index") as finish,
        pytest.raises(VerificationError, match="do not share one staged tree"),
    ):
        verify_artifacts.verify(source)

    quality.assert_called_once()
    finish.assert_called_once_with(source.resolve(), "a" * 40)


def test_quality_cannot_tamper_with_a_pre_materialized_build_sibling(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()

    def materialize(_root: Path, destination: Path) -> str:
        try:
            destination.mkdir()
        except FileExistsError as error:
            raise VerificationError("could not create the isolated staged build root") from error
        (destination / "sentinel").write_text("exact\n", encoding="utf-8")
        return "a" * 40

    def hostile_quality(root: Path) -> None:
        sibling = root.parent / "build-workspace"
        sibling.mkdir(exist_ok=True)
        (sibling / "sentinel").write_text("tampered\n", encoding="utf-8")

    with (
        patch("scripts.verify_artifacts.materialize_staged_index", side_effect=materialize),
        patch("scripts.verify_artifacts.verify_staged_quality", side_effect=hostile_quality),
        patch("scripts.verify_artifacts.build_staged_snapshot") as build,
        patch("scripts.verify_artifacts.finish_staged_index"),
        pytest.raises(VerificationError, match="isolated staged build root"),
    ):
        verify_artifacts.verify(source)

    build.assert_not_called()


def test_main_reports_verification_failures_without_a_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with patch("scripts.verify_artifacts.verify", side_effect=VerificationError("not clean")):
        result = verify_artifacts.main()

    assert result == 1
    assert capsys.readouterr().err == "artifact verification failed: not clean\n"


def test_main_reports_success(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("scripts.verify_artifacts.verify"):
        result = verify_artifacts.main()

    assert result == 0
    assert capsys.readouterr().out == "verified exact runtime and launcher wheels and sdists\n"


def test_tool_failure_is_redacted_to_the_tool_and_exit_status(tmp_path: Path) -> None:
    failure = subprocess.CalledProcessError(
        7,
        ["tool", "--secret", "sensitive"],
        stderr="sensitive output",
    )
    with (
        patch("scripts.verify_artifacts.subprocess.run", Mock(side_effect=failure)),
        pytest.raises(VerificationError, match="tool failed with exit status 7") as raised,
    ):
        verify_artifacts.run(["tool", "--secret", "sensitive"], cwd=tmp_path)

    assert "sensitive" not in str(raised.value)


def test_missing_tool_execution_is_reported_without_os_details(tmp_path: Path) -> None:
    with (
        patch("scripts.verify_artifacts.subprocess.run", Mock(side_effect=OSError("private path"))),
        pytest.raises(VerificationError, match="could not execute required tool tool") as raised,
    ):
        verify_artifacts.run(["tool"], cwd=tmp_path)

    assert "private path" not in str(raised.value)


def test_check_wheel_uses_the_standard_checker(tmp_path: Path) -> None:
    wheel = tmp_path / EXPECTED_RELEASES[0].wheel_filename
    with patch("scripts.verify_artifacts.run") as run:
        verify_artifacts.check_wheel(wheel, EXPECTED_RELEASES[0])

    command = run.call_args.args[0]
    assert Path(command[0]).name == "check-wheel-contents"
    assert command[1:] == ["--no-config", "--toplevel", "cairnvm", str(wheel)]


def test_missing_required_tool_fails_closed() -> None:
    with (
        patch("scripts.verify_artifacts.shutil.which", return_value=None),
        pytest.raises(VerificationError, match="required tool is unavailable"),
    ):
        verify_artifacts._tool("missing")
