#!/usr/bin/env python3
"""Verify Phase 0 release artifacts in an authorized developer and CI checkout.

This is an ordinary release gate, not an attacker-resistant sandbox. It assumes
the local Git executable, object storage, index, Python interpreter, and packaging
tools are trusted. It does not defend against malicious local Git object storage
or concurrent hostile processes.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
BUILD_CONSTRAINTS = ROOT / "build-constraints.txt"


class VerificationError(RuntimeError):
    """A release-gate check failed."""


@dataclass(frozen=True)
class Release:
    """Expected identity and behavior for one workspace distribution."""

    name: str
    version: str
    import_name: str
    wheel_filename: str
    sdist_filename: str
    console_script: str | None
    summary: str = ""


@dataclass(frozen=True)
class Artifacts:
    """The wheel and source distribution for one release."""

    wheel: Path
    sdist: Path


@dataclass(frozen=True)
class IndexEntry:
    """One canonical stage-zero file entry."""

    mode: bytes
    object_id: bytes
    path: bytes


EXPECTED_RELEASES = (
    Release(
        "cairnvm-runtime",
        "0.1.0",
        "cairnvm",
        "cairnvm_runtime-0.1.0-py3-none-any.whl",
        "cairnvm_runtime-0.1.0.tar.gz",
        "cairnvm=cairnvm.cli:main",
        "Runtime foundation for the CairnVM persistent virtual disk",
    ),
    Release(
        "cairnvm-launcher",
        "0.1.0",
        "cairnvm_launcher",
        "cairnvm_launcher-0.1.0-py3-none-any.whl",
        "cairnvm_launcher-0.1.0.tar.gz",
        None,
        "Independent trusted launcher boundary for CairnVM",
    ),
)


def run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a release tool without copying possibly sensitive output into failures."""

    try:
        return subprocess.run(  # noqa: S603 - commands are assembled from release-gate constants
            command,
            cwd=cwd,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        tool = Path(command[0]).name
        raise VerificationError(f"{tool} failed with exit status {error.returncode}") from error
    except OSError as error:
        tool = Path(command[0]).name
        raise VerificationError(f"could not execute required tool {tool}") from error


def _git_environment(*, index_file: Path | None = None) -> dict[str, str]:
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    if index_file is not None:
        environment["GIT_INDEX_FILE"] = str(index_file)
    return environment


def _git_command(*arguments: str) -> list[str]:
    return [
        _tool("git"),
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.eol=lf",
        "-c",
        "core.fileMode=true",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.sparseCheckout=false",
        *arguments,
    ]


def _git(
    root: Path,
    *arguments: str,
    index_file: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return run(
        _git_command(*arguments),
        cwd=root,
        env=_git_environment(index_file=index_file),
    )


def _redacted_git_failure(error: subprocess.CalledProcessError | OSError) -> VerificationError:
    if isinstance(error, subprocess.CalledProcessError):
        return VerificationError(f"git failed with exit status {error.returncode}")
    return VerificationError("could not execute required tool git")


def _git_bytes(
    root: Path,
    *arguments: str,
    index_file: Path | None = None,
) -> bytes:
    try:
        return subprocess.run(  # noqa: S603 - fixed Git plumbing with test-owned paths
            _git_command(*arguments),
            cwd=root,
            env=_git_environment(index_file=index_file),
            check=True,
            capture_output=True,
        ).stdout
    except (subprocess.CalledProcessError, OSError) as error:
        raise _redacted_git_failure(error) from error


def _require_repository_root(root: Path) -> None:
    top_level = Path(_git(root, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    if top_level != root:
        raise VerificationError("release gate must run at the repository root")

    _git(root, "ls-files", "--error-unmatch", "--", "build-constraints.txt")


def _index_tree(root: Path) -> str:
    tree = _git(root, "write-tree").stdout.strip()
    if len(tree) not in (40, 64) or any(character not in "0123456789abcdef" for character in tree):
        raise VerificationError("git write-tree returned an invalid object identity")
    return tree


def _parse_index_entries(output: bytes) -> tuple[IndexEntry, ...]:
    entries: list[IndexEntry] = []
    try:
        for record in output.split(b"\0"):
            if not record:
                continue
            metadata, path = record.split(b"\t", maxsplit=1)
            mode, object_id, stage = metadata.split(b" ")
            if stage != b"0" or not path:
                raise ValueError
            entries.append(IndexEntry(mode, object_id, path))
    except ValueError as error:
        raise VerificationError("Git index returned malformed or non-stage-zero entries") from error
    return tuple(entries)


def _parse_flagged_index_entries(output: bytes) -> tuple[IndexEntry, ...]:
    records: list[bytes] = []
    try:
        for record in output.split(b"\0"):
            if not record:
                continue
            flag, entry = record.split(b" ", maxsplit=1)
            if flag != b"H":
                raise VerificationError(
                    "assume-unchanged and skip-worktree index flags are forbidden"
                )
            records.append(entry)
    except ValueError as error:
        raise VerificationError("Git index returned malformed index flags") from error
    return _parse_index_entries(b"\0".join(records) + (b"\0" if records else b""))


def _parse_tree_entries(output: bytes) -> tuple[IndexEntry, ...]:
    entries: list[IndexEntry] = []
    try:
        for record in output.split(b"\0"):
            if not record:
                continue
            metadata, path = record.split(b"\t", maxsplit=1)
            mode, object_type, object_id = metadata.split(b" ")
            if object_type != b"blob" or not path:
                raise ValueError
            entries.append(IndexEntry(mode, object_id, path))
    except ValueError as error:
        raise VerificationError("Git tree returned malformed entries") from error
    return tuple(entries)


def _path_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise VerificationError("could not inspect Git attribute controls") from error
    return True


def _configured_global_attributes() -> bool:
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    try:
        result = subprocess.run(  # noqa: S603 - fixed read-only Git config query
            [_tool("git"), "config", "--global", "--get-all", "core.attributesFile"],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise _redacted_git_failure(error) from error
    if result.returncode not in (0, 1):
        raise VerificationError("git could not inspect global Git attributes")
    return result.returncode == 0


def _global_attribute_paths() -> tuple[Path, ...]:
    paths: list[Path] = []
    home = os.environ.get("HOME")
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        paths.append(Path(xdg_config_home) / "git/attributes")
    if home:
        paths.extend(
            (
                Path(home) / ".config/git/attributes",
                Path(home) / ".gitattributes",
            )
        )
    return tuple(paths)


def _repository_attribute_configured(root: Path) -> bool:
    try:
        result = subprocess.run(  # noqa: S603 - fixed read-only Git config query
            _git_command("config", "--local", "--get-all", "core.attributesFile"),
            cwd=root,
            env=_git_environment(),
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise _redacted_git_failure(error) from error
    if result.returncode not in (0, 1):
        raise VerificationError("git could not inspect repository Git attributes")
    return result.returncode == 0


def _reject_attribute_controls(root: Path, entries: tuple[IndexEntry, ...]) -> None:
    if any(
        any(component.lower() == b".gitattributes" for component in entry.path.split(b"/"))
        for entry in entries
    ):
        raise VerificationError("staged Git attributes are not allowed")

    info_attributes_output = _git(
        root,
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "info/attributes",
    ).stdout.strip()
    if not info_attributes_output:
        raise VerificationError("git returned an invalid Git attributes path")
    if _path_exists(Path(info_attributes_output)):
        raise VerificationError("repository info Git attributes are not allowed")
    if _repository_attribute_configured(root):
        raise VerificationError("repository Git attributes configuration is not allowed")
    if _configured_global_attributes() or any(
        _path_exists(path) for path in _global_attribute_paths()
    ):
        raise VerificationError("global Git attributes are not allowed")


def _validate_entries(entries: tuple[IndexEntry, ...]) -> None:
    if any(entry.mode not in (b"100644", b"100755") for entry in entries):
        raise VerificationError("staged tree must contain only regular files")
    if any(
        len(entry.object_id) not in (40, 64)
        or any(character not in b"0123456789abcdef" for character in entry.object_id)
        for entry in entries
    ):
        raise VerificationError("staged tree contains an invalid blob identity")
    paths = [entry.path for entry in entries]
    if len(paths) != len(set(paths)) or any(
        path.startswith(b"/")
        or any(component in (b"", b".", b"..") for component in path.split(b"/"))
        for path in paths
    ):
        raise VerificationError("staged tree contains an invalid path")


def _require_exact_worktree(root: Path, entries: tuple[IndexEntry, ...]) -> None:
    """Compare tracked files directly with index blobs, bypassing Git's stat cache."""

    for entry in entries:
        path = root / os.fsdecode(entry.path)
        try:
            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode):
                raise VerificationError("tracked worktree paths must be regular files")
            contents = path.read_bytes()
        except VerificationError:
            raise
        except OSError as error:
            raise VerificationError("could not read a tracked worktree file") from error
        if bool(stat.S_IMODE(mode) & 0o111) != (entry.mode == b"100755"):
            raise VerificationError("tracked worktree executable modes do not match the Git index")
        object_id = entry.object_id.decode("ascii")
        if contents != _git_bytes(root, "cat-file", "blob", object_id):
            raise VerificationError("tracked worktree bytes do not match the Git index")


def _trusted_root_ignore(root: Path, entries: tuple[IndexEntry, ...]) -> bytes:
    ignore_entries = tuple(
        entry
        for entry in entries
        if any(component.lower() == b".gitignore" for component in entry.path.split(b"/"))
    )
    if any(entry.path != b".gitignore" for entry in ignore_entries) or len(ignore_entries) > 1:
        raise VerificationError("only the staged root .gitignore may define release-gate ignores")
    if not ignore_entries:
        return b""
    return _git_bytes(root, "cat-file", "blob", ignore_entries[0].object_id.decode("ascii"))


def _require_clean_worktree(root: Path, entries: tuple[IndexEntry, ...]) -> None:
    _require_exact_worktree(root, entries)
    ignore_bytes = _trusted_root_ignore(root, entries)
    with tempfile.TemporaryDirectory(prefix="cairnvm-tracked-ignore-") as temporary:
        ignore_file = Path(temporary) / "root.gitignore"
        try:
            ignore_file.write_bytes(ignore_bytes)
        except OSError as error:
            raise VerificationError("could not materialize the staged ignore policy") from error
        if _git_bytes(root, "ls-files", "--others", f"--exclude-from={ignore_file}", "-z"):
            raise VerificationError("nonignored untracked paths are present")


def _captured_entries(root: Path) -> tuple[str, tuple[IndexEntry, ...]]:
    index_entries = _parse_flagged_index_entries(
        _git_bytes(root, "ls-files", "--stage", "-v", "-z")
    )
    _validate_entries(index_entries)
    tree = _index_tree(root)
    tree_entries = _parse_tree_entries(_git_bytes(root, "ls-tree", "-r", "-z", "--full-tree", tree))
    _validate_entries(tree_entries)
    if index_entries != tree_entries:
        raise VerificationError("Git index entries do not exactly match the captured tree")
    return tree, tree_entries


def _verify_materialized_files(destination: Path, entries: tuple[IndexEntry, ...]) -> None:
    expected = {entry.path: entry.mode == b"100755" for entry in entries}
    actual: dict[bytes, bool] = {}
    try:
        for path in destination.rglob("*"):
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode):
                raise VerificationError("materialized tree must contain only regular files")
            relative = os.fsencode(path.relative_to(destination).as_posix())
            actual[relative] = bool(stat.S_IMODE(mode) & 0o111)
    except OSError as error:
        raise VerificationError("could not inspect the materialized staged tree") from error
    if actual != expected:
        raise VerificationError("materialized files do not exactly match the staged tree")


def materialize_staged_index(root: Path, destination: Path) -> str:
    """Validate and materialize the canonical stage-zero index tree."""

    root = root.resolve()
    _require_repository_root(root)
    tree, tree_entries = _captured_entries(root)
    _reject_attribute_controls(root, tree_entries)
    _require_clean_worktree(root, tree_entries)

    try:
        destination.mkdir(parents=False, exist_ok=False)
    except OSError as error:
        raise VerificationError("could not create the isolated staged build root") from error

    with tempfile.TemporaryDirectory(
        prefix="cairnvm-private-index-", dir=destination.parent
    ) as temporary:
        private_index = Path(temporary) / "index"
        _git(root, "read-tree", tree, index_file=private_index)
        materialized_entries = _parse_index_entries(
            _git_bytes(root, "ls-files", "--stage", "-z", index_file=private_index)
        )
        if materialized_entries != tree_entries:
            raise VerificationError("private Git index does not exactly match the captured tree")
        _git(
            root,
            "checkout-index",
            "--all",
            "--force",
            f"--prefix={destination}{os.sep}",
            index_file=private_index,
        )
    _verify_materialized_files(destination, tree_entries)
    return tree


def finish_staged_index(root: Path, captured_tree: str) -> None:
    """Require an unchanged, still-supported staged index tree."""

    root = root.resolve()
    _require_repository_root(root)
    current_tree, current_entries = _captured_entries(root)
    _reject_attribute_controls(root, current_entries)
    _require_clean_worktree(root, current_entries)
    if current_tree != captured_tree:
        raise VerificationError("Git index tree changed during artifact verification")


def collect_artifacts(directory: Path) -> dict[str, Artifacts]:
    """Require exactly one wheel and sdist for each expected distribution."""

    expected = {
        filename
        for release in EXPECTED_RELEASES
        for filename in (release.wheel_filename, release.sdist_filename)
    }
    try:
        paths = {path.name: path for path in directory.iterdir()}
    except OSError as error:
        raise VerificationError("dist directory is unavailable") from error
    if set(paths) != expected:
        raise VerificationError(
            "dist must contain exactly the expected runtime and launcher artifacts"
        )
    if any(not stat.S_ISREG(path.lstat().st_mode) for path in paths.values()):
        raise VerificationError("every release artifact must be a regular file")

    artifacts: dict[str, Artifacts] = {}
    for release in EXPECTED_RELEASES:
        wheel_name, wheel_version, _build, wheel_tags = parse_wheel_filename(release.wheel_filename)
        sdist_name, sdist_version = parse_sdist_filename(release.sdist_filename)
        expected_name = canonicalize_name(release.name)
        if (
            wheel_name != expected_name
            or sdist_name != expected_name
            or str(wheel_version) != release.version
            or str(sdist_version) != release.version
            or {str(tag) for tag in wheel_tags} != {"py3-none-any"}
        ):
            raise VerificationError(f"invalid expected artifact declaration for {release.name}")
        artifacts[release.name] = Artifacts(
            paths[release.wheel_filename],
            paths[release.sdist_filename],
        )
    return artifacts


def _tool(name: str) -> str:
    executable = shutil.which(name)
    if executable is None:
        raise VerificationError(f"required tool is unavailable: {name}")
    return executable


def _tool_environment() -> dict[str, str]:
    """Return a small environment with no ambient package/build controls."""

    environment = {
        "HOME": os.environ.get("HOME", str(Path.home())),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    for name in ("SYSTEMROOT", "WINDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


QUALITY_PYTEST_PROGRAM = """
import sys
from pathlib import Path

import pytest

root = Path(sys.argv[1])
sys.path[:0] = [
    str(root),
    str(root / "src"),
    str(root / "packages" / "launcher" / "src"),
]
raise SystemExit(pytest.main([]))
"""


def _quality_environment(root: Path) -> dict[str, str]:
    environment = _tool_environment()
    tool_directories = (
        str(Path(sys.executable).parent),
        *(str(Path(_tool(name)).parent) for name in ("git", "uv", "check-wheel-contents")),
        *os.defpath.split(os.pathsep),
    )
    environment["PATH"] = os.pathsep.join(dict.fromkeys(tool_directories))
    environment["PYTHONPATH"] = os.pathsep.join(
        (
            str(root),
            str(root / "src"),
            str(root / "packages/launcher/src"),
        )
    )
    return environment


def verify_staged_quality(root: Path) -> None:
    """Run every authoritative quality tool against only the staged snapshot."""

    environment = _quality_environment(root)
    commands = (
        [sys.executable, "-I", "-m", "ruff", "check", "."],
        [sys.executable, "-I", "-m", "ruff", "format", "--check", "."],
        [sys.executable, "-I", "-m", "mypy"],
        [sys.executable, "-I", "-c", QUALITY_PYTEST_PROGRAM, str(root)],
    )
    for command in commands:
        run(command, cwd=root, env=environment)


def build_staged_snapshot(root: Path, *, constraints: Path) -> None:
    """Build both workspace distributions from the supplied staged snapshot."""

    run(
        [
            _tool("uv"),
            "build",
            "--no-config",
            "--all-packages",
            "--clear",
            "--build-constraints",
            str(constraints),
            "--require-hashes",
        ],
        cwd=root,
        env=_tool_environment(),
    )
    try:
        (root / "dist/.gitignore").unlink(missing_ok=True)
    except OSError as error:
        raise VerificationError("could not remove uv's nonartifact dist marker") from error


def check_wheel(wheel: Path, release: Release) -> None:
    """Validate wheel layout with the maintained packaging checker."""

    run(
        [
            _tool("check-wheel-contents"),
            "--no-config",
            "--toplevel",
            release.import_name,
            str(wheel),
        ],
        cwd=wheel.parent,
    )


def rebuild_wheel(
    release: Release,
    sdist: Path,
    output: Path,
    *,
    constraints: Path,
) -> Path:
    """Rebuild one wheel from its sdist with the release backend constraints."""

    output.mkdir(parents=True, exist_ok=False)
    run(
        [
            _tool("uv"),
            "build",
            "--no-config",
            "--wheel",
            "--clear",
            "--out-dir",
            str(output),
            "--build-constraints",
            str(constraints),
            "--require-hashes",
            str(sdist),
        ],
        cwd=Path(str(constraints)).parent,
        env=_tool_environment(),
    )
    wheels = list(output.glob("*.whl"))
    expected = output / release.wheel_filename
    if wheels != [expected]:
        raise VerificationError(f"sdist produced an unexpected rebuilt wheel for {release.name}")
    return expected


def _venv_python(environment: Path) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _venv_script(environment: Path, name: str) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / f"{name}.exe"
    return environment / "bin" / name


def _smoke_environment(root: Path) -> dict[str, str]:
    home = root / "home"
    cache = root / "uv-cache"
    home.mkdir()
    cache.mkdir()
    environment = _tool_environment()
    environment.update(
        {
            "HOME": str(home),
            "TMPDIR": str(root),
            "UV_CACHE_DIR": str(cache),
        }
    )
    return environment


SMOKE_PROGRAM = """
import importlib
import importlib.metadata
import importlib.util
import json
import sys

expected = json.loads(sys.argv[1])
distribution = importlib.metadata.distribution(expected["name"])
assert distribution.metadata["Name"] == expected["name"]
assert distribution.version == expected["version"]
assert distribution.metadata["Summary"] == expected["summary"]
assert distribution.metadata["Requires-Python"] == ">=3.11"
assert not distribution.requires
module = importlib.import_module(expected["import_name"])
assert module.__version__ == expected["version"]
other = "cairnvm" if expected["import_name"] == "cairnvm_launcher" else "cairnvm_launcher"
assert importlib.util.find_spec(other) is None
entry_points = sorted(
    f"{entry.group}:{entry.name}={entry.value}" for entry in distribution.entry_points
)
expected_entry_points = (
    [f"console_scripts:{expected['console_script']}"] if expected["console_script"] else []
)
assert entry_points == expected_entry_points
"""


def smoke_test_wheel(wheel: Path, release: Release) -> None:
    """Install one wheel alone and inspect it from a fresh isolated interpreter."""

    with tempfile.TemporaryDirectory(prefix="cairnvm-wheel-smoke-") as temporary:
        root = Path(temporary)
        environment = root / "venv"
        sanitized = _smoke_environment(root)
        run(
            [
                _tool("uv"),
                "venv",
                "--no-config",
                "--python",
                sys.executable,
                "--no-project",
                str(environment),
            ],
            cwd=root,
            env=sanitized,
        )
        python = _venv_python(environment)
        run(
            [
                _tool("uv"),
                "pip",
                "install",
                "--no-config",
                "--python",
                str(python),
                "--no-deps",
                "--no-index",
                str(wheel),
            ],
            cwd=root,
            env=sanitized,
        )
        expected = json.dumps(
            {
                "name": release.name,
                "version": release.version,
                "summary": release.summary,
                "import_name": release.import_name,
                "console_script": release.console_script,
            },
            sort_keys=True,
        )
        run([str(python), "-I", "-c", SMOKE_PROGRAM, expected], cwd=root, env=sanitized)
        if release.console_script is not None:
            script_name = release.console_script.split("=", maxsplit=1)[0]
            result = run(
                [str(_venv_script(environment, script_name)), "--version"],
                cwd=root,
                env=sanitized,
            )
            if result.stdout.strip() != f"cairnvm {release.version}":
                raise VerificationError("runtime CLI returned unexpected version output")


def verify(root: Path = ROOT) -> None:
    """Verify quality and artifacts from separate exact staged Phase 0 snapshots."""

    trusted_root = root.resolve()
    captured_tree: str | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="cairnvm-staged-build-") as temporary:
            temporary_root = Path(temporary)
            build_root = temporary_root / "build-workspace"
            quality_root = temporary_root / "quality-workspace"
            captured_tree = materialize_staged_index(trusted_root, quality_root)
            verify_staged_quality(quality_root)
            build_tree = materialize_staged_index(trusted_root, build_root)
            if build_tree != captured_tree:
                raise VerificationError("quality and build snapshots do not share one staged tree")
            constraints = build_root / BUILD_CONSTRAINTS.relative_to(ROOT)
            build_staged_snapshot(build_root, constraints=constraints)
            artifacts = collect_artifacts(build_root / DIST.relative_to(ROOT))
            rebuilt_root = temporary_root / "rebuilt"
            for release in EXPECTED_RELEASES:
                built = artifacts[release.name]
                check_wheel(built.wheel, release)
                smoke_test_wheel(built.wheel, release)
                rebuilt = rebuild_wheel(
                    release,
                    built.sdist,
                    rebuilt_root / release.name,
                    constraints=constraints,
                )
                check_wheel(rebuilt, release)
                smoke_test_wheel(rebuilt, release)
    finally:
        if captured_tree is not None:
            finish_staged_index(trusted_root, captured_tree)


def main() -> int:
    try:
        verify()
    except VerificationError as error:
        print(f"artifact verification failed: {error}", file=sys.stderr)
        return 1
    print("verified exact runtime and launcher wheels and sdists")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
