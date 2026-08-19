#!/usr/bin/env python3
"""Scan exact Git trees with a pinned Gitleaks policy and generated canary."""

from __future__ import annotations

import base64
import hashlib
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

ARCHIVE_DEPTH = "1"
DECODE_DEPTH = "1"
GIT_COMMAND_TIMEOUT_SECONDS = 30
REPOSITORY_SCAN_TIMEOUT_SECONDS = 300
MAX_HISTORY_TREES = 4096
MAX_TREE_ENTRIES = 100_000
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024
GITLEAKS_CONFIG_ENVIRONMENT = ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML")
GITLEAKS_POLICY = "[extend]\nuseDefault = true\n"
REPOSITORY_CONTROL_FILES = frozenset((".gitleaks.toml", ".gitleaksignore"))
REGULAR_FILE_MODES = frozenset(("100644", "100755"))
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PINNED_GITLEAKS_REVISION = "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
PINNED_PRE_COMMIT_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve() / ".cache" / "pre-commit"
BOOTSTRAP_ENVIRONMENT_VARIABLE = "CAIRNVM_GITLEAKS_BOOTSTRAPPED"


@dataclass(frozen=True)
class GitRepository:
    executable: str
    root: Path
    git_dir: Path
    environment: dict[str, str]
    object_format: str = "sha1"


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    object_id: str
    size: int
    path: str


def build_canary() -> str:
    """Build a rule-matching token without storing one contiguously in the repository."""

    payload = "".join(("wA9mK2pL", "xN4vRtQz", "Y6bC8dEf", "GhJlM0oP", "q1rS"))
    return "".join(("gh", "p_", payload))


def scanner_environment() -> dict[str, str]:
    """Remove ambient Git and Gitleaks controls from scanner subprocesses."""

    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_") and key not in GITLEAKS_CONFIG_ENVIRONMENT
    }


def _bootstrap_environment() -> dict[str, str]:
    blocked_names = {"SKIP", BOOTSTRAP_ENVIRONMENT_VARIABLE}
    blocked_prefixes = ("GIT_", "GITLEAKS_", "PRE_COMMIT")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in blocked_names and not key.startswith(blocked_prefixes)
    }
    environment["PRE_COMMIT_HOME"] = str(PINNED_PRE_COMMIT_HOME)
    environment[BOOTSTRAP_ENVIRONMENT_VARIABLE] = "1"
    return environment


def _configured_gitleaks_pin_is_exact() -> bool:
    try:
        configuration = (REPOSITORY_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    except OSError:
        return False
    return (
        "repo: https://github.com/gitleaks/gitleaks\n"
        f"    rev: {PINNED_GITLEAKS_REVISION} # v8.30.1\n" in configuration
    )


def _resolve_pinned_scanner() -> str | None:
    candidate = shutil.which("gitleaks")
    if candidate is None:
        return None
    try:
        scanner = Path(candidate).resolve(strict=True)
        cache_root = PINNED_PRE_COMMIT_HOME.resolve(strict=True)
        relative = scanner.relative_to(cache_root)
    except (OSError, ValueError):
        return None
    if (
        len(relative.parts) != 4
        or not relative.parts[0].startswith("repo")
        or relative.parts[1:] != ("golangenv-default", "bin", "gitleaks")
        or not scanner.is_file()
        or not os.access(scanner, os.X_OK)
    ):
        return None

    repository = cache_root / relative.parts[0]
    git = shutil.which("git")
    if git is None:
        return None
    try:
        git = str(Path(git).resolve(strict=True))
        result = subprocess.run(  # noqa: S603  # Git is resolved without a shell.
            [git, "--no-pager", "--no-replace-objects", "-C", str(repository), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            env=git_environment(PINNED_PRE_COMMIT_HOME),
            timeout=GIT_COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        revision = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    if revision != PINNED_GITLEAKS_REVISION:
        return None
    return str(scanner)


def _run_pinned_hook() -> int:
    if not _configured_gitleaks_pin_is_exact():
        return 2
    uv = shutil.which("uv")
    if uv is None:
        return 2
    try:
        uv = str(Path(uv).resolve(strict=True))
        result = subprocess.run(  # noqa: S603  # uv is resolved without a shell.
            [
                uv,
                "run",
                "--locked",
                "--all-packages",
                "python",
                "-m",
                "pre_commit",
                "run",
                "--config",
                str(REPOSITORY_ROOT / ".pre-commit-config.yaml"),
                "gitleaks",
                "--all-files",
            ],
            check=False,
            cwd=REPOSITORY_ROOT,
            env=_bootstrap_environment(),
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            timeout=REPOSITORY_SCAN_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 2
    return result.returncode if result.returncode in (0, 1) else 2


def git_environment(isolated_home: Path) -> dict[str, str]:
    """Create a Git environment without ambient selectors or external configuration."""

    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "HOME": str(isolated_home),
            "LC_ALL": "C",
            "XDG_CONFIG_HOME": str(isolated_home),
        }
    )
    return environment


def write_scanner_policy(directory: Path) -> Path:
    """Bind scans to the pinned scanner's built-in policy."""

    policy = directory / "policy.toml"
    policy.write_text(GITLEAKS_POLICY, encoding="utf-8")
    policy.chmod(0o600)
    return policy


def _remaining_timeout(deadline: float, maximum: int) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("secret scanner repository snapshot timed out")
    return min(remaining, float(maximum))


def _run_discovery_git(
    executable: str,
    repository: Path,
    arguments: list[str],
    *,
    environment: dict[str, str],
    deadline: float,
) -> bytes:
    try:
        result = subprocess.run(  # noqa: S603  # Git is resolved to an absolute executable.
            [executable, "--no-pager", "--no-replace-objects", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
            env=environment,
            timeout=_remaining_timeout(deadline, GIT_COMMAND_TIMEOUT_SECONDS),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("Git could not resolve the repository boundary") from error
    if result.returncode != 0 or len(result.stdout) > MAX_GIT_OUTPUT_BYTES:
        raise RuntimeError("Git could not resolve the repository boundary")
    return result.stdout


def _open_repository(repository: Path, *, isolated_home: Path, deadline: float) -> GitRepository:
    try:
        requested_root = repository.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("secret scan repository is unavailable") from error
    if not requested_root.is_dir():
        raise RuntimeError("secret scan repository is unavailable")

    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("Git is unavailable for secret scanning")
    try:
        executable = str(Path(executable).resolve(strict=True))
    except OSError as error:
        raise RuntimeError("Git is unavailable for secret scanning") from error

    environment = git_environment(isolated_home)
    root_output = _run_discovery_git(
        executable,
        requested_root,
        ["rev-parse", "--show-toplevel"],
        environment=environment,
        deadline=deadline,
    )
    git_dir_output = _run_discovery_git(
        executable,
        requested_root,
        ["rev-parse", "--absolute-git-dir"],
        environment=environment,
        deadline=deadline,
    )
    try:
        canonical_root = Path(root_output.decode("utf-8").strip()).resolve(strict=True)
        canonical_git_dir = Path(git_dir_output.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as error:
        raise RuntimeError("Git returned an invalid repository boundary") from error
    if canonical_root != requested_root or not canonical_git_dir.is_dir():
        raise RuntimeError("Git returned an invalid repository boundary")

    repository_boundary = GitRepository(
        executable,
        canonical_root,
        canonical_git_dir,
        environment,
    )
    object_format_output = _captured_stdout(
        _run_bound_git(
            repository_boundary,
            ["rev-parse", "--show-object-format"],
            deadline=deadline,
        )
    )
    try:
        object_format = object_format_output.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise RuntimeError("Git returned an unsupported object format") from error
    if object_format not in ("sha1", "sha256"):
        raise RuntimeError("Git returned an unsupported object format")
    return GitRepository(
        executable,
        canonical_root,
        canonical_git_dir,
        environment,
        object_format,
    )


def _run_bound_git(
    repository: GitRepository,
    arguments: list[str],
    *,
    deadline: float,
    stdout: int | BinaryIO = subprocess.PIPE,
) -> subprocess.CompletedProcess[bytes]:
    command = [
        repository.executable,
        "--no-pager",
        "--no-replace-objects",
        f"--git-dir={repository.git_dir}",
        f"--work-tree={repository.root}",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        f"core.excludesFile={os.devnull}",
        "-c",
        "core.fsmonitor=false",
        *arguments,
    ]
    try:
        result = subprocess.run(  # noqa: S603  # Git is resolved to an absolute executable.
            command,
            check=False,
            env=repository.environment,
            stderr=subprocess.PIPE,
            stdout=stdout,
            timeout=_remaining_timeout(deadline, GIT_COMMAND_TIMEOUT_SECONDS),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("Git could not capture repository content") from error
    if result.returncode != 0:
        raise RuntimeError("Git could not capture repository content")
    if isinstance(result.stdout, bytes) and len(result.stdout) > MAX_GIT_OUTPUT_BYTES:
        raise RuntimeError("Git repository metadata exceeds the scanner limit")
    return result


def _captured_stdout(result: subprocess.CompletedProcess[bytes]) -> bytes:
    if not isinstance(result.stdout, bytes):
        raise RuntimeError("Git did not return captured repository metadata")
    return result.stdout


def _blob_object_id(path: Path, size: int, object_format: str) -> str:
    digest = hashlib.new(object_format)
    digest.update(f"blob {size}\0".encode("ascii"))
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_object_id(value: str) -> None:
    if len(value) not in (40, 64) or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise RuntimeError("Git returned an invalid object identifier")


def _validate_entry_path(raw_path: bytes, collision_keys: set[str]) -> str:
    try:
        path = raw_path.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError("Git tree contains a non-UTF-8 path") from error
    pure_path = PurePosixPath(path)
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or any(part in ("", ".", "..") for part in pure_path.parts)
    ):
        raise RuntimeError("Git tree contains an unsafe path")
    if any(part in REPOSITORY_CONTROL_FILES for part in pure_path.parts):
        raise RuntimeError("repository secret-scanner control file is unsupported")
    collision_key = unicodedata.normalize("NFC", path).casefold()
    if collision_key in collision_keys:
        raise RuntimeError("Git tree contains colliding paths")
    collision_keys.add(collision_key)
    return path


def _list_tree(
    repository: GitRepository, tree: str, *, deadline: float
) -> tuple[list[TreeEntry], int]:
    _validate_object_id(tree)
    result = _run_bound_git(
        repository,
        ["ls-tree", "-rz", "-l", "--full-tree", tree],
        deadline=deadline,
    )
    output = _captured_stdout(result)
    entries: list[TreeEntry] = []
    total_bytes = 0
    collision_keys: set[str] = set()
    records = output.split(b"\0")
    if records[-1] != b"":
        raise RuntimeError("Git returned a malformed tree listing")
    for record in records[:-1]:
        try:
            metadata, raw_path = record.split(b"\t", 1)
            raw_mode, raw_type, raw_object_id, raw_size = metadata.split()
            mode = raw_mode.decode("ascii")
            object_type = raw_type.decode("ascii")
            object_id = raw_object_id.decode("ascii")
            size = int(raw_size)
        except (UnicodeDecodeError, ValueError) as error:
            raise RuntimeError("Git returned a malformed tree listing") from error
        if mode not in REGULAR_FILE_MODES or object_type != "blob" or size < 0:
            raise RuntimeError("Git tree contains an unsupported Git tree entry")
        _validate_object_id(object_id)
        path = _validate_entry_path(raw_path, collision_keys)
        entries.append(TreeEntry(mode, object_id, size, path))
        total_bytes += size
        if len(entries) > MAX_TREE_ENTRIES or total_bytes > MAX_SNAPSHOT_BYTES:
            raise RuntimeError("Git tree exceeds the scanner snapshot limit")
    return entries, total_bytes


def _materialize_tree(
    repository: GitRepository,
    tree: str,
    destination: Path,
    *,
    deadline: float,
) -> tuple[int, int]:
    entries, total_bytes = _list_tree(repository, tree, deadline=deadline)
    destination.mkdir(mode=0o700)
    expected_paths = {entry.path for entry in entries}
    try:
        for entry in entries:
            target = destination.joinpath(*PurePosixPath(entry.path).parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with target.open("xb") as output:
                _run_bound_git(
                    repository,
                    ["cat-file", "blob", entry.object_id],
                    deadline=deadline,
                    stdout=output,
                )
            metadata = target.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != entry.size:
                raise RuntimeError("Git blob materialization did not match the captured tree")
            if _blob_object_id(target, entry.size, repository.object_format) != entry.object_id:
                raise RuntimeError("Git blob materialization did not match its object identifier")
            target.chmod(0o700 if entry.mode == "100755" else 0o600)
    except OSError as error:
        raise RuntimeError("Git tree could not be materialized safely") from error

    actual_paths: set[str] = set()
    for root, directories, files in os.walk(destination, followlinks=False):
        if any(Path(root, directory).is_symlink() for directory in directories):
            raise RuntimeError("Git tree materialization contains a symlink")
        for filename in files:
            path = Path(root, filename)
            if not stat.S_ISREG(path.lstat().st_mode):
                raise RuntimeError("Git tree materialization contains a nonregular file")
            actual_paths.add(path.relative_to(destination).as_posix())
    if actual_paths != expected_paths:
        raise RuntimeError("Git tree materialization entry set did not match")
    return len(entries), total_bytes


def _captured_trees(repository: GitRepository, *, scope: str, deadline: float) -> list[str]:
    if scope == "staged":
        result = _run_bound_git(repository, ["write-tree"], deadline=deadline)
        output = _captured_stdout(result)
        try:
            tree = output.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise RuntimeError("Git returned an invalid index tree") from error
        _validate_object_id(tree)
        return [tree]

    result = _run_bound_git(
        repository,
        ["log", "--all", "--format=%T", "--no-show-signature"],
        deadline=deadline,
    )
    output = _captured_stdout(result)
    try:
        candidates = output.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("Git returned an invalid history tree list") from error
    trees: list[str] = []
    seen: set[str] = set()
    for tree in candidates:
        _validate_object_id(tree)
        if tree not in seen:
            seen.add(tree)
            trees.append(tree)
        if len(trees) > MAX_HISTORY_TREES:
            raise RuntimeError("Git history exceeds the scanner tree limit")
    if not trees:
        raise RuntimeError("Git history contains no commit trees")
    return trees


def verify_canary(scanner: str) -> None:
    """Require Gitleaks to report exactly one leak-style exit for a synthetic token."""

    with tempfile.TemporaryDirectory(prefix="cairnvm-gitleaks-canary-") as temporary:
        temporary_path = Path(temporary)
        policy = write_scanner_policy(temporary_path)
        source = temporary_path / "canary.zip"
        encoded = base64.b64encode(build_canary().encode("ascii"))
        with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("canary.txt", encoded)
        try:
            result = subprocess.run(  # noqa: S603  # Scanner is resolved without a shell.
                [
                    scanner,
                    "dir",
                    "--config",
                    str(policy),
                    "--redact",
                    "--no-banner",
                    "--max-archive-depth",
                    ARCHIVE_DEPTH,
                    "--max-decode-depth",
                    DECODE_DEPTH,
                    str(source),
                ],
                check=False,
                env=scanner_environment(),
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("secret scanner canary could not complete") from error

    if result.returncode != 1:
        raise RuntimeError("secret scanner failed to detect its generated canary")


def _scan_snapshot(scanner: str, snapshot: Path, policy_directory: Path, *, deadline: float) -> int:
    policy = write_scanner_policy(policy_directory)
    disabled_ignore_path = policy_directory / "no-gitleaksignore"
    timeout = _remaining_timeout(deadline, REPOSITORY_SCAN_TIMEOUT_SECONDS)
    command = [
        scanner,
        "dir",
        "--config",
        str(policy),
        "--gitleaks-ignore-path",
        str(disabled_ignore_path),
        "--ignore-gitleaks-allow",
        "--redact",
        "--no-banner",
        "--no-color",
        "--max-archive-depth",
        ARCHIVE_DEPTH,
        "--max-decode-depth",
        DECODE_DEPTH,
        "--timeout",
        str(max(1, int(timeout))),
        str(snapshot),
    ]
    try:
        result = subprocess.run(  # noqa: S603  # Scanner is resolved without a shell.
            command,
            check=False,
            env=scanner_environment(),
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("secret scanner could not scan repository content") from error
    if result.returncode not in (0, 1):
        raise RuntimeError("secret scanner failed while scanning repository content")
    return result.returncode


def scan_repository(scanner: str | Path, *, scope: str, repository: Path = REPOSITORY_ROOT) -> int:
    """Scan the complete canonical index tree or every unique commit tree."""

    if scope not in ("staged", "history"):
        raise RuntimeError(f"unsupported secret scan scope: {scope}")

    deadline = time.monotonic() + REPOSITORY_SCAN_TIMEOUT_SECONDS
    with tempfile.TemporaryDirectory(prefix="cairnvm-gitleaks-snapshot-") as temporary:
        temporary_path = Path(temporary)
        isolated_home = temporary_path / "home"
        snapshot = temporary_path / "snapshot"
        policy_directory = temporary_path / "policy"
        isolated_home.mkdir(mode=0o700)
        snapshot.mkdir(mode=0o700)
        policy_directory.mkdir(mode=0o700)

        git_repository = _open_repository(
            repository,
            isolated_home=isolated_home,
            deadline=deadline,
        )
        trees = _captured_trees(git_repository, scope=scope, deadline=deadline)
        total_entries = 0
        total_bytes = 0
        for index, tree in enumerate(trees):
            destination = snapshot / f"tree-{index:06d}"
            entries, size = _materialize_tree(
                git_repository,
                tree,
                destination,
                deadline=deadline,
            )
            total_entries += entries
            total_bytes += size
            if total_entries > MAX_TREE_ENTRIES or total_bytes > MAX_SNAPSHOT_BYTES:
                raise RuntimeError("Git repository snapshots exceed the scanner limit")

        result = _scan_snapshot(str(scanner), snapshot, policy_directory, deadline=deadline)
        if scope == "staged":
            final_tree = _captured_trees(
                git_repository,
                scope="staged",
                deadline=deadline,
            )[0]
            if final_tree != trees[0]:
                raise RuntimeError("canonical index changed during secret scanning")
        return result


def main() -> int:
    """Verify the scanner, then run the selected staged or history scope over exact trees."""

    scanner = _resolve_pinned_scanner()
    if scanner is None:
        if os.environ.get(BOOTSTRAP_ENVIRONMENT_VARIABLE) == "1":
            print("pinned secret scanner is unavailable", file=sys.stderr)
            return 2
        return _run_pinned_hook()

    try:
        verify_canary(scanner)
        return scan_repository(
            scanner,
            scope=os.environ.get("CAIRNVM_SECRET_SCAN_SCOPE", "staged"),
            repository=REPOSITORY_ROOT,
        )
    except (OSError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
