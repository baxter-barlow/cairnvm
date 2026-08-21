from __future__ import annotations

import base64
import concurrent.futures
import gzip
import hashlib
import inspect
import io
import os
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
import zlib
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from http.client import HTTPMessage
from pathlib import Path
from typing import BinaryIO, cast
from unittest.mock import Mock, patch

from pre_commit.clientlib import load_config  # type: ignore[import-untyped]

from scripts import verify_secret_scanner as scanner_module
from scripts.verify_secret_scanner import (
    REPOSITORY_ROOT,
    build_canary,
    main,
    scan_repository,
    verify_canary,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_SCANNER = bytearray(64)
FIXTURE_SCANNER[:6] = b"\x7fELF\x02\x01"
FIXTURE_SCANNER[18:20] = (62).to_bytes(2, "little")
FIXTURE_SCANNER_BYTES = bytes(FIXTURE_SCANNER)


def run_git(repository: Path, *arguments: str, environment: dict[str, str] | None = None) -> None:
    git = shutil.which("git")
    if git is None:
        raise AssertionError("Git is required for the scanner regression tests")
    subprocess.run(  # noqa: S603  # Git is resolved from the test environment.
        [git, "-C", str(repository), *arguments],
        env=environment,
        check=True,
        capture_output=True,
    )


def initialize_repository(repository: Path) -> None:
    run_git(repository, "init", "--quiet")
    run_git(repository, "config", "user.name", "Scanner Test")
    run_git(repository, "config", "user.email", "scanner@example.invalid")


def write_fake_scanner(directory: Path, *, emit_output: bool = False) -> Path:
    scanner = directory / "gitleaks"
    output = (
        "print('scanner stdout ' + token)\nprint('scanner stderr ' + token, file=sys.stderr)\n"
        if emit_output
        else ""
    )
    scanner.write_text(
        "#!/usr/bin/env python3\n"
        "import base64\n"
        "import pathlib\n"
        "import sys\n"
        "import zipfile\n"
        "token = 'gh' + 'p_' + 'wA9mK2pL' + 'xN4vRtQz' + 'Y6bC8dEf' + "
        "'GhJlM0oP' + 'q1rS'\n"
        f"{output}"
        "if len(sys.argv) == 2 and sys.argv[1] == 'version':\n"
        "    print('8.30.1')\n"
        "    raise SystemExit(0)\n"
        "if len(sys.argv) < 3 or sys.argv[1] != 'dir':\n"
        "    raise SystemExit(2)\n"
        "target = pathlib.Path(sys.argv[-1])\n"
        "found = False\n"
        "for path in ([target] if target.is_file() else target.rglob('*')):\n"
        "    if not path.is_file():\n"
        "        continue\n"
        "    data = path.read_bytes()\n"
        "    if token.encode() in data:\n"
        "        found = True\n"
        "    if zipfile.is_zipfile(path):\n"
        "        with zipfile.ZipFile(path) as archive:\n"
        "            for name in archive.namelist():\n"
        "                try:\n"
        "                    decoded = base64.b64decode(archive.read(name))\n"
        "                except ValueError:\n"
        "                    continue\n"
        "                found = found or token.encode() in decoded\n"
        "raise SystemExit(1 if found else 0)\n",
        encoding="utf-8",
    )
    scanner.chmod(0o700)
    return scanner


def build_release_archive(
    entries: list[tuple[tarfile.TarInfo, bytes | None]] | None = None,
    *,
    scanner_payload: bytes = FIXTURE_SCANNER_BYTES,
) -> bytes:
    license_member = tarfile.TarInfo("LICENSE")
    license_member.mode = 0o644
    license_member.size = 1_069
    readme_member = tarfile.TarInfo("README.md")
    readme_member.mode = 0o644
    readme_member.size = 29_998
    scanner = tarfile.TarInfo("gitleaks")
    scanner.mode = 0o755
    scanner.size = len(scanner_payload)
    selected_entries = entries or [
        (license_member, b"L" * license_member.size),
        (readme_member, b"R" * readme_member.size),
        (scanner, scanner_payload),
    ]
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for member, payload in selected_entries:
            archive.addfile(member, io.BytesIO(payload) if payload is not None else None)
    return output.getvalue()


def fixture_release_asset(
    archive: bytes,
    *,
    binary_size: int = len(FIXTURE_SCANNER_BYTES),
) -> scanner_module.ReleaseAsset:
    return scanner_module.ReleaseAsset(
        "gitleaks_8.30.1_fixture.tar.gz",
        hashlib.sha256(archive).hexdigest(),
        binary_size,
        len(archive),
        len(zlib.decompress(archive, 16 + zlib.MAX_WBITS)),
        "elf",
        62,
    )


def mutate_tar_header(archive: bytes, member_index: int, offset: int, value: bytes) -> bytes:
    raw = bytearray(gzip.decompress(archive))
    position = 0
    for index in range(member_index + 1):
        header = raw[position : position + 512]
        if len(header) != 512 or header == bytes(512):
            raise AssertionError("fixture member is unavailable")
        if index == member_index:
            header[offset : offset + len(value)] = value
            header[148:156] = b" " * 8
            checksum = sum(header)
            header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
            raw[position : position + 512] = header
            return gzip.compress(bytes(raw), mtime=0)
        size = int(bytes(header[124:136]).rstrip(b"\0 ") or b"0", 8)
        position += 512 + ((size + 511) // 512) * 512
    raise AssertionError("fixture member is unavailable")


class SecretScannerConfigurationTests(unittest.TestCase):
    def test_mandatory_staged_gate_removes_ambient_pre_commit_skip(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-scan-gate-test-") as temporary:
            temporary_path = Path(temporary)
            marker = temporary_path / "invocation.txt"
            fake_uv = temporary_path / "uv"
            fake_uv.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"${CAIRNVM_SECRET_SCAN_SCOPE}|${SKIP-unset}|"
                '${CAIRNVM_GITLEAKS_BOOTSTRAPPED-unset}|$*" '
                '> "$CAIRNVM_TEST_MARKER"\n',
                encoding="utf-8",
            )
            fake_uv.chmod(0o700)
            environment = os.environ.copy()
            environment.update(
                {
                    "CAIRNVM_TEST_MARKER": str(marker),
                    "PATH": f"{temporary}{os.pathsep}{environment['PATH']}",
                    "SKIP": "gitleaks",
                    "CAIRNVM_GITLEAKS_BOOTSTRAPPED": "hostile",
                }
            )
            make = shutil.which("make")
            self.assertIsNotNone(make)
            assert make is not None

            result = subprocess.run(  # noqa: S603  # make is resolved from the test environment.
                [make, "--no-print-directory", "scan-staged"],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            invocation = marker.read_text(encoding="utf-8")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            "staged|unset|unset|run --locked --all-packages python "
            "scripts/verify_secret_scanner.py\n",
            invocation,
        )

    def test_gitignore_does_not_hide_reviewable_security_source_or_fixtures(self) -> None:
        patterns = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())

        for broad_pattern in (
            "**/client_secret*.json",
            "**/credentials*.json",
            "**/oauth*.json",
            "**/token*.json",
            "**/*refresh_token*",
            "*.pem",
            "*.key",
            "*.p12",
            "*.pfx",
            "*.jks",
            "*.keystore",
            "id_rsa",
            "id_ed25519",
        ):
            self.assertNotIn(broad_pattern, patterns)

        for root_export_pattern in (
            "/client_secret*.json",
            "/credentials*.json",
            "/oauth*.json",
            "/token*.json",
            "/*refresh_token*",
            "/*.pem",
            "/*.key",
            "/*.p12",
            "/*.pfx",
            "/*.jks",
            "/*.keystore",
            "/id_rsa",
            "/id_ed25519",
        ):
            self.assertIn(root_export_pattern, patterns)

    def test_pre_commit_uses_the_locked_wrapper_as_a_local_system_hook(self) -> None:
        configuration = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        verifier = (ROOT / "scripts/verify_secret_scanner.py").read_text(encoding="utf-8")
        parsed = load_config(str(ROOT / ".pre-commit-config.yaml"))
        self.assertEqual(["local"], [repository["repo"] for repository in parsed["repos"]])
        hooks = parsed["repos"][0]["hooks"]
        gitleaks_hooks = [hook for hook in hooks if hook["id"] == "gitleaks"]
        self.assertEqual(1, len(gitleaks_hooks))
        self.assertEqual(
            {
                "id": "gitleaks",
                "name": "scan exact Git trees for secrets",
                "entry": "python3 scripts/verify_secret_scanner.py",
                "language": "unsupported",
                "pass_filenames": False,
                "always_run": True,
            },
            {
                key: gitleaks_hooks[0][key]
                for key in (
                    "id",
                    "name",
                    "entry",
                    "language",
                    "pass_filenames",
                    "always_run",
                )
            },
        )

        self.assertNotIn("github.com/gitleaks/gitleaks", configuration)
        self.assertNotIn("language_version:", configuration)
        for rejected in (
            "pre_commit",
            "PRE_COMMIT_HOME",
            "PINNED_GO_VERSION",
            "golangenv",
            "_run_pinned_hook",
            "_resolve_pinned_scanner",
        ):
            self.assertNotIn(rejected, verifier)

        duplicate_key = configuration.replace(
            "        language: system\n",
            "        language: system\n        language: python\n",
            1,
        )
        with tempfile.TemporaryDirectory(prefix="cairnvm-duplicate-hook-key-test-") as temporary:
            duplicate_path = Path(temporary) / ".pre-commit-config.yaml"
            duplicate_path.write_text(duplicate_key, encoding="utf-8")
            mutated = load_config(str(duplicate_path))
            original_ruff = next(hook for hook in hooks if hook["id"] == "ruff-check")
            mutated_ruff = next(
                hook
                for repository in mutated["repos"]
                for hook in repository["hooks"]
                if hook["id"] == "ruff-check"
            )
            self.assertEqual("unsupported", original_ruff["language"])
            self.assertEqual("python", mutated_ruff["language"])

    def test_release_mapping_is_exact_and_rejects_unsupported_platforms(self) -> None:
        expected = {
            ("darwin", "arm64"): (
                "gitleaks_8.30.1_darwin_arm64.tar.gz",
                "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
            ),
            ("darwin", "x64"): (
                "gitleaks_8.30.1_darwin_x64.tar.gz",
                "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
            ),
            ("linux", "arm64"): (
                "gitleaks_8.30.1_linux_arm64.tar.gz",
                "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
            ),
            ("linux", "x64"): (
                "gitleaks_8.30.1_linux_x64.tar.gz",
                "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
            ),
        }

        self.assertEqual(
            expected,
            {
                platform_key: (asset.filename, asset.sha256)
                for platform_key, asset in scanner_module.GITLEAKS_RELEASE_ASSETS.items()
            },
        )
        self.assertEqual(
            {
                ("darwin", "arm64"): (21_324_882, 7_897_593, 21_359_616, "macho", 0x0100000C),
                ("darwin", "x64"): (22_398_576, 8_359_235, 22_433_280, "macho", 0x01000007),
                ("linux", "arm64"): (20_775_096, 7_601_421, 20_809_728, "elf", 183),
                ("linux", "x64"): (21_958_840, 8_230_402, 21_993_472, "elf", 62),
            },
            {
                platform_key: (
                    asset.binary_size,
                    asset.archive_size,
                    asset.tar_size,
                    asset.binary_format,
                    asset.machine_code,
                )
                for platform_key, asset in scanner_module.GITLEAKS_RELEASE_ASSETS.items()
            },
        )
        aliases = {
            ("Darwin", "arm64"): expected[("darwin", "arm64")],
            ("Darwin", "x86_64"): expected[("darwin", "x64")],
            ("Linux", "aarch64"): expected[("linux", "arm64")],
            ("Linux", "amd64"): expected[("linux", "x64")],
        }
        for (system, machine), selected in aliases.items():
            with self.subTest(system=system, machine=machine):
                asset = scanner_module._select_release_asset(system=system, machine=machine)
                self.assertEqual(selected, (asset.filename, asset.sha256))
        for system, machine in (("Windows", "x86_64"), ("Linux", "i386"), ("Darwin", "")):
            with (
                self.subTest(system=system, machine=machine),
                self.assertRaisesRegex(RuntimeError, "unsupported secret scanner platform"),
            ):
                scanner_module._select_release_asset(system=system, machine=machine)

    def test_cache_location_ignores_ambient_redirect_controls(self) -> None:
        asset = next(iter(scanner_module.GITLEAKS_RELEASE_ASSETS.values()))
        passwd_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        hostile = {
            "HOME": "/redirected/home",
            "XDG_CACHE_HOME": "/redirected/xdg",
            "PRE_COMMIT_HOME": "/redirected/pre-commit",
            "GOCACHE": "/redirected/go-cache",
            "GOMODCACHE": "/redirected/go-mod-cache",
            "UV_CACHE_DIR": "/redirected/uv-cache",
        }

        with patch.dict(os.environ, hostile):
            selected = scanner_module._cache_archive_path(asset)

        self.assertEqual(
            passwd_home / ".cache" / "cairnvm" / "gitleaks" / "v8.30.1" / asset.filename,
            selected,
        )

    def test_ci_denies_setup_uv_the_implicit_github_token(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertEqual(3, workflow.count("uses: astral-sh/setup-uv@"))
        self.assertEqual(3, workflow.count('github-token: ""'))
        self.assertNotIn("${{ github.token }}", workflow)

    def test_ci_uses_least_privilege_and_a_complete_history_scan(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertEqual(3, workflow.count("persist-credentials: false"))
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn("CAIRNVM_SECRET_SCAN_SCOPE: history", workflow)


class SecretScannerCanaryTests(unittest.TestCase):
    def test_cached_archive_is_published_atomically_and_reused_offline(self) -> None:
        archive = build_release_archive()
        asset = fixture_release_asset(archive)
        with tempfile.TemporaryDirectory(prefix="cairnvm-release-cache-test-") as temporary:
            cache_home = Path(temporary)

            def download(
                selected: scanner_module.ReleaseAsset,
                destination: BinaryIO,
                *,
                deadline: float,
            ) -> None:
                self.assertEqual(asset, selected)
                self.assertGreater(deadline, time.monotonic())
                destination.write(archive)

            with (
                patch.object(scanner_module, "GITLEAKS_CACHE_HOME", cache_home),
                patch.object(
                    scanner_module,
                    "_download_release_archive",
                    side_effect=download,
                ) as downloader,
            ):
                selected = scanner_module._ensure_cached_archive(asset)
                reused = scanner_module._ensure_cached_archive(asset)

            self.assertEqual(selected, reused)
            self.assertEqual(archive, selected.read_bytes())
            self.assertEqual(0o600, selected.stat().st_mode & 0o777)
            self.assertEqual(0o700, selected.parent.stat().st_mode & 0o777)
            downloader.assert_called_once()
            self.assertEqual(
                {".download.lock", selected.name},
                {path.name for path in selected.parent.iterdir()},
            )

    def test_verified_cache_runs_complete_gate_offline_then_removes_executable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-offline-cache-test-") as temporary:
            cache_home = Path(temporary)
            fake_source = write_fake_scanner(cache_home)
            scanner_payload = fake_source.read_bytes()
            archive = build_release_archive(scanner_payload=scanner_payload)
            asset = fixture_release_asset(archive, binary_size=len(scanner_payload))

            def download(
                _asset: scanner_module.ReleaseAsset,
                destination: BinaryIO,
                *,
                deadline: float,
            ) -> None:
                self.assertGreater(deadline, time.monotonic())
                destination.write(archive)

            with (
                patch.object(scanner_module, "GITLEAKS_CACHE_HOME", cache_home),
                patch.object(scanner_module, "_download_release_archive", side_effect=download),
            ):
                scanner_module._ensure_cached_archive(asset)

            repository = cache_home / "repository"
            repository.mkdir()
            initialize_repository(repository)
            (repository / "safe.txt").write_text("safe", encoding="utf-8")
            run_git(repository, "add", "safe.txt")
            with (
                patch.object(scanner_module, "GITLEAKS_CACHE_HOME", cache_home),
                patch.object(
                    scanner_module,
                    "_download_release_archive",
                    side_effect=AssertionError("network used"),
                ) as parent_download,
                patch.object(
                    scanner_module,
                    "_download_release_archive_child",
                    side_effect=AssertionError("network used"),
                ) as child_download,
                patch.object(scanner_module, "_validate_binary_header"),
                scanner_module._temporary_cached_scanner(asset) as scanner,
            ):
                extracted = scanner
                scanner_module.verify_version(str(scanner), scanner.parent)
                verify_canary(str(scanner))
                self.assertEqual(0, scan_repository(scanner, scope="staged", repository=repository))

            parent_download.assert_not_called()
            child_download.assert_not_called()
            self.assertFalse(extracted.exists())
            cache_root = cache_home / ".cache" / "cairnvm" / "gitleaks" / "v8.30.1"
            self.assertEqual([], list(cache_root.glob(".gitleaks-exec-*")))

    def test_partial_download_is_never_published(self) -> None:
        archive = build_release_archive()
        asset = fixture_release_asset(archive)
        with tempfile.TemporaryDirectory(prefix="cairnvm-partial-download-test-") as temporary:
            cache_home = Path(temporary)

            def fail_download(
                _asset: scanner_module.ReleaseAsset,
                destination: BinaryIO,
                *,
                deadline: float,
            ) -> None:
                self.assertGreater(deadline, time.monotonic())
                destination.write(b"partial")
                raise RuntimeError("download failed")

            with (
                patch.object(scanner_module, "GITLEAKS_CACHE_HOME", cache_home),
                patch.object(
                    scanner_module,
                    "_download_release_archive",
                    side_effect=fail_download,
                ),
                self.assertRaisesRegex(RuntimeError, "download failed"),
            ):
                scanner_module._ensure_cached_archive(asset)

            cache_root = cache_home / ".cache" / "cairnvm" / "gitleaks" / "v8.30.1"
            self.assertFalse((cache_root / asset.filename).exists())
            self.assertEqual([], list(cache_root.glob("*.partial")))

    def test_invalid_or_redirected_cache_state_is_never_overwritten(self) -> None:
        archive = build_release_archive()
        asset = fixture_release_asset(archive)
        with tempfile.TemporaryDirectory(prefix="cairnvm-invalid-cache-test-") as temporary:
            cache_home = Path(temporary)
            cache_root = cache_home / ".cache" / "cairnvm" / "gitleaks" / "v8.30.1"
            cache_root.mkdir(parents=True, mode=0o700)
            for parent in (
                cache_home / ".cache" / "cairnvm",
                cache_home / ".cache" / "cairnvm" / "gitleaks",
                cache_root,
            ):
                parent.chmod(0o700)
            final = cache_root / asset.filename
            final.write_bytes(b"corrupt")
            final.chmod(0o600)
            with (
                patch.object(scanner_module, "GITLEAKS_CACHE_HOME", cache_home),
                patch.object(scanner_module, "_download_release_archive") as downloader,
                self.assertRaisesRegex(RuntimeError, "size did not match"),
            ):
                scanner_module._ensure_cached_archive(asset)
            downloader.assert_not_called()
            self.assertEqual(b"corrupt", final.read_bytes())

            final.unlink()
            os.mkfifo(final, mode=0o600)
            with (
                patch.object(scanner_module, "GITLEAKS_CACHE_HOME", cache_home),
                patch.object(scanner_module, "_download_release_archive") as downloader,
                self.assertRaisesRegex(RuntimeError, "private regular file"),
            ):
                scanner_module._ensure_cached_archive(asset)
            downloader.assert_not_called()

            final.unlink()
            target = cache_home / "redirected"
            target.write_bytes(archive)
            final.symlink_to(target)
            with (
                patch.object(scanner_module, "GITLEAKS_CACHE_HOME", cache_home),
                patch.object(scanner_module, "_download_release_archive") as downloader,
                self.assertRaisesRegex(RuntimeError, "archive is unavailable"),
            ):
                scanner_module._ensure_cached_archive(asset)
            downloader.assert_not_called()

    def test_cache_component_permissions_and_hardlinks_fail_closed(self) -> None:
        archive = build_release_archive()
        asset = fixture_release_asset(archive)
        with tempfile.TemporaryDirectory(prefix="cairnvm-cache-shape-test-") as temporary:
            cache_home = Path(temporary)
            cairnvm = cache_home / ".cache" / "cairnvm"
            cairnvm.mkdir(parents=True)
            cairnvm.chmod(0o755)
            with (
                patch.object(scanner_module, "GITLEAKS_CACHE_HOME", cache_home),
                self.assertRaisesRegex(RuntimeError, "cache directory is unsafe"),
            ):
                scanner_module._ensure_cached_archive(asset)

        with tempfile.TemporaryDirectory(prefix="cairnvm-cache-hardlink-test-") as temporary:
            cache_home = Path(temporary)
            with patch.object(scanner_module, "GITLEAKS_CACHE_HOME", cache_home):
                with scanner_module._open_cache_directory() as (_fd, cache_root):
                    final = cache_root / asset.filename
                    final.write_bytes(archive)
                    final.chmod(0o600)
                    os.link(final, cache_root / "second-link")
                with self.assertRaisesRegex(RuntimeError, "private regular file"):
                    scanner_module._ensure_cached_archive(asset)

    def test_symlink_at_each_cache_component_fails_closed(self) -> None:
        asset = fixture_release_asset(build_release_archive())
        components = ("home", ".cache", "cairnvm", "gitleaks", "v8.30.1")
        for component in components:
            with (
                self.subTest(component=component),
                tempfile.TemporaryDirectory(prefix="cairnvm-cache-symlink-test-") as temporary,
            ):
                base = Path(temporary)
                target = base / "target"
                target.mkdir()
                home = base / "home"
                if component == "home":
                    home.symlink_to(target, target_is_directory=True)
                else:
                    home.mkdir()
                    current = home
                    for name in (".cache", "cairnvm", "gitleaks", "v8.30.1"):
                        candidate = current / name
                        if name == component:
                            candidate.symlink_to(target, target_is_directory=True)
                            break
                        candidate.mkdir()
                        current = candidate
                with (
                    patch.object(scanner_module, "GITLEAKS_CACHE_HOME", home),
                    patch.object(scanner_module, "_download_release_archive") as downloader,
                    self.assertRaisesRegex(RuntimeError, "cache directory is unsafe"),
                ):
                    scanner_module._ensure_cached_archive(asset)
                downloader.assert_not_called()

    def test_cache_file_shapes_permissions_and_owner_fail_closed(self) -> None:
        archive = build_release_archive()
        fixture = fixture_release_asset(archive)
        asset = scanner_module.ReleaseAsset(
            "asset.tar.gz",
            fixture.sha256,
            fixture.binary_size,
            fixture.archive_size,
            fixture.tar_size,
            fixture.binary_format,
            fixture.machine_code,
        )
        with tempfile.TemporaryDirectory(prefix="cv-", dir="/tmp") as temporary:
            cache_home = Path(temporary)
            with patch.object(scanner_module, "GITLEAKS_CACHE_HOME", cache_home):
                with scanner_module._open_cache_directory() as (_fd, cache_root):
                    final = cache_root / asset.filename

                for name, create, message in (
                    ("directory", lambda: final.mkdir(), "private regular file"),
                    ("bad-permissions", lambda: final.write_bytes(archive), "private regular file"),
                ):
                    with self.subTest(name=name):
                        create()
                        if name == "bad-permissions":
                            final.chmod(0o644)
                        with (
                            patch.object(scanner_module, "_download_release_archive") as downloader,
                            self.assertRaisesRegex(RuntimeError, message),
                        ):
                            scanner_module._ensure_cached_archive(asset)
                        downloader.assert_not_called()
                        if final.is_dir():
                            final.rmdir()
                        else:
                            final.unlink()

                unix_socket = socket.socket(socket.AF_UNIX)
                try:
                    unix_socket.bind(str(final))
                    with (
                        patch.object(scanner_module, "_download_release_archive") as downloader,
                        self.assertRaisesRegex(RuntimeError, "archive"),
                    ):
                        scanner_module._ensure_cached_archive(asset)
                    downloader.assert_not_called()
                finally:
                    unix_socket.close()
                    final.unlink(missing_ok=True)

                lock = cache_root / ".download.lock"
                lock.chmod(0o644)
                with self.assertRaisesRegex(RuntimeError, "cache lock is unsafe"):
                    scanner_module._ensure_cached_archive(asset)

        foreign_archive = cast(
            os.stat_result,
            Mock(
                st_mode=stat.S_IFREG | 0o600,
                st_uid=os.getuid() + 1,
                st_nlink=1,
                st_size=len(archive),
            ),
        )
        foreign_lock = cast(
            os.stat_result,
            Mock(
                st_mode=stat.S_IFREG | 0o600,
                st_uid=os.getuid() + 1,
                st_nlink=1,
            ),
        )
        device = cast(
            os.stat_result,
            Mock(
                st_mode=stat.S_IFCHR | 0o600,
                st_uid=os.getuid(),
                st_nlink=1,
                st_size=len(archive),
            ),
        )
        for metadata, validator, message in (
            (foreign_archive, scanner_module._validate_archive_metadata, "private regular file"),
            (foreign_lock, scanner_module._validate_lock_metadata, "cache lock is unsafe"),
            (device, scanner_module._validate_archive_metadata, "private regular file"),
        ):
            with self.assertRaisesRegex(RuntimeError, message):
                validator(metadata)

    def test_leftover_partial_is_never_published_or_executed(self) -> None:
        archive = build_release_archive()
        asset = fixture_release_asset(archive)
        with tempfile.TemporaryDirectory(prefix="cairnvm-cache-crash-test-") as temporary:
            cache_home = Path(temporary)
            with patch.object(scanner_module, "GITLEAKS_CACHE_HOME", cache_home):
                with scanner_module._open_cache_directory() as (_fd, cache_root):
                    stale = cache_root / f".{asset.filename}.crashed.partial"
                    stale.write_bytes(b"partial")
                    stale.chmod(0o600)

                def download(
                    _asset: scanner_module.ReleaseAsset,
                    destination: BinaryIO,
                    *,
                    deadline: float,
                ) -> None:
                    self.assertGreater(deadline, time.monotonic())
                    destination.write(archive)

                with patch.object(
                    scanner_module,
                    "_download_release_archive",
                    side_effect=download,
                ):
                    selected = scanner_module._ensure_cached_archive(asset)
                self.assertEqual(archive, selected.read_bytes())
                self.assertEqual(b"partial", stale.read_bytes())

    def test_benign_concurrent_cold_starts_share_one_verified_download(self) -> None:
        archive = build_release_archive()
        asset = fixture_release_asset(archive)
        started = threading.Event()
        finish = threading.Event()
        download_calls = 0
        calls_lock = threading.Lock()

        def download(
            _asset: scanner_module.ReleaseAsset,
            destination: BinaryIO,
            *,
            deadline: float,
        ) -> None:
            nonlocal download_calls
            self.assertGreater(deadline, time.monotonic())
            with calls_lock:
                download_calls += 1
            started.set()
            if not finish.wait(timeout=5):
                raise AssertionError("concurrent cache test timed out")
            destination.write(archive)

        with (
            tempfile.TemporaryDirectory(prefix="cairnvm-concurrent-cache-test-") as temporary,
            patch.object(scanner_module, "GITLEAKS_CACHE_HOME", Path(temporary)),
            patch.object(scanner_module, "_download_release_archive", side_effect=download),
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(scanner_module._ensure_cached_archive, asset)
            self.assertTrue(started.wait(timeout=5))
            second = executor.submit(scanner_module._ensure_cached_archive, asset)
            finish.set()
            paths = (first.result(timeout=5), second.result(timeout=5))
            self.assertEqual(archive, paths[0].read_bytes())
            self.assertEqual(archive, paths[1].read_bytes())

        self.assertEqual(1, download_calls)
        self.assertEqual(paths[0], paths[1])

    def test_cache_directory_fd_closes_when_validation_rejects_it(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-cache-fd-test-") as temporary:
            cache_home = Path(temporary)
            real_close = os.close
            closed: list[int] = []

            def record_close(file_descriptor: int) -> None:
                closed.append(file_descriptor)
                real_close(file_descriptor)

            with (
                patch.object(scanner_module, "GITLEAKS_CACHE_HOME", cache_home),
                patch.object(
                    scanner_module,
                    "_validate_private_directory",
                    side_effect=RuntimeError("secret scanner cache directory is unsafe"),
                ),
                patch("scripts.verify_secret_scanner.os.close", side_effect=record_close),
                self.assertRaisesRegex(RuntimeError, "cache directory is unsafe"),
                scanner_module._open_cache_directory(),
            ):
                pass

            self.assertEqual(1, len(closed))

    def test_cache_lock_wait_is_deadline_bounded(self) -> None:
        archive = build_release_archive()
        asset = fixture_release_asset(archive)
        with (
            tempfile.TemporaryDirectory(prefix="cairnvm-cache-lock-test-") as temporary,
            patch.object(scanner_module, "GITLEAKS_CACHE_HOME", Path(temporary)),
            patch.object(scanner_module, "RELEASE_DOWNLOAD_TIMEOUT_SECONDS", 1),
            patch("scripts.verify_secret_scanner.fcntl.flock", side_effect=BlockingIOError),
            patch("scripts.verify_secret_scanner.time.monotonic", side_effect=(0.0, 0.5, 1.1)),
            patch("scripts.verify_secret_scanner.time.sleep"),
            self.assertRaisesRegex(RuntimeError, "cache lock timed out"),
        ):
            scanner_module._ensure_cached_archive(asset)

    def test_download_copy_enforces_archive_size_and_deadline(self) -> None:
        with patch.object(scanner_module, "MAX_RELEASE_ARCHIVE_BYTES", 4):
            exact = io.BytesIO()
            scanner_module._copy_download(
                io.BytesIO(b"1234"),
                exact,
                deadline=time.monotonic() + 5,
            )
            self.assertEqual(b"1234", exact.getvalue())
            with self.assertRaisesRegex(RuntimeError, "archive exceeds"):
                scanner_module._copy_download(
                    io.BytesIO(b"12345"),
                    io.BytesIO(),
                    deadline=time.monotonic() + 5,
                )
        with self.assertRaisesRegex(RuntimeError, "download timed out"):
            scanner_module._copy_download(
                io.BytesIO(b"x"),
                io.BytesIO(),
                deadline=time.monotonic() - 1,
            )

        class SlowSource(io.BytesIO):
            def read(self, size: int | None = -1) -> bytes:
                return super().read(size)

        clock = iter((0.0, 2.0))
        with (
            patch("scripts.verify_secret_scanner.time.monotonic", side_effect=lambda: next(clock)),
            self.assertRaisesRegex(RuntimeError, "download timed out"),
        ):
            scanner_module._copy_download(
                SlowSource(b"slow"),
                io.BytesIO(),
                deadline=1.0,
            )

        invalid_source = Mock()
        invalid_source.read.return_value = "not bytes"
        with self.assertRaisesRegex(RuntimeError, "invalid bytes"):
            scanner_module._copy_download(
                invalid_source,
                io.BytesIO(),
                deadline=time.monotonic() + 5,
            )

    def test_download_worker_is_isolated_and_parent_deadline_is_hard(self) -> None:
        archive = build_release_archive()
        asset = fixture_release_asset(archive)

        def complete(_command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            output = cast(BinaryIO, kwargs["stdout"])
            output.write(archive)
            environment = cast(dict[str, str], kwargs["env"])
            self.assertEqual(
                {"LANG": "C", "LC_ALL": "C", "PATH": os.defpath},
                environment,
            )
            self.assertTrue(kwargs["close_fds"])
            return subprocess.CompletedProcess(args=[], returncode=0)

        with (
            patch.dict(
                scanner_module.GITLEAKS_RELEASE_ASSETS,
                {("linux", "x64"): asset},
                clear=True,
            ),
            patch("scripts.verify_secret_scanner.subprocess.run", side_effect=complete) as run,
        ):
            destination = io.BytesIO()
            scanner_module._download_release_archive(
                asset,
                destination,
                deadline=time.monotonic() + 5,
            )
        command = run.call_args.args[0]
        self.assertEqual(sys.executable, command[0])
        self.assertEqual("-I", command[1])
        self.assertEqual(["--internal-download", "linux", "x64"], command[-3:])

        with (
            patch.dict(
                scanner_module.GITLEAKS_RELEASE_ASSETS,
                {("linux", "x64"): asset},
                clear=True,
            ),
            patch(
                "scripts.verify_secret_scanner.subprocess.run",
                side_effect=subprocess.TimeoutExpired("download", 1),
            ),
            self.assertRaisesRegex(RuntimeError, "could not complete"),
        ):
            scanner_module._download_release_archive(
                asset,
                io.BytesIO(),
                deadline=time.monotonic() + 1,
            )

        with self.assertRaisesRegex(RuntimeError, "asset is unsupported"):
            scanner_module._download_release_archive(
                asset,
                io.BytesIO(),
                deadline=time.monotonic() + 1,
            )

        with (
            patch.dict(
                scanner_module.GITLEAKS_RELEASE_ASSETS,
                {("linux", "x64"): asset},
                clear=True,
            ),
            patch(
                "scripts.verify_secret_scanner.subprocess.run",
                return_value=subprocess.CompletedProcess(args=[], returncode=1),
            ),
            self.assertRaisesRegex(RuntimeError, "download failed"),
        ):
            scanner_module._download_release_archive(
                asset,
                io.BytesIO(),
                deadline=time.monotonic() + 1,
            )

        def wrong_archive(
            _command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            cast(BinaryIO, kwargs["stdout"]).write(b"x" * len(archive))
            return subprocess.CompletedProcess(args=[], returncode=0)

        with (
            patch.dict(
                scanner_module.GITLEAKS_RELEASE_ASSETS,
                {("linux", "x64"): asset},
                clear=True,
            ),
            patch("scripts.verify_secret_scanner.subprocess.run", side_effect=wrong_archive),
            self.assertRaisesRegex(RuntimeError, "checksum"),
        ):
            scanner_module._download_release_archive(
                asset,
                io.BytesIO(),
                deadline=time.monotonic() + 1,
            )

    def test_download_response_length_and_proxy_policy_fail_closed(self) -> None:
        archive = b"archive"
        asset = scanner_module.ReleaseAsset(
            "fixture.tar.gz",
            hashlib.sha256(archive).hexdigest(),
            1,
            len(archive),
            1,
            "elf",
            62,
        )

        class FakeResponse(io.BytesIO):
            status = 200

            def __init__(self, payload: bytes, length: str | None) -> None:
                super().__init__(payload)
                self.headers = {} if length is None else {"Content-Length": length}

            def geturl(self) -> str:
                return "https://release-assets.githubusercontent.com/release/fixture"

            def __enter__(self) -> FakeResponse:
                return self

            def __exit__(self, *_args: object) -> None:
                self.close()

        for length in (None, str(len(archive))):
            opener = Mock()
            opener.open.return_value = FakeResponse(archive, length)
            with patch(
                "scripts.verify_secret_scanner.urllib.request.build_opener",
                return_value=opener,
            ) as build:
                output = io.BytesIO()
                scanner_module._download_release_archive_child(
                    asset,
                    output,
                    deadline=time.monotonic() + 5,
                )
                self.assertEqual(archive, output.getvalue())
            proxy_handler = build.call_args.args[0]
            self.assertEqual({}, proxy_handler.proxies)

        for length, message in (
            (str(len(archive) - 1), "length did not match"),
            (str(scanner_module.MAX_RELEASE_ARCHIVE_BYTES + 1), "archive exceeds"),
            ("invalid", "invalid length"),
        ):
            opener = Mock()
            opener.open.return_value = FakeResponse(archive, length)
            with (
                patch(
                    "scripts.verify_secret_scanner.urllib.request.build_opener",
                    return_value=opener,
                ),
                self.assertRaisesRegex(RuntimeError, message),
            ):
                scanner_module._download_release_archive_child(
                    asset,
                    io.BytesIO(),
                    deadline=time.monotonic() + 5,
                )

        for failure, message in (
            (
                urllib.error.HTTPError(
                    "https://github.com/release",
                    500,
                    "failed",
                    HTTPMessage(),
                    None,
                ),
                "download failed",
            ),
            (urllib.error.URLError("failed"), "could not complete"),
        ):
            opener = Mock()
            opener.open.side_effect = failure
            with (
                patch(
                    "scripts.verify_secret_scanner.urllib.request.build_opener",
                    return_value=opener,
                ),
                self.assertRaisesRegex(RuntimeError, message),
            ):
                scanner_module._download_release_archive_child(
                    asset,
                    io.BytesIO(),
                    deadline=time.monotonic() + 5,
                )

        failed_response = FakeResponse(archive, str(len(archive)))
        failed_response.status = 503
        opener = Mock()
        opener.open.return_value = failed_response
        with (
            patch(
                "scripts.verify_secret_scanner.urllib.request.build_opener",
                return_value=opener,
            ),
            self.assertRaisesRegex(RuntimeError, "download failed"),
        ):
            scanner_module._download_release_archive_child(
                asset,
                io.BytesIO(),
                deadline=time.monotonic() + 5,
            )

        self.assertEqual(3, scanner_module._ReleaseRedirectHandler.max_redirections)

    def test_release_redirects_are_https_and_host_bounded(self) -> None:
        accepted = (
            "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/archive.tar.gz",
            "https://release-assets.githubusercontent.com/github-production-release-asset/1/x"
            "?sp=r&sig=fixture",
        )
        rejected = (
            "http://github.com/gitleaks/gitleaks/releases/download/v8.30.1/archive.tar.gz",
            "https://github.com.evil.invalid/archive.tar.gz",
            "https://user@github.com/archive.tar.gz",
            "https://github.com:444/archive.tar.gz",
            "https://objects.githubusercontent.com/archive.tar.gz",
            "https://github.com:invalid/archive.tar.gz",
        )
        for url in accepted:
            with self.subTest(url=url):
                scanner_module._validate_release_url(url)
        for url in rejected:
            with (
                self.subTest(url=url),
                self.assertRaisesRegex(RuntimeError, "unsafe secret scanner release URL"),
            ):
                scanner_module._validate_release_url(url)

    def test_redirect_chain_is_bounded_and_never_forwards_credentials(self) -> None:
        handler = scanner_module._ReleaseRedirectHandler()
        handler.parent = Mock()
        request = urllib.request.Request(
            "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/archive.tar.gz",
            headers={"Authorization": "secret", "Cookie": "session", "Accept": "fixture"},
        )
        redirected = handler.redirect_request(
            request,
            io.BytesIO(),
            302,
            "Found",
            HTTPMessage(),
            "https://release-assets.githubusercontent.com/asset",
        )
        self.assertIsNotNone(redirected)
        assert redirected is not None
        self.assertNotIn("Authorization", redirected.headers)
        self.assertNotIn("Cookie", redirected.headers)
        self.assertEqual("fixture", redirected.headers["Accept"])

        current = request
        for redirect_number in range(scanner_module.MAX_RELEASE_REDIRECTS):
            current.timeout = 1
            response = io.BytesIO()
            target = f"https://release-assets.githubusercontent.com/asset-{redirect_number}"
            headers = HTTPMessage()
            headers["Location"] = target
            handler.http_error_302(current, response, 302, "Found", headers)
            current = handler.parent.open.call_args.args[0]
        current.timeout = 1
        headers = HTTPMessage()
        headers["Location"] = "https://release-assets.githubusercontent.com/asset-4"
        with self.assertRaises(urllib.error.HTTPError):
            handler.http_error_302(
                current,
                io.BytesIO(),
                302,
                "Found",
                headers,
            )

        looping = urllib.request.Request(
            "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/archive.tar.gz"
        )
        for _ in range(scanner_module.MAX_RELEASE_REDIRECTS):
            looping.timeout = 1
            headers = HTTPMessage()
            headers["Location"] = "https://release-assets.githubusercontent.com/repeat"
            handler.http_error_302(
                looping,
                io.BytesIO(),
                302,
                "Found",
                headers,
            )
            looping = handler.parent.open.call_args.args[0]
        looping.timeout = 1
        headers = HTTPMessage()
        headers["Location"] = "https://release-assets.githubusercontent.com/repeat"
        with self.assertRaises(urllib.error.HTTPError):
            handler.http_error_302(
                looping,
                io.BytesIO(),
                302,
                "Found",
                headers,
            )

    def test_archive_size_wrong_hash_and_nonregular_cache_fail_closed(self) -> None:
        archive = build_release_archive()
        with tempfile.TemporaryDirectory(prefix="cairnvm-archive-validation-test-") as temporary:
            path = Path(temporary) / "archive.tar.gz"
            path.write_bytes(archive)
            path.chmod(0o600)
            with (
                self.assertRaisesRegex(RuntimeError, "checksum"),
                scanner_module._open_verified_archive(path, "0" * 64),
            ):
                pass
            with (
                patch.object(scanner_module, "MAX_RELEASE_ARCHIVE_BYTES", len(archive)),
                scanner_module._open_verified_archive(
                    path, hashlib.sha256(archive).hexdigest()
                ) as opened,
            ):
                self.assertEqual(archive, opened.read())
            with (
                patch.object(scanner_module, "MAX_RELEASE_ARCHIVE_BYTES", len(archive) - 1),
                self.assertRaisesRegex(RuntimeError, "archive exceeds"),
                scanner_module._open_verified_archive(path, hashlib.sha256(archive).hexdigest()),
            ):
                pass
            path.unlink()
            path.mkdir()
            with (
                self.assertRaisesRegex(RuntimeError, "regular file"),
                scanner_module._open_verified_archive(path, hashlib.sha256(archive).hexdigest()),
            ):
                pass

    def test_archive_rejects_malformed_truncated_and_unexpected_shapes(self) -> None:
        asset = fixture_release_asset(build_release_archive())
        scanner = tarfile.TarInfo("gitleaks")
        scanner.mode = 0o755
        scanner.size = 1
        duplicate = tarfile.TarInfo("gitleaks")
        duplicate.mode = 0o755
        duplicate.size = 1
        missing = tarfile.TarInfo("README.md")
        missing.mode = 0o644
        missing.size = 4
        symlink = tarfile.TarInfo("gitleaks")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "elsewhere"
        hardlink = tarfile.TarInfo("gitleaks")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "elsewhere"
        directory = tarfile.TarInfo("gitleaks")
        directory.type = tarfile.DIRTYPE
        archives = {
            "malformed": b"not a gzip tar",
            "truncated": build_release_archive()[:31],
            "tarbomb": build_release_archive([(missing, b"docs"), (scanner, b"x")] * 20),
            "symlink": build_release_archive([(symlink, None)]),
            "hardlink": build_release_archive([(hardlink, None)]),
            "duplicate": build_release_archive([(scanner, b"x"), (duplicate, b"y")]),
            "missing": build_release_archive([(missing, b"docs")]),
            "nonregular": build_release_archive([(directory, None)]),
        }
        with tempfile.TemporaryDirectory(prefix="cairnvm-tar-shape-test-") as temporary:
            base = Path(temporary)
            for name, archive in archives.items():
                destination = base / name
                destination.mkdir()
                rejected_during_decompression = name in {"malformed", "truncated"}
                candidate_asset = (
                    asset if rejected_during_decompression else fixture_release_asset(archive)
                )
                if not rejected_during_decompression:
                    self.assertEqual(
                        len(zlib.decompress(archive, 16 + zlib.MAX_WBITS)),
                        candidate_asset.tar_size,
                    )
                with (
                    self.subTest(name=name),
                    patch.object(
                        scanner_module,
                        "_validate_raw_tar",
                        wraps=scanner_module._validate_raw_tar,
                    ) as validate_raw_tar,
                    self.assertRaisesRegex(RuntimeError, "invalid secret scanner archive"),
                ):
                    scanner_module._extract_scanner(
                        io.BytesIO(archive), destination, candidate_asset
                    )
                if rejected_during_decompression:
                    validate_raw_tar.assert_not_called()
                else:
                    validate_raw_tar.assert_called_once()

    def test_archive_rejects_trailing_concatenated_and_raw_header_extensions(self) -> None:
        archive = build_release_archive()
        asset = fixture_release_asset(archive)
        pax_entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
        for name, mode, payload in (
            ("LICENSE", 0o644, b"L" * 1_069),
            ("README.md", 0o644, b"R" * 29_998),
            ("gitleaks", 0o755, FIXTURE_SCANNER_BYTES),
        ):
            member = tarfile.TarInfo(name)
            member.mode = mode
            member.size = len(payload)
            if name == "gitleaks":
                member.pax_headers = {"comment": "rejected"}
            pax_entries.append((member, payload))
        pax_output = io.BytesIO()
        with tarfile.open(fileobj=pax_output, mode="w:gz", format=tarfile.PAX_FORMAT) as bundle:
            for member, entry_payload in pax_entries:
                bundle.addfile(
                    member,
                    io.BytesIO(entry_payload) if entry_payload is not None else None,
                )

        gnu_member = tarfile.TarInfo("g" * 101)
        gnu_member.mode = 0o755
        gnu_member.size = len(FIXTURE_SCANNER_BYTES)
        gnu_output = io.BytesIO()
        with tarfile.open(fileobj=gnu_output, mode="w:gz", format=tarfile.GNU_FORMAT) as bundle:
            bundle.addfile(gnu_member, io.BytesIO(FIXTURE_SCANNER_BYTES))

        cases = {
            "trailing": archive + b"trailing",
            "concatenated": archive + archive,
            "pax": pax_output.getvalue(),
            "gnu-longname": gnu_output.getvalue(),
            "sparse": mutate_tar_header(archive, 2, 156, b"S"),
            "fifo": mutate_tar_header(archive, 2, 156, tarfile.FIFOTYPE),
            "device": mutate_tar_header(archive, 2, 156, tarfile.CHRTYPE),
        }
        with tempfile.TemporaryDirectory(prefix="cairnvm-archive-extension-test-") as temporary:
            base = Path(temporary)
            for name, candidate in cases.items():
                destination = base / name
                destination.mkdir()
                rejected_during_decompression = name in {"trailing", "concatenated"}
                candidate_asset = (
                    asset if rejected_during_decompression else fixture_release_asset(candidate)
                )
                if not rejected_during_decompression:
                    self.assertEqual(
                        len(zlib.decompress(candidate, 16 + zlib.MAX_WBITS)),
                        candidate_asset.tar_size,
                    )
                with (
                    self.subTest(name=name),
                    patch.object(
                        scanner_module,
                        "_validate_raw_tar",
                        wraps=scanner_module._validate_raw_tar,
                    ) as validate_raw_tar,
                    self.assertRaisesRegex(RuntimeError, "invalid secret scanner archive"),
                ):
                    scanner_module._extract_scanner(
                        io.BytesIO(candidate), destination, candidate_asset
                    )
                if rejected_during_decompression:
                    validate_raw_tar.assert_not_called()
                else:
                    validate_raw_tar.assert_called_once()

    def test_archive_rejects_unsafe_colliding_and_unexpected_inventory(self) -> None:
        archive = build_release_archive()
        nonzero_padding = bytearray(gzip.decompress(archive))
        nonzero_padding[512 + 1_069] = 1
        unsafe_headers = {
            "absolute": mutate_tar_header(archive, 2, 0, b"/gitleaks"),
            "parent": mutate_tar_header(archive, 2, 0, b"../gitleaks"),
            "backslash": mutate_tar_header(archive, 2, 0, b"git\\leaks"),
            "nul": mutate_tar_header(archive, 2, 0, b"git\0evil"),
            "wrong-license-mode": mutate_tar_header(archive, 0, 100, b"0000600\0"),
            "wrong-ustar-magic": mutate_tar_header(archive, 0, 257, b"badtar"),
            "nonzero-padding": gzip.compress(bytes(nonzero_padding), mtime=0),
        }

        def named_entries(names: tuple[str, str, str]) -> bytes:
            selected: list[tuple[tarfile.TarInfo, bytes | None]] = []
            for name in names:
                member = tarfile.TarInfo(name)
                member.mode = 0o644
                member.size = 1
                selected.append((member, b"x"))
            return build_release_archive(selected)

        cases = {
            **unsafe_headers,
            "case-collision": named_entries(("Readme", "README", "gitleaks")),
            "nfc-collision": named_entries(("é", "e\u0301", "gitleaks")),
        }
        license_member = tarfile.TarInfo("LICENSE")
        license_member.mode = 0o644
        license_member.size = 1_069
        readme_member = tarfile.TarInfo("README.md")
        readme_member.mode = 0o644
        readme_member.size = 29_998
        scanner_member = tarfile.TarInfo("gitleaks")
        scanner_member.mode = 0o755
        scanner_member.size = len(FIXTURE_SCANNER_BYTES)
        cases["wrong-order"] = build_release_archive(
            [
                (readme_member, b"R" * readme_member.size),
                (license_member, b"L" * license_member.size),
                (scanner_member, FIXTURE_SCANNER_BYTES),
            ]
        )
        with tempfile.TemporaryDirectory(prefix="cairnvm-unsafe-inventory-test-") as temporary:
            base = Path(temporary)
            for name, candidate in cases.items():
                destination = base / name
                destination.mkdir()
                candidate_asset = fixture_release_asset(candidate)
                self.assertEqual(
                    len(zlib.decompress(candidate, 16 + zlib.MAX_WBITS)),
                    candidate_asset.tar_size,
                )
                with (
                    self.subTest(name=name),
                    patch.object(
                        scanner_module,
                        "_validate_raw_tar",
                        wraps=scanner_module._validate_raw_tar,
                    ) as validate_raw_tar,
                    self.assertRaisesRegex(RuntimeError, "invalid secret scanner archive"),
                ):
                    scanner_module._extract_scanner(
                        io.BytesIO(candidate), destination, candidate_asset
                    )
                validate_raw_tar.assert_called_once()

    def test_archive_decompressed_total_is_bounded(self) -> None:
        archive = build_release_archive()
        asset = fixture_release_asset(archive)
        with (
            tempfile.TemporaryDirectory(prefix="cairnvm-decompressed-limit-test-") as temporary,
            patch.object(
                scanner_module,
                "MAX_RELEASE_DECOMPRESSED_BYTES",
                asset.tar_size - 1,
            ),
            self.assertRaisesRegex(RuntimeError, "invalid secret scanner archive"),
        ):
            scanner_module._extract_scanner(io.BytesIO(archive), Path(temporary), asset)

    def test_archive_rejects_an_oversized_scanner_member(self) -> None:
        archive = build_release_archive()
        asset = fixture_release_asset(archive)
        with (
            tempfile.TemporaryDirectory(prefix="cairnvm-oversized-member-test-") as temporary,
            patch.object(
                scanner_module,
                "MAX_GITLEAKS_BINARY_BYTES",
                len(FIXTURE_SCANNER_BYTES) - 1,
            ),
            self.assertRaisesRegex(RuntimeError, "invalid secret scanner archive"),
        ):
            scanner_module._extract_scanner(io.BytesIO(archive), Path(temporary), asset)

    def test_binary_headers_and_raw_tar_parser_fail_closed(self) -> None:
        macho_header = b"\xcf\xfa\xed\xfe" + (0x0100000C).to_bytes(4, "little") + bytes(24)
        macho_asset = scanner_module.ReleaseAsset(
            "fixture", "0" * 64, 32, 1, 1, "macho", 0x0100000C
        )
        scanner_module._validate_binary_header(io.BytesIO(macho_header), macho_asset)

        cases = (
            (b"invalid", macho_asset),
            (
                FIXTURE_SCANNER_BYTES,
                scanner_module.ReleaseAsset("fixture", "0" * 64, 64, 1, 1, "elf", 183),
            ),
            (
                FIXTURE_SCANNER_BYTES,
                scanner_module.ReleaseAsset("fixture", "0" * 64, 64, 1, 1, "unknown", 62),
            ),
        )
        for header, candidate_asset in cases:
            with (
                self.subTest(binary_format=candidate_asset.binary_format),
                self.assertRaisesRegex(RuntimeError, "invalid secret scanner archive"),
            ):
                scanner_module._validate_binary_header(io.BytesIO(header), candidate_asset)

        with self.assertRaisesRegex(RuntimeError, "invalid secret scanner archive"):
            scanner_module._parse_tar_octal(b"not-octal")
        with self.assertRaisesRegex(RuntimeError, "invalid secret scanner archive"):
            scanner_module._parse_tar_name(b"\xff")

        archive = build_release_archive()
        asset = fixture_release_asset(archive)
        raw = gzip.decompress(archive)
        malformed_tar_streams = {
            "short-header": raw[:1],
            "bad-checksum": bytes([raw[0] ^ 1]) + raw[1:],
            "short-payload": raw[:522],
        }
        first_terminator = 512 + 1_536 + 512 + 30_208 + 512 + 512
        bad_second_terminator = bytearray(raw)
        bad_second_terminator[first_terminator + 512] = 1
        malformed_tar_streams["bad-second-terminator"] = bytes(bad_second_terminator)
        trailing_tar_data = bytearray(raw)
        trailing_tar_data[first_terminator + 1_024] = 1
        malformed_tar_streams["trailing-tar-data"] = bytes(trailing_tar_data)
        for name, candidate in malformed_tar_streams.items():
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(RuntimeError, "invalid secret scanner archive"),
            ):
                scanner_module._validate_raw_tar(io.BytesIO(candidate), asset)

    def test_internal_download_entrypoint_is_fail_closed(self) -> None:
        self.assertEqual(2, scanner_module._internal_download_main([]))
        asset = scanner_module.GITLEAKS_RELEASE_ASSETS[("linux", "x64")]
        with patch.object(scanner_module, "_download_release_archive_child") as download:
            self.assertEqual(0, scanner_module._internal_download_main(["linux", "x64"]))
        self.assertIs(asset, download.call_args.args[0])

        with patch.object(scanner_module, "_download_release_archive_child") as download:
            self.assertEqual(2, scanner_module._internal_download_main(["plan9", "mips"]))
        download.assert_not_called()

    def test_archive_is_rehashed_each_run_and_persistent_binary_is_ignored(self) -> None:
        archive = build_release_archive()
        asset = fixture_release_asset(archive)
        with tempfile.TemporaryDirectory(prefix="cairnvm-rehash-test-") as temporary:
            base = Path(temporary)
            path = base / asset.filename
            path.write_bytes(archive)
            path.chmod(0o600)
            persistent = base / "gitleaks"
            persistent.write_bytes(b"substituted")
            persistent.chmod(0o700)
            with scanner_module._temporary_scanner(path, asset) as first:
                first_path = first
                self.assertEqual(FIXTURE_SCANNER_BYTES, first.read_bytes())
                self.assertNotEqual(persistent, first)
                self.assertEqual(0o700, first.stat().st_mode & 0o777)
            self.assertFalse(first_path.exists())
            with scanner_module._temporary_scanner(path, asset) as second:
                self.assertNotEqual(first_path, second)
                self.assertEqual(FIXTURE_SCANNER_BYTES, second.read_bytes())
            changed = bytearray(archive)
            changed[-1] ^= 1
            path.write_bytes(changed)
            with (
                self.assertRaisesRegex(RuntimeError, "checksum"),
                scanner_module._temporary_scanner(path, asset),
            ):
                pass

    def test_scanner_environment_is_fully_isolated_from_ambient_controls(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="cairnvm-scanner-env-test-") as temporary,
            patch.dict(
                os.environ,
                {
                    "GITLEAKS_CONFIG": "/weakened.toml",
                    "HTTPS_PROXY": "http://proxy.invalid",
                    "SSL_CERT_FILE": "/untrusted.pem",
                    "LD_PRELOAD": "/injected.so",
                    "DYLD_INSERT_LIBRARIES": "/injected.dylib",
                    "PATH": "/hostile/path",
                    "HOME": "/hostile/home",
                    "XDG_CONFIG_HOME": "/hostile/config",
                },
            ),
        ):
            isolated = Path(temporary)
            environment = scanner_module.scanner_environment(isolated)

        self.assertEqual(
            {
                "HOME": str(isolated),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.defpath,
                "TMPDIR": str(isolated),
                "XDG_CONFIG_HOME": str(isolated),
            },
            environment,
        )

    def test_module_states_same_uid_cache_mutation_exclusion(self) -> None:
        documentation = inspect.getdoc(scanner_module)
        self.assertIsNotNone(documentation)
        assert documentation is not None
        self.assertIn("Benign concurrent cold starts are serialized", documentation)
        self.assertIn("hostile same-UID process", documentation)

    @patch("scripts.verify_secret_scanner.subprocess.run")
    def test_version_check_requires_exact_locked_release(self, run: Mock) -> None:
        run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"8.30.1\n")
        with tempfile.TemporaryDirectory(prefix="cairnvm-version-test-") as temporary:
            isolated = Path(temporary)
            scanner_module.verify_version("/private/gitleaks", isolated)
        self.assertEqual(["/private/gitleaks", "version"], run.call_args.args[0])
        self.assertTrue(run.call_args.kwargs["close_fds"])
        self.assertEqual(scanner_module.scanner_environment(isolated), run.call_args.kwargs["env"])

        for result in (
            subprocess.CompletedProcess(args=[], returncode=0, stdout=b"8.30.0\n"),
            subprocess.CompletedProcess(args=[], returncode=2, stdout=b"8.30.1\n"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout=b"\xff"),
        ):
            with self.subTest(result=result):
                run.return_value = result
                with self.assertRaisesRegex(RuntimeError, "version"):
                    scanner_module.verify_version("/private/gitleaks", Path("/private"))

    def test_fresh_executable_is_removed_when_validation_fails(self) -> None:
        archive = build_release_archive()
        asset = fixture_release_asset(archive)

        def download(
            _asset: scanner_module.ReleaseAsset,
            destination: BinaryIO,
            *,
            deadline: float,
        ) -> None:
            self.assertGreater(deadline, time.monotonic())
            destination.write(archive)

        with tempfile.TemporaryDirectory(prefix="cairnvm-exec-cleanup-test-") as temporary:
            cache_home = Path(temporary)
            stderr = io.StringIO()
            with (
                patch.object(scanner_module, "GITLEAKS_CACHE_HOME", cache_home),
                patch.object(scanner_module, "_select_release_asset", return_value=asset),
                patch.object(scanner_module, "_download_release_archive", side_effect=download),
                patch.object(
                    scanner_module,
                    "verify_version",
                    side_effect=RuntimeError("version failed"),
                ),
                patch("sys.stderr", stderr),
            ):
                self.assertEqual(2, main())
            cache_root = cache_home / ".cache" / "cairnvm" / "gitleaks" / "v8.30.1"
            self.assertEqual([], list(cache_root.glob(".gitleaks-exec-*")))
            self.assertEqual("version failed\n", stderr.getvalue())

    def test_main_documents_both_supported_scan_scopes(self) -> None:
        documentation = inspect.getdoc(main)

        self.assertIsNotNone(documentation)
        assert documentation is not None
        self.assertIn("selected staged or history scope", documentation)

    def test_canary_is_generated_as_a_rule_matching_high_entropy_token(self) -> None:
        canary = build_canary()

        self.assertTrue(canary.startswith("ghp_"))
        self.assertEqual(40, len(canary))
        self.assertGreater(len(set(canary[4:])), 20)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", canary.lower())

    @patch("scripts.verify_secret_scanner.subprocess.run")
    def test_canary_proves_archive_and_decode_scanning(self, run: Mock) -> None:
        policy_content = ""

        def inspect_canary(
            command: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            nonlocal policy_content
            archive = Path(command[-1])
            with zipfile.ZipFile(archive) as bundle:
                encoded = bundle.read("canary.txt")
            self.assertEqual(build_canary(), base64.b64decode(encoded).decode("ascii"))
            policy_content = Path(command[3]).read_text(encoding="utf-8")
            return subprocess.CompletedProcess(args=command, returncode=1)

        run.side_effect = inspect_canary

        verify_canary("/usr/bin/gitleaks")

        command = run.call_args.args[0]
        self.assertEqual(
            [
                "/usr/bin/gitleaks",
                "dir",
                "--config",
                command[3],
                "--redact",
                "--no-banner",
                "--max-archive-depth",
                "1",
                "--max-decode-depth",
                "1",
            ],
            command[:-1],
        )
        self.assertEqual(
            "[extend]\nuseDefault = true\n",
            policy_content,
        )

    @patch("scripts.verify_secret_scanner.subprocess.run")
    def test_canary_sanitizes_ambient_gitleaks_configuration(self, run: Mock) -> None:
        run.return_value = subprocess.CompletedProcess(args=[], returncode=1)

        with patch.dict(
            "os.environ",
            {
                "CAIRNVM_TEST_PRESERVED": "yes",
                "GITLEAKS_CONFIG": "ambient-weak.toml",
                "GITLEAKS_CONFIG_TOML": "[allowlist]",
            },
        ):
            verify_canary("/usr/bin/gitleaks")

        scanner_environment = run.call_args.kwargs["env"]
        self.assertNotIn("CAIRNVM_TEST_PRESERVED", scanner_environment)
        self.assertNotIn("GITLEAKS_CONFIG", scanner_environment)
        self.assertNotIn("GITLEAKS_CONFIG_TOML", scanner_environment)

    @patch("scripts.verify_secret_scanner.subprocess.run")
    def test_accepts_the_scanner_only_when_it_rejects_the_canary(self, run: Mock) -> None:
        run.return_value = subprocess.CompletedProcess(args=[], returncode=1)

        verify_canary("/usr/bin/gitleaks")

    @patch("scripts.verify_secret_scanner.subprocess.run")
    def test_fails_closed_when_the_scanner_misses_the_canary(self, run: Mock) -> None:
        run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        with self.assertRaisesRegex(RuntimeError, "failed to detect"):
            verify_canary("/usr/bin/gitleaks")

    @patch(
        "scripts.verify_secret_scanner.subprocess.run",
        side_effect=subprocess.TimeoutExpired("gitleaks", 30),
    )
    def test_fails_closed_when_the_canary_scan_cannot_complete(self, _run: Mock) -> None:
        with self.assertRaisesRegex(RuntimeError, "canary could not complete"):
            verify_canary("/usr/bin/gitleaks")

    @patch("scripts.verify_secret_scanner.subprocess.run")
    def test_unknown_scan_scope_fails_closed(self, run: Mock) -> None:
        with self.assertRaisesRegex(RuntimeError, "unsupported secret scan scope"):
            scan_repository("/usr/bin/gitleaks", scope="unexpected")

        run.assert_not_called()

    @patch(
        "scripts.verify_secret_scanner._temporary_cached_scanner",
        side_effect=RuntimeError("release unavailable"),
    )
    def test_main_reports_release_acquisition_failure(self, _scanner: Mock) -> None:
        stderr = io.StringIO()

        with patch("sys.stderr", stderr):
            self.assertEqual(2, main())

        self.assertEqual("release unavailable\n", stderr.getvalue())

    @patch("scripts.verify_secret_scanner.scan_repository", return_value=0)
    @patch("scripts.verify_secret_scanner.verify_canary")
    @patch("scripts.verify_secret_scanner.verify_version")
    def test_main_verifies_then_uses_the_selected_scope(
        self,
        version: Mock,
        canary: Mock,
        scan: Mock,
    ) -> None:
        scanner = Path(__file__).resolve()

        @contextmanager
        def selected_scanner(_asset: scanner_module.ReleaseAsset) -> Iterator[Path]:
            yield scanner

        with (
            patch.object(scanner_module, "_temporary_cached_scanner", selected_scanner),
            patch.dict("os.environ", {"CAIRNVM_SECRET_SCAN_SCOPE": "history"}),
        ):
            self.assertEqual(0, main())

        version.assert_called_once_with(str(scanner), scanner.parent)
        canary.assert_called_once_with(str(scanner))
        scan.assert_called_once_with(scanner, scope="history", repository=REPOSITORY_ROOT)

    @patch(
        "scripts.verify_secret_scanner.verify_canary",
        side_effect=RuntimeError("canary failed"),
    )
    @patch("scripts.verify_secret_scanner.verify_version")
    def test_main_reports_validation_failures(
        self,
        _version: Mock,
        _canary: Mock,
    ) -> None:
        stderr = io.StringIO()
        scanner = Path(__file__).resolve()

        @contextmanager
        def selected_scanner(_asset: scanner_module.ReleaseAsset) -> Iterator[Path]:
            yield scanner

        with (
            patch.object(scanner_module, "_temporary_cached_scanner", selected_scanner),
            patch("sys.stderr", stderr),
        ):
            self.assertEqual(2, main())

        self.assertEqual("canary failed\n", stderr.getvalue())


class SecretScannerFailClosedTests(unittest.TestCase):
    def test_expired_repository_deadline_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "snapshot timed out"):
            scanner_module._remaining_timeout(time.monotonic() - 1, 30)

    def test_git_discovery_failures_are_redacted(self) -> None:
        with (
            patch("scripts.verify_secret_scanner.subprocess.run", side_effect=OSError("sensitive")),
            self.assertRaisesRegex(RuntimeError, "resolve the repository boundary"),
        ):
            scanner_module._run_discovery_git(
                "/usr/bin/git",
                ROOT,
                ["rev-parse"],
                environment={},
                deadline=time.monotonic() + 5,
            )

        failed = subprocess.CompletedProcess[bytes](args=[], returncode=1, stdout=b"", stderr=b"")
        with (
            patch("scripts.verify_secret_scanner.subprocess.run", return_value=failed),
            self.assertRaisesRegex(RuntimeError, "resolve the repository boundary"),
        ):
            scanner_module._run_discovery_git(
                "/usr/bin/git",
                ROOT,
                ["rev-parse"],
                environment={},
                deadline=time.monotonic() + 5,
            )

    def test_repository_open_rejects_missing_paths_and_git(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-open-boundary-test-") as temporary:
            temporary_path = Path(temporary)
            missing = temporary_path / "missing"
            with self.assertRaisesRegex(RuntimeError, "repository is unavailable"):
                scanner_module._open_repository(
                    missing,
                    isolated_home=temporary_path,
                    deadline=time.monotonic() + 5,
                )

            regular_file = temporary_path / "file"
            regular_file.write_text("not a repository", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "repository is unavailable"):
                scanner_module._open_repository(
                    regular_file,
                    isolated_home=temporary_path,
                    deadline=time.monotonic() + 5,
                )

            with (
                patch("scripts.verify_secret_scanner.shutil.which", return_value=None),
                self.assertRaisesRegex(RuntimeError, "Git is unavailable"),
            ):
                scanner_module._open_repository(
                    temporary_path,
                    isolated_home=temporary_path,
                    deadline=time.monotonic() + 5,
                )

    def test_bound_git_and_captured_stdout_fail_closed(self) -> None:
        repository = scanner_module.GitRepository("/usr/bin/git", ROOT, ROOT / ".git", {})
        failed = subprocess.CompletedProcess[bytes](args=[], returncode=1, stdout=b"", stderr=b"")
        with (
            patch("scripts.verify_secret_scanner.subprocess.run", return_value=failed),
            self.assertRaisesRegex(RuntimeError, "capture repository content"),
        ):
            scanner_module._run_bound_git(
                repository,
                ["write-tree"],
                deadline=time.monotonic() + 5,
            )

        without_output = subprocess.CompletedProcess[bytes](args=[], returncode=0)
        with self.assertRaisesRegex(RuntimeError, "captured repository metadata"):
            scanner_module._captured_stdout(without_output)

    def test_tree_identifiers_and_paths_are_validated(self) -> None:
        for invalid_object_id in ("short", "z" * 40):
            with (
                self.subTest(object_id=invalid_object_id),
                self.assertRaisesRegex(RuntimeError, "invalid object identifier"),
            ):
                scanner_module._validate_object_id(invalid_object_id)

        for invalid_path in (b"", b"/absolute", b"back\\slash", b"\xff"):
            with (
                self.subTest(path=invalid_path),
                self.assertRaisesRegex(RuntimeError, "path"),
            ):
                scanner_module._validate_entry_path(invalid_path, set())

        collision_keys: set[str] = set()
        self.assertEqual(
            "Name.txt", scanner_module._validate_entry_path(b"Name.txt", collision_keys)
        )
        with self.assertRaisesRegex(RuntimeError, "colliding paths"):
            scanner_module._validate_entry_path(b"name.txt", collision_keys)

    def test_malformed_and_oversized_tree_listings_are_rejected(self) -> None:
        repository = scanner_module.GitRepository("/usr/bin/git", ROOT, ROOT / ".git", {})
        tree = "a" * 40
        malformed = subprocess.CompletedProcess[bytes](
            args=[], returncode=0, stdout=b"not-a-tree-record\0", stderr=b""
        )
        with (
            patch.object(scanner_module, "_run_bound_git", return_value=malformed),
            self.assertRaisesRegex(RuntimeError, "malformed tree listing"),
        ):
            scanner_module._list_tree(repository, tree, deadline=time.monotonic() + 5)

        symlink = subprocess.CompletedProcess[bytes](
            args=[],
            returncode=0,
            stdout=f"120000 blob {'b' * 40} 6\tlink\0".encode(),
            stderr=b"",
        )
        with (
            patch.object(scanner_module, "_run_bound_git", return_value=symlink),
            self.assertRaisesRegex(RuntimeError, "unsupported Git tree entry"),
        ):
            scanner_module._list_tree(repository, tree, deadline=time.monotonic() + 5)

        oversized = subprocess.CompletedProcess[bytes](
            args=[],
            returncode=0,
            stdout=(
                f"100644 blob {'b' * 40} {scanner_module.MAX_SNAPSHOT_BYTES + 1}\tlarge\0"
            ).encode(),
            stderr=b"",
        )
        with (
            patch.object(scanner_module, "_run_bound_git", return_value=oversized),
            self.assertRaisesRegex(RuntimeError, "snapshot limit"),
        ):
            scanner_module._list_tree(repository, tree, deadline=time.monotonic() + 5)

    def test_empty_history_and_scanner_internal_errors_fail_closed(self) -> None:
        repository = scanner_module.GitRepository("/usr/bin/git", ROOT, ROOT / ".git", {})
        empty = subprocess.CompletedProcess[bytes](args=[], returncode=0, stdout=b"", stderr=b"")
        with (
            patch.object(scanner_module, "_run_bound_git", return_value=empty),
            self.assertRaisesRegex(RuntimeError, "no commit trees"),
        ):
            scanner_module._captured_trees(
                repository, scope="history", deadline=time.monotonic() + 5
            )

        with tempfile.TemporaryDirectory(prefix="cairnvm-scan-error-test-") as temporary:
            temporary_path = Path(temporary)
            policy = temporary_path / "policy"
            snapshot = temporary_path / "snapshot"
            policy.mkdir()
            snapshot.mkdir()
            with (
                patch(
                    "scripts.verify_secret_scanner.subprocess.run",
                    side_effect=OSError("sensitive"),
                ),
                self.assertRaisesRegex(RuntimeError, "could not scan repository content"),
            ):
                scanner_module._scan_snapshot(
                    "/usr/bin/gitleaks",
                    snapshot,
                    policy,
                    deadline=time.monotonic() + 5,
                )

            internal_error = subprocess.CompletedProcess[bytes](args=[], returncode=2)
            with (
                patch(
                    "scripts.verify_secret_scanner.subprocess.run",
                    return_value=internal_error,
                ),
                self.assertRaisesRegex(RuntimeError, "failed while scanning"),
            ):
                scanner_module._scan_snapshot(
                    "/usr/bin/gitleaks",
                    snapshot,
                    policy,
                    deadline=time.monotonic() + 5,
                )


class SecretScannerRepositorySnapshotTests(unittest.TestCase):
    def test_materialization_rejects_same_size_blob_substitution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-blob-substitution-test-") as temporary:
            repository = Path(temporary)
            initialize_repository(repository)
            source = repository / "source.txt"
            source.write_text("trusted-bytes", encoding="utf-8")
            run_git(repository, "add", "source.txt")
            git = shutil.which("git")
            self.assertIsNotNone(git)
            assert git is not None
            tree = subprocess.run(  # noqa: S603  # Git is resolved from the test environment.
                [git, "-C", str(repository), "write-tree"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            destination = repository / "materialized"
            deadline = time.monotonic() + 30
            isolated_home = repository / "isolated-home"
            isolated_home.mkdir()
            git_repository = scanner_module._open_repository(
                repository, isolated_home=isolated_home, deadline=deadline
            )
            original_run = scanner_module._run_bound_git

            def substitute_blob(
                bound_repository: scanner_module.GitRepository,
                arguments: list[str],
                *,
                deadline: float,
                stdout: int | BinaryIO = subprocess.PIPE,
            ) -> subprocess.CompletedProcess[bytes]:
                if arguments[:2] == ["cat-file", "blob"]:
                    self.assertTrue(hasattr(stdout, "write"))
                    cast(BinaryIO, stdout).write(b"altered-bytes")
                    return subprocess.CompletedProcess(args=[], returncode=0, stdout=None)
                return original_run(
                    bound_repository,
                    arguments,
                    deadline=deadline,
                    stdout=stdout,
                )

            with (
                patch.object(scanner_module, "_run_bound_git", side_effect=substitute_blob),
                self.assertRaisesRegex(RuntimeError, "object identifier"),
            ):
                scanner_module._materialize_tree(
                    git_repository,
                    tree,
                    destination,
                    deadline=deadline,
                )

    def test_staged_scope_rejects_index_drift_during_scan(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-index-drift-test-") as temporary:
            repository = Path(temporary)
            initialize_repository(repository)
            (repository / "original.txt").write_text("original", encoding="utf-8")
            run_git(repository, "add", "original.txt")

            def mutate_index(*_args: object, **_kwargs: object) -> int:
                (repository / "drift.txt").write_text("drift", encoding="utf-8")
                run_git(repository, "add", "drift.txt")
                return 0

            with (
                patch.object(scanner_module, "_scan_snapshot", side_effect=mutate_index),
                self.assertRaisesRegex(RuntimeError, "index changed during secret scanning"),
            ):
                scan_repository("/usr/bin/gitleaks", scope="staged", repository=repository)

    def test_staged_scope_ignores_an_ambient_empty_alternate_index(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-canonical-index-test-") as temporary:
            repository = Path(temporary)
            initialize_repository(repository)
            scanner = write_fake_scanner(repository)
            (repository / "secret.txt").write_text(build_canary(), encoding="utf-8")
            run_git(repository, "add", "secret.txt")
            alternate_index = repository / "empty-index"
            alternate_environment = os.environ.copy()
            alternate_environment["GIT_INDEX_FILE"] = str(alternate_index)
            run_git(repository, "read-tree", "--empty", environment=alternate_environment)

            with patch.dict(os.environ, {"GIT_INDEX_FILE": str(alternate_index)}):
                result = scan_repository(scanner, scope="staged", repository=repository)

        self.assertEqual(1, result)

    def test_staged_scope_scans_the_full_index_after_commit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-full-index-test-") as temporary:
            repository = Path(temporary)
            initialize_repository(repository)
            scanner = write_fake_scanner(repository)
            (repository / "secret.txt").write_text(build_canary(), encoding="utf-8")
            run_git(repository, "add", "secret.txt")
            run_git(repository, "commit", "--quiet", "-m", "fixture")

            result = scan_repository(scanner, scope="staged", repository=repository)

        self.assertEqual(1, result)

    def test_git_attributes_and_ignore_files_cannot_hide_staged_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-attributes-test-") as temporary:
            repository = Path(temporary)
            initialize_repository(repository)
            scanner = write_fake_scanner(repository)
            (repository / ".gitattributes").write_text(
                "secret.txt -diff\n*.txt binary\n", encoding="utf-8"
            )
            (repository / ".gitignore").write_text("secret.txt\n", encoding="utf-8")
            (repository / "secret.txt").write_text(build_canary(), encoding="utf-8")
            run_git(repository, "add", "-f", ".gitattributes", ".gitignore", "secret.txt")

            result = scan_repository(scanner, scope="staged", repository=repository)

        self.assertEqual(1, result)

    def test_ambient_git_selectors_and_config_cannot_redirect_scope(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-git-env-test-") as temporary:
            base = Path(temporary)
            repository = base / "repository"
            alternate = base / "alternate"
            repository.mkdir()
            alternate.mkdir()
            initialize_repository(repository)
            initialize_repository(alternate)
            scanner = write_fake_scanner(base)
            (repository / "secret.txt").write_text(build_canary(), encoding="utf-8")
            run_git(repository, "add", "secret.txt")
            empty_index = alternate / "empty-index"
            alternate_environment = os.environ.copy()
            alternate_environment["GIT_INDEX_FILE"] = str(empty_index)
            run_git(alternate, "read-tree", "--empty", environment=alternate_environment)
            hostile_environment = {
                "GIT_DIR": str(alternate / ".git"),
                "GIT_WORK_TREE": str(alternate),
                "GIT_INDEX_FILE": str(empty_index),
                "GIT_OBJECT_DIRECTORY": str(alternate / ".git" / "objects"),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(alternate / ".git" / "objects"),
                "GIT_NAMESPACE": "redirected",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.attributesFile",
                "GIT_CONFIG_VALUE_0": str(base / "missing-attributes"),
            }

            with patch.dict(os.environ, hostile_environment):
                result = scan_repository(scanner, scope="staged", repository=repository)

        self.assertEqual(1, result)

    def test_global_and_info_attributes_cannot_hide_staged_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-external-attributes-test-") as temporary:
            base = Path(temporary)
            repository = base / "repository"
            fake_home = base / "home"
            repository.mkdir()
            fake_home.mkdir()
            initialize_repository(repository)
            scanner = write_fake_scanner(base)
            (repository / "secret.txt").write_text(build_canary(), encoding="utf-8")
            run_git(repository, "add", "secret.txt")
            (fake_home / ".gitattributes").write_text("secret.txt -diff\n", encoding="utf-8")
            (repository / ".git" / "info" / "attributes").write_text(
                "secret.txt binary\n", encoding="utf-8"
            )

            with patch.dict(
                os.environ,
                {
                    "HOME": str(fake_home),
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "core.attributesFile",
                    "GIT_CONFIG_VALUE_0": str(fake_home / ".gitattributes"),
                },
            ):
                result = scan_repository(scanner, scope="staged", repository=repository)

        self.assertEqual(1, result)

    def test_staged_symlink_is_rejected_before_scanning(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-symlink-test-") as temporary:
            repository = Path(temporary)
            initialize_repository(repository)
            scanner = write_fake_scanner(repository)
            (repository / "target.txt").write_text("safe", encoding="utf-8")
            (repository / "link.txt").symlink_to("target.txt")
            run_git(repository, "add", "target.txt", "link.txt")

            with self.assertRaisesRegex(RuntimeError, "unsupported Git tree entry"):
                scan_repository(scanner, scope="staged", repository=repository)

    def test_history_scope_scans_removed_secrets_from_complete_commit_trees(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-history-tree-test-") as temporary:
            repository = Path(temporary)
            initialize_repository(repository)
            scanner = write_fake_scanner(repository)
            secret = repository / "secret.txt"
            secret.write_text(build_canary(), encoding="utf-8")
            run_git(repository, "add", "secret.txt")
            run_git(repository, "commit", "--quiet", "-m", "secret fixture")
            secret.unlink()
            (repository / "safe.txt").write_text("safe", encoding="utf-8")
            run_git(repository, "add", "--all")
            run_git(repository, "commit", "--quiet", "-m", "remove fixture")

            result = scan_repository(scanner, scope="history", repository=repository)

        self.assertEqual(1, result)

    def test_repository_policy_and_ignore_files_are_rejected_from_captured_tree(self) -> None:
        for control_file in (".gitleaksignore", ".gitleaks.toml"):
            with (
                self.subTest(control_file=control_file),
                tempfile.TemporaryDirectory(prefix="cairnvm-policy-tree-test-") as temporary,
            ):
                repository = Path(temporary)
                initialize_repository(repository)
                scanner = write_fake_scanner(repository)
                (repository / control_file).write_text("allow", encoding="utf-8")
                run_git(repository, "add", control_file)
                run_git(repository, "commit", "--quiet", "-m", "policy fixture")
                (repository / control_file).unlink()
                run_git(repository, "add", "--all")
                run_git(repository, "commit", "--quiet", "-m", "remove policy")

                with self.assertRaisesRegex(RuntimeError, "repository secret-scanner control file"):
                    scan_repository(scanner, scope="history", repository=repository)

    def test_scanner_output_is_never_forwarded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cairnvm-scanner-output-test-") as temporary:
            repository = Path(temporary)
            initialize_repository(repository)
            scanner = write_fake_scanner(repository, emit_output=True)
            (repository / "secret.txt").write_text(build_canary(), encoding="utf-8")
            run_git(repository, "add", "secret.txt")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = scan_repository(scanner, scope="staged", repository=repository)

        self.assertEqual(1, result)
        self.assertEqual("", stdout.getvalue())
        self.assertEqual("", stderr.getvalue())
