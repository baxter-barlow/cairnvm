from __future__ import annotations

import base64
import inspect
import io
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import BinaryIO, cast
from unittest.mock import Mock, patch

from scripts import verify_secret_scanner as scanner_module
from scripts.verify_secret_scanner import (
    REPOSITORY_ROOT,
    build_canary,
    main,
    scan_repository,
    verify_canary,
)

ROOT = Path(__file__).resolve().parents[2]


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

    def test_pre_commit_pins_the_current_release_commit(self) -> None:
        configuration = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")

        self.assertIn(
            "rev: 83d9cd684c87d95d656c1458ef04895a7f1cbd8e # v8.30.1",
            configuration,
        )
        self.assertIn(
            "entry: python3 scripts/verify_secret_scanner.py\n"
            "        pass_filenames: false\n"
            "        always_run: true",
            configuration,
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
    def test_resolves_only_a_scanner_from_the_pinned_managed_checkout(self) -> None:
        with patch("scripts.verify_secret_scanner.shutil.which", return_value=None):
            self.assertIsNone(scanner_module._resolve_pinned_scanner())

        with tempfile.TemporaryDirectory(prefix="cairnvm-pinned-scanner-test-") as temporary:
            cache = Path(temporary) / "pre-commit"
            repository = cache / "repo-fixture"
            scanner = repository / "golangenv-default" / "bin" / "gitleaks"
            scanner.parent.mkdir(parents=True)
            initialize_repository(repository)
            scanner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            scanner.chmod(0o700)
            run_git(repository, "add", "golangenv-default/bin/gitleaks")
            run_git(repository, "commit", "--quiet", "-m", "pinned fixture")
            git = shutil.which("git")
            self.assertIsNotNone(git)
            assert git is not None
            revision = subprocess.run(  # noqa: S603  # Git is resolved from the test environment.
                [git, "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            def resolve_executable(name: str) -> str | None:
                return str(scanner) if name == "gitleaks" else git

            with (
                patch.object(scanner_module, "PINNED_PRE_COMMIT_HOME", cache),
                patch.object(scanner_module, "PINNED_GITLEAKS_REVISION", revision),
                patch("scripts.verify_secret_scanner.shutil.which", side_effect=resolve_executable),
            ):
                self.assertEqual(str(scanner.resolve()), scanner_module._resolve_pinned_scanner())

            with (
                patch.object(scanner_module, "PINNED_PRE_COMMIT_HOME", cache),
                patch.object(scanner_module, "PINNED_GITLEAKS_REVISION", "0" * 40),
                patch("scripts.verify_secret_scanner.shutil.which", side_effect=resolve_executable),
            ):
                self.assertIsNone(scanner_module._resolve_pinned_scanner())

            with (
                patch.object(scanner_module, "PINNED_PRE_COMMIT_HOME", cache),
                patch("scripts.verify_secret_scanner.shutil.which", return_value=__file__),
            ):
                self.assertIsNone(scanner_module._resolve_pinned_scanner())

    @patch("scripts.verify_secret_scanner._run_pinned_hook", return_value=0)
    @patch("scripts.verify_secret_scanner._resolve_pinned_scanner", return_value=None)
    def test_main_bootstraps_the_pinned_hook_when_no_valid_scanner_is_active(
        self,
        resolve: Mock,
        bootstrap: Mock,
    ) -> None:
        self.assertEqual(0, main())

        resolve.assert_called_once_with()
        bootstrap.assert_called_once_with()

    @patch("scripts.verify_secret_scanner.subprocess.run")
    @patch("scripts.verify_secret_scanner.shutil.which", return_value=__file__)
    def test_pinned_hook_bootstrap_sanitizes_ambient_controls(
        self,
        _which: Mock,
        run: Mock,
    ) -> None:
        run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        with (
            tempfile.TemporaryDirectory(prefix="cairnvm-bootstrap-env-test-") as temporary,
            patch.dict(
                os.environ,
                {
                    "SKIP": "gitleaks",
                    "GIT_DIR": str(Path(temporary) / "redirected"),
                    "GITLEAKS_CONFIG": str(Path(temporary) / "weakened.toml"),
                    "PRE_COMMIT_HOME": str(Path(temporary) / "redirected-cache"),
                    "CAIRNVM_GITLEAKS_BOOTSTRAPPED": "hostile",
                },
            ),
        ):
            self.assertEqual(0, scanner_module._run_pinned_hook())

        command = run.call_args.args[0]
        self.assertEqual(str(Path(__file__).resolve()), command[0])
        self.assertEqual(
            [
                "run",
                "--locked",
                "--all-packages",
                "python",
                "-m",
                "pre_commit",
                "run",
                "--config",
                str(ROOT / ".pre-commit-config.yaml"),
                "gitleaks",
                "--all-files",
            ],
            command[1:],
        )
        environment = run.call_args.kwargs["env"]
        self.assertNotIn("SKIP", environment)
        self.assertNotIn("GIT_DIR", environment)
        self.assertNotIn("GITLEAKS_CONFIG", environment)
        self.assertEqual(str(scanner_module.PINNED_PRE_COMMIT_HOME), environment["PRE_COMMIT_HOME"])
        self.assertEqual("1", environment["CAIRNVM_GITLEAKS_BOOTSTRAPPED"])
        self.assertEqual(ROOT, run.call_args.kwargs["cwd"])
        self.assertEqual(subprocess.DEVNULL, run.call_args.kwargs["stdout"])
        self.assertEqual(subprocess.DEVNULL, run.call_args.kwargs["stderr"])

    def test_pinned_hook_bootstrap_failures_are_closed(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="cairnvm-pin-config-test-") as temporary,
            patch.object(scanner_module, "REPOSITORY_ROOT", Path(temporary)),
        ):
            self.assertEqual(2, scanner_module._run_pinned_hook())

        internal_error = subprocess.CompletedProcess[bytes](args=[], returncode=3)
        with (
            patch(
                "scripts.verify_secret_scanner._configured_gitleaks_pin_is_exact", return_value=True
            ),
            patch("scripts.verify_secret_scanner.shutil.which", return_value=__file__),
            patch("scripts.verify_secret_scanner.subprocess.run", return_value=internal_error),
        ):
            self.assertEqual(2, scanner_module._run_pinned_hook())

        with (
            patch(
                "scripts.verify_secret_scanner._configured_gitleaks_pin_is_exact", return_value=True
            ),
            patch("scripts.verify_secret_scanner.shutil.which", return_value=None),
        ):
            self.assertEqual(2, scanner_module._run_pinned_hook())

        with (
            patch(
                "scripts.verify_secret_scanner._configured_gitleaks_pin_is_exact", return_value=True
            ),
            patch("scripts.verify_secret_scanner.shutil.which", return_value=__file__),
            patch("scripts.verify_secret_scanner.subprocess.run", side_effect=OSError("sensitive")),
        ):
            self.assertEqual(2, scanner_module._run_pinned_hook())

    @patch("scripts.verify_secret_scanner._resolve_pinned_scanner", return_value=None)
    def test_bootstrapped_main_does_not_recurse_when_scanner_is_missing(
        self, _resolve: Mock
    ) -> None:
        stderr = io.StringIO()
        with (
            patch.dict(os.environ, {"CAIRNVM_GITLEAKS_BOOTSTRAPPED": "1"}),
            patch("sys.stderr", stderr),
            patch("scripts.verify_secret_scanner._run_pinned_hook") as bootstrap,
        ):
            self.assertEqual(2, main())

        bootstrap.assert_not_called()
        self.assertEqual("pinned secret scanner is unavailable\n", stderr.getvalue())

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
        self.assertEqual("yes", scanner_environment["CAIRNVM_TEST_PRESERVED"])
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

    @patch("scripts.verify_secret_scanner._run_pinned_hook", return_value=2)
    @patch("scripts.verify_secret_scanner._resolve_pinned_scanner", return_value=None)
    def test_main_fails_when_the_pinned_hook_is_unavailable(
        self, _resolve: Mock, _bootstrap: Mock
    ) -> None:
        stderr = io.StringIO()

        with patch("sys.stderr", stderr):
            self.assertEqual(2, main())

        self.assertEqual("", stderr.getvalue())

    @patch("scripts.verify_secret_scanner.scan_repository", return_value=0)
    @patch("scripts.verify_secret_scanner.verify_canary")
    @patch("scripts.verify_secret_scanner._resolve_pinned_scanner", return_value=__file__)
    def test_main_verifies_then_uses_the_selected_scope(
        self,
        _resolve: Mock,
        canary: Mock,
        scan: Mock,
    ) -> None:
        with patch.dict("os.environ", {"CAIRNVM_SECRET_SCAN_SCOPE": "history"}):
            self.assertEqual(0, main())

        scanner = str(Path(__file__).resolve())
        canary.assert_called_once_with(scanner)
        scan.assert_called_once_with(scanner, scope="history", repository=REPOSITORY_ROOT)

    @patch(
        "scripts.verify_secret_scanner.verify_canary",
        side_effect=RuntimeError("canary failed"),
    )
    @patch("scripts.verify_secret_scanner._resolve_pinned_scanner", return_value=__file__)
    def test_main_reports_validation_failures(
        self,
        _resolve: Mock,
        _canary: Mock,
    ) -> None:
        stderr = io.StringIO()

        with patch("sys.stderr", stderr):
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
