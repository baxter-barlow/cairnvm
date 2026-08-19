from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from cairnvm.diagnostics import Check, DiagnosticReport, Status, collect_diagnostics


class DiagnosticModelTests(unittest.TestCase):
    def test_report_has_prerequisites_when_only_preliminary_checks_warn(self) -> None:
        report = DiagnosticReport(
            checks=(
                Check("qemu", Status.PASS, "found"),
                Check("kvm", Status.WARN, "TCG fallback required"),
            )
        )

        self.assertTrue(report.prerequisites_present)

    def test_report_lacks_prerequisites_when_any_required_check_fails(self) -> None:
        report = DiagnosticReport(
            checks=(
                Check("qemu", Status.PASS, "found"),
                Check("nbdkit", Status.FAIL, "missing"),
            )
        )

        self.assertFalse(report.prerequisites_present)


class DiagnosticCollectionTests(unittest.TestCase):
    @patch("cairnvm.diagnostics._probe_kvm")
    @patch("cairnvm.diagnostics.subprocess.run")
    @patch("cairnvm.diagnostics.shutil.which")
    def test_collects_required_tools_and_optional_kvm(
        self,
        which: Mock,
        run: Mock,
        probe_kvm: Mock,
    ) -> None:
        paths = {
            "qemu-system-x86_64": "/usr/bin/qemu-system-x86_64",
            "nbdkit": "/usr/bin/nbdkit",
            "zstd": "/usr/bin/zstd",
        }
        which.side_effect = paths.get
        run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
        )
        probe_kvm.return_value = Check("kvm", Status.WARN, "TCG fallback required")

        report = collect_diagnostics(kvm_path=Path("/dev/kvm"))

        self.assertTrue(report.prerequisites_present)
        self.assertEqual(
            ("python", "qemu", "nbdkit", "nbdkit-python-presence", "zstd", "kvm"),
            tuple(check.name for check in report.checks),
        )
        plugin = next(check for check in report.checks if check.name == "nbdkit-python-presence")
        self.assertEqual(Status.WARN, plugin.status)
        self.assertEqual(
            "plugin is present; embedded Python compatibility requires a Phase 0 smoke test",
            plugin.detail,
        )
        run.assert_has_calls(
            [
                call(
                    ["/usr/bin/qemu-system-x86_64", "--version"],
                    check=False,
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    timeout=5,
                ),
                call(
                    ["/usr/bin/nbdkit", "--version"],
                    check=False,
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    timeout=5,
                ),
                call(
                    ["/usr/bin/zstd", "--version"],
                    check=False,
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    timeout=5,
                ),
                call(
                    ["/usr/bin/nbdkit", "python", "--dump-plugin"],
                    check=False,
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    timeout=5,
                ),
            ]
        )
        self.assertEqual(4, run.call_count)

    @patch("cairnvm.diagnostics._probe_kvm")
    @patch("cairnvm.diagnostics.subprocess.run")
    @patch("cairnvm.diagnostics.shutil.which")
    def test_missing_required_tool_fails_without_running_plugin_probe(
        self,
        which: Mock,
        run: Mock,
        probe_kvm: Mock,
    ) -> None:
        which.side_effect = {
            "qemu-system-x86_64": None,
            "nbdkit": None,
            "zstd": "/usr/bin/zstd",
        }.get
        probe_kvm.return_value = Check("kvm", Status.WARN, "TCG fallback required")
        run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        report = collect_diagnostics()

        self.assertFalse(report.prerequisites_present)
        run.assert_called_once_with(
            ["/usr/bin/zstd", "--version"],
            check=False,
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            timeout=5,
        )
        failures = {check.name for check in report.checks if check.status is Status.FAIL}
        self.assertEqual({"qemu", "nbdkit", "nbdkit-python-presence"}, failures)

    @patch("cairnvm.diagnostics._probe_kvm")
    @patch("cairnvm.diagnostics.subprocess.run")
    @patch("cairnvm.diagnostics.shutil.which")
    def test_failed_python_plugin_probe_is_reported(
        self,
        which: Mock,
        run: Mock,
        probe_kvm: Mock,
    ) -> None:
        which.side_effect = lambda name: f"/usr/bin/{name}"

        def probe_result(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
            returncode = 1 if args[1:] == ["python", "--dump-plugin"] else 0
            return subprocess.CompletedProcess(
                args=args,
                returncode=returncode,
                stdout=b"/Users/alice/private token=EXAMPLE_SECRET",
                stderr=b"x" * 1_000_000,
            )

        run.side_effect = probe_result
        probe_kvm.return_value = Check("kvm", Status.WARN, "TCG fallback required")

        report = collect_diagnostics()

        plugin = next(check for check in report.checks if check.name == "nbdkit-python-presence")
        self.assertEqual(Status.FAIL, plugin.status)
        self.assertEqual("plugin probe failed with exit status 1", plugin.detail)
        self.assertNotIn("alice", plugin.detail)
        self.assertNotIn("SECRET", plugin.detail)

    @patch("cairnvm.diagnostics._probe_kvm")
    @patch("cairnvm.diagnostics.subprocess.run")
    @patch("cairnvm.diagnostics.shutil.which")
    def test_timed_out_python_plugin_probe_is_reported(
        self,
        which: Mock,
        run: Mock,
        probe_kvm: Mock,
    ) -> None:
        which.side_effect = lambda name: f"/usr/bin/{name}"
        probe_kvm.return_value = Check("kvm", Status.WARN, "TCG fallback required")

        def probe_result(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if args[1:] == ["python", "--dump-plugin"]:
                raise subprocess.TimeoutExpired(args, 5)
            return subprocess.CompletedProcess(args=args, returncode=0)

        run.side_effect = probe_result

        report = collect_diagnostics()

        plugin = next(check for check in report.checks if check.name == "nbdkit-python-presence")
        self.assertEqual(Status.FAIL, plugin.status)
        self.assertEqual("plugin probe timed out after 5 seconds", plugin.detail)

    @patch("cairnvm.diagnostics._probe_kvm")
    @patch("cairnvm.diagnostics.subprocess.run")
    @patch("cairnvm.diagnostics.shutil.which")
    def test_python_plugin_execution_error_is_reported(
        self,
        which: Mock,
        run: Mock,
        probe_kvm: Mock,
    ) -> None:
        which.side_effect = lambda name: f"/usr/bin/{name}"
        probe_kvm.return_value = Check("kvm", Status.WARN, "TCG fallback required")

        def probe_result(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if args[1:] == ["python", "--dump-plugin"]:
                raise OSError("/Users/alice/private token=EXAMPLE_SECRET")
            return subprocess.CompletedProcess(args=args, returncode=0)

        run.side_effect = probe_result

        report = collect_diagnostics()

        plugin = next(check for check in report.checks if check.name == "nbdkit-python-presence")
        self.assertEqual(Status.FAIL, plugin.status)
        self.assertEqual("plugin probe could not execute", plugin.detail)
        self.assertNotIn("alice", plugin.detail)

    @patch("cairnvm.diagnostics._probe_kvm")
    @patch("cairnvm.diagnostics.subprocess.run")
    @patch("cairnvm.diagnostics.shutil.which")
    def test_non_utf8_plugin_output_is_never_decoded_or_reported(
        self,
        which: Mock,
        run: Mock,
        probe_kvm: Mock,
    ) -> None:
        which.side_effect = lambda name: f"/usr/bin/{name}"
        probe_kvm.return_value = Check("kvm", Status.WARN, "TCG fallback required")

        def probe_result(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
            returncode = 1 if args[1:] == ["python", "--dump-plugin"] else 0
            return subprocess.CompletedProcess(
                args=args,
                returncode=returncode,
                stdout=b"\xff\xfe",
                stderr=b"\x80\x81",
            )

        run.side_effect = probe_result

        report = collect_diagnostics()

        plugin = next(check for check in report.checks if check.name == "nbdkit-python-presence")
        self.assertEqual(Status.FAIL, plugin.status)
        self.assertEqual("plugin probe failed with exit status 1", plugin.detail)

    @patch("cairnvm.diagnostics._probe_kvm")
    @patch("cairnvm.diagnostics.subprocess.run")
    @patch("cairnvm.diagnostics.shutil.which")
    def test_nonfunctional_required_binaries_fail_readiness(
        self,
        which: Mock,
        run: Mock,
        probe_kvm: Mock,
    ) -> None:
        which.return_value = "/usr/bin/false"
        run.return_value = subprocess.CompletedProcess(args=[], returncode=1)
        probe_kvm.return_value = Check("kvm", Status.WARN, "TCG fallback required")

        report = collect_diagnostics()

        self.assertFalse(report.prerequisites_present)
        failures = {check.name for check in report.checks if check.status is Status.FAIL}
        self.assertEqual({"nbdkit", "nbdkit-python-presence", "qemu", "zstd"}, failures)
        self.assertEqual(3, run.call_count)

    @patch("cairnvm.diagnostics._probe_kvm")
    @patch("cairnvm.diagnostics.subprocess.run", side_effect=subprocess.TimeoutExpired("probe", 5))
    @patch("cairnvm.diagnostics.shutil.which")
    def test_required_version_probe_timeout_is_structured(
        self,
        which: Mock,
        _run: Mock,
        probe_kvm: Mock,
    ) -> None:
        which.side_effect = {"qemu-system-x86_64": "/usr/bin/qemu-system-x86_64"}.get
        probe_kvm.return_value = Check("kvm", Status.WARN, "TCG fallback required")

        report = collect_diagnostics()

        qemu = next(check for check in report.checks if check.name == "qemu")
        self.assertEqual(Status.FAIL, qemu.status)
        self.assertEqual("version probe timed out after 5 seconds", qemu.detail)

    @patch("cairnvm.diagnostics._probe_kvm")
    @patch(
        "cairnvm.diagnostics.subprocess.run",
        side_effect=OSError("/Users/alice/private token=EXAMPLE_SECRET"),
    )
    @patch("cairnvm.diagnostics.shutil.which")
    def test_required_version_probe_execution_error_is_redacted(
        self,
        which: Mock,
        _run: Mock,
        probe_kvm: Mock,
    ) -> None:
        which.side_effect = {"qemu-system-x86_64": "/usr/bin/qemu-system-x86_64"}.get
        probe_kvm.return_value = Check("kvm", Status.WARN, "TCG fallback required")

        report = collect_diagnostics()

        qemu = next(check for check in report.checks if check.name == "qemu")
        self.assertEqual(Status.FAIL, qemu.status)
        self.assertEqual("version probe could not execute", qemu.detail)
        self.assertNotIn("alice", qemu.detail)

    @patch("cairnvm.diagnostics.os.access", return_value=True)
    def test_kvm_requires_a_character_device(self, access: Mock) -> None:
        with patch.object(Path, "is_char_device", return_value=False):
            from cairnvm.diagnostics import _probe_kvm

            check = _probe_kvm(Path("/dev/kvm"))

        self.assertEqual(Status.WARN, check.status)
        self.assertNotIn("/dev/kvm", check.detail)
        access.assert_not_called()

    @patch("cairnvm.diagnostics.os.access", return_value=False)
    def test_kvm_warns_when_device_permissions_are_insufficient(self, access: Mock) -> None:
        with patch.object(Path, "is_char_device", return_value=True):
            from cairnvm.diagnostics import _probe_kvm

            check = _probe_kvm(Path("/dev/kvm"))

        self.assertEqual(Status.WARN, check.status)
        self.assertIn("not readable and writable", check.detail)
        self.assertNotIn("/dev/kvm", check.detail)
        access.assert_called_once()

    @patch("cairnvm.diagnostics.os.access", return_value=True)
    def test_kvm_device_access_is_only_a_preliminary_check(self, access: Mock) -> None:
        with patch.object(Path, "is_char_device", return_value=True):
            from cairnvm.diagnostics import _probe_kvm

            check = _probe_kvm(Path("/dev/kvm"))

        self.assertEqual(Status.WARN, check.status)
        self.assertIn("QEMU KVM smoke test required", check.detail)
        self.assertNotIn("/dev/kvm", check.detail)
        access.assert_called_once()


if __name__ == "__main__":
    unittest.main()
