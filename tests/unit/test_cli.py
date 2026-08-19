from __future__ import annotations

import io
import json
import runpy
import unittest
from unittest.mock import patch

from cairnvm.cli import main
from cairnvm.diagnostics import Check, DiagnosticReport, Status


class CliTests(unittest.TestCase):
    def test_version_prints_package_version(self) -> None:
        stdout = io.StringIO()

        with patch("sys.stdout", stdout):
            exit_code = main(["--version"])

        self.assertEqual(0, exit_code)
        self.assertRegex(stdout.getvalue(), r"^cairnvm \d+\.\d+\.\d+\n$")

    def test_doctor_json_reports_preliminary_prerequisites(self) -> None:
        report = DiagnosticReport(
            checks=(Check("qemu", Status.PASS, "/usr/bin/qemu-system-x86_64"),)
        )
        stdout = io.StringIO()

        with (
            patch("cairnvm.cli.collect_diagnostics", return_value=report),
            patch("sys.stdout", stdout),
        ):
            exit_code = main(["doctor", "--json"])

        self.assertEqual(0, exit_code)
        self.assertEqual(
            {
                "checks": [
                    {
                        "detail": "/usr/bin/qemu-system-x86_64",
                        "name": "qemu",
                        "status": "pass",
                    }
                ],
                "prerequisites_present": True,
            },
            json.loads(stdout.getvalue()),
        )

    def test_doctor_returns_nonzero_when_a_required_check_fails(self) -> None:
        report = DiagnosticReport(checks=(Check("nbdkit", Status.FAIL, "not found on PATH"),))

        with (
            patch("cairnvm.cli.collect_diagnostics", return_value=report),
            patch("sys.stdout", io.StringIO()),
        ):
            exit_code = main(["doctor", "--json"])

        self.assertEqual(1, exit_code)

    def test_doctor_text_reports_each_check_and_preliminary_result(self) -> None:
        report = DiagnosticReport(checks=(Check("kvm", Status.WARN, "TCG fallback required"),))
        stdout = io.StringIO()

        with (
            patch("cairnvm.cli.collect_diagnostics", return_value=report),
            patch("sys.stdout", stdout),
        ):
            exit_code = main(["doctor"])

        self.assertEqual(0, exit_code)
        self.assertEqual(
            "WARN kvm: TCG fallback required\nprerequisites present: yes\n",
            stdout.getvalue(),
        )

    def test_no_command_prints_help_and_returns_usage_error(self) -> None:
        stdout = io.StringIO()

        with patch("sys.stdout", stdout):
            exit_code = main([])

        self.assertEqual(2, exit_code)
        self.assertIn("usage: cairnvm", stdout.getvalue())

    def test_package_module_invokes_the_cli(self) -> None:
        with (
            patch("cairnvm.cli.main", return_value=0) as mocked_main,
            self.assertRaises(SystemExit) as exit_context,
        ):
            runpy.run_module("cairnvm", run_name="__main__")

        self.assertEqual(0, exit_context.exception.code)
        mocked_main.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
