"""Command-line entry point for the Phase 0 CairnVM scaffold."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from cairnvm import __version__
from cairnvm.diagnostics import DiagnosticReport, collect_diagnostics


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cairnvm",
        description="Inspect the local prerequisites for the CairnVM feasibility phase.",
    )
    parser.add_argument("--version", action="store_true", help="print the installed version")

    commands = parser.add_subparsers(dest="command")
    doctor = commands.add_parser("doctor", help="probe preliminary host prerequisites")
    doctor.add_argument("--json", action="store_true", help="emit a machine-readable report")
    return parser


def _print_report(report: DiagnosticReport, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
        return

    for check in report.checks:
        print(f"{check.status.value.upper():4} {check.name}: {check.detail}")
    present = "yes" if report.prerequisites_present else "no"
    print(f"prerequisites present: {present}")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CairnVM command-line interface and return a process exit code."""

    parser = _parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"cairnvm {__version__}")
        return 0

    if args.command == "doctor":
        report = collect_diagnostics()
        _print_report(report, as_json=args.json)
        return 0 if report.prerequisites_present else 1

    parser.print_help()
    return 2
