"""Read-only host diagnostics for the CairnVM feasibility phase."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class Status(StrEnum):
    """Outcome of a host capability check."""

    PASS = "pass"  # noqa: S105  # Status label, not a credential.
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class Check:
    """One diagnostic result."""

    name: str
    status: Status
    detail: str


@dataclass(frozen=True, slots=True)
class DiagnosticReport:
    """Ordered set of host diagnostic results."""

    checks: tuple[Check, ...]

    @property
    def prerequisites_present(self) -> bool:
        """Return whether preliminary probes found every required prerequisite."""

        return all(check.status is not Status.FAIL for check in self.checks)

    def as_dict(self) -> dict[str, object]:
        """Return a stable JSON-compatible representation."""

        return {
            "checks": [
                {"detail": check.detail, "name": check.name, "status": check.status.value}
                for check in self.checks
            ],
            "prerequisites_present": self.prerequisites_present,
        }


def _probe_executable(
    check_name: str,
    executable: str,
    *,
    version_arguments: tuple[str, ...] = ("--version",),
) -> tuple[Check, str | None]:
    resolved = shutil.which(executable)
    if resolved is None:
        return Check(check_name, Status.FAIL, f"{executable} not found on PATH"), None

    try:
        result = subprocess.run(  # noqa: S603  # Executable is resolved without a shell.
            [resolved, *version_arguments],
            check=False,
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return Check(check_name, Status.FAIL, "version probe timed out after 5 seconds"), None
    except OSError:
        return Check(check_name, Status.FAIL, "version probe could not execute"), None

    if result.returncode != 0:
        detail = f"version probe failed with exit status {result.returncode}"
        return Check(check_name, Status.FAIL, detail), None

    return Check(check_name, Status.PASS, "version probe passed"), resolved


def _probe_nbdkit_python(nbdkit_path: str | None) -> Check:
    check_name = "nbdkit-python-presence"
    if nbdkit_path is None:
        return Check(check_name, Status.FAIL, "cannot probe without nbdkit")

    try:
        result = subprocess.run(  # noqa: S603  # nbdkit is resolved without a shell.
            [nbdkit_path, "python", "--dump-plugin"],
            check=False,
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return Check(check_name, Status.FAIL, "plugin probe timed out after 5 seconds")
    except OSError:
        return Check(check_name, Status.FAIL, "plugin probe could not execute")

    if result.returncode == 0:
        return Check(
            check_name,
            Status.WARN,
            "plugin is present; embedded Python compatibility requires a Phase 0 smoke test",
        )

    detail = f"plugin probe failed with exit status {result.returncode}"
    return Check(check_name, Status.FAIL, detail)


def _probe_kvm(path: Path) -> Check:
    if not path.is_char_device():
        return Check("kvm", Status.WARN, "device unavailable; QEMU TCG fallback required")
    if not os.access(path, os.R_OK | os.W_OK):
        return Check("kvm", Status.WARN, "device is not readable and writable")
    return Check(
        "kvm",
        Status.WARN,
        "device appears accessible; QEMU KVM smoke test required",
    )


def collect_diagnostics(*, kvm_path: Path = Path("/dev/kvm")) -> DiagnosticReport:
    """Collect read-only checks needed before a Phase 0 feasibility run."""

    python_status = Status.PASS if sys.version_info >= (3, 11) else Status.FAIL
    python_check = Check(
        "python",
        python_status,
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )
    qemu_check, _ = _probe_executable("qemu", "qemu-system-x86_64")
    nbdkit_check, nbdkit_path = _probe_executable("nbdkit", "nbdkit")
    zstd_check, _ = _probe_executable("zstd", "zstd")

    return DiagnosticReport(
        checks=(
            python_check,
            qemu_check,
            nbdkit_check,
            _probe_nbdkit_python(nbdkit_path),
            zstd_check,
            _probe_kvm(kvm_path),
        )
    )
