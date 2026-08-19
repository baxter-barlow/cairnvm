from __future__ import annotations

import re
import subprocess
import sys

from cairnvm_launcher import __version__


def test_launcher_exposes_a_semantic_version() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)


def test_launcher_import_never_touches_the_runtime_package() -> None:
    script = """
import importlib.abc
import sys

attempts = []

class DenyRuntime(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "cairnvm" or fullname.startswith("cairnvm."):
            attempts.append(fullname)
            raise RuntimeError(f"launcher attempted runtime import: {fullname}")
        return None

sys.meta_path.insert(0, DenyRuntime())
import cairnvm_launcher
if attempts:
    raise SystemExit(f"runtime import attempts: {attempts!r}")
"""
    subprocess.run(  # noqa: S603  # Current interpreter and fixed test program.
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
