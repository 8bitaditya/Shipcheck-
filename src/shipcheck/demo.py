"""Run a real scan of the bundled `vulnshop` fixture.

This is the one scan a public deployment may run, because its target is
fixed: the app under test is the copy of `fixtures/vulnshop` shipped with
ShipCheck, never anything a visitor supplies. Nothing from the request is
executed, so exposing it cannot turn the host into someone else's sandbox.

Used by `GET /api/demo-scan` and by `scripts/record_golden.py`, so the live
demo and the recorded golden run are the same scan.
"""

from __future__ import annotations

import shlex
import socket
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

from shipcheck import config
from shipcheck.orchestrator import ScanResult, ShipCheckScanner
from shipcheck.probes.harness import ProbeHarness
from shipcheck.rectify.fixer import RectificationEngine
from shipcheck.sandbox.client import SandboxClient

APP_DIR = "fixtures/vulnshop"
VULNSHOP = config.BASE_DIR / APP_DIR


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def vulnshop_files(root: Optional[Path] = None) -> dict:
    """The fixture's files, keyed by their repo-relative path."""
    src = Path(root or VULNSHOP)
    return {
        f"{APP_DIR}/{p.relative_to(src)}": p.read_text(encoding="utf-8")
        for p in sorted(src.rglob("*"))
        if p.is_file() and not {"__pycache__", ".pytest_cache"} & set(p.parts)
    }


def _runtime(backend: str) -> Tuple[int, str, int]:
    """(port, python, concurrency) for this backend."""
    if backend in ("docker", "contree"):
        # Each sandbox has its own loopback and its own Python on PATH.
        return 5000, "python", 4
    # Local sandboxes share the host's ports, so probe one at a time, and use
    # this interpreter (macOS has no bare `python` outside a venv).
    return _free_port(), shlex.quote(sys.executable), 1


async def run_vulnshop_scan(
    backend: Optional[str] = None, *, commit_sha: str = "vulnshop-demo"
) -> Tuple[ScanResult, float]:
    """Scan the bundled fixture end to end. Returns (result, seconds)."""
    backend = (backend or config.SANDBOX_BACKEND).lower()
    sandbox = SandboxClient(backend_type=backend).create_sandbox()
    try:
        files = vulnshop_files()
        await sandbox.apply_files(files)

        port, py, concurrency = _runtime(backend)
        harness = ProbeHarness(port=port)
        scanner = ShipCheckScanner(
            harness=harness,
            rectifier=RectificationEngine(harness=harness),
            max_concurrent=concurrency,
        )
        app_py = files[f"{APP_DIR}/app.py"]
        diff = (
            f"diff --git a/{APP_DIR}/app.py b/{APP_DIR}/app.py\nnew file mode 100644\n"
            f"--- /dev/null\n+++ b/{APP_DIR}/app.py\n"
            + "".join("+" + line + "\n" for line in app_py.splitlines())
        )
        started = time.monotonic()
        result = await scanner.scan(
            sandbox, diff, commit_sha=commit_sha,
            app_cmd=f"PORT={port} {py} app.py",
            target_dir=f"{sandbox.default_workdir}/{APP_DIR}",
            test_cmd=f"cd {APP_DIR} && {py} -m pytest -q test_app.py",
        )
        return result, time.monotonic() - started
    finally:
        sandbox.cleanup()
