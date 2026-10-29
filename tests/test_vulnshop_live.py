"""Live end-to-end probe tests against the real vulnshop Flask app.

Unlike the deterministic suite, these start the actual app in a local sandbox
and fire real exploits through the real ProbeHarness (curl -> marker check),
proving the pipeline genuinely exploits a live target.

Opt-in: they need flask + curl and are slower/port-dependent, so they only run
when SHIPCHECK_LIVE=1. The default suite and CI stay deterministic.

    SHIPCHECK_LIVE=1 pytest tests/test_vulnshop_live.py -v
"""

import importlib.util
import os
import shlex
import shutil
import socket
import sys
from pathlib import Path

import pytest

from shipcheck.contracts.attack_plan import AttackPlan, VulnClass
from shipcheck.probes.harness import ProbeHarness
from shipcheck.sandbox.client import SandboxClient

pytestmark = pytest.mark.skipif(
    os.environ.get("SHIPCHECK_LIVE") != "1"
    or shutil.which("curl") is None
    or importlib.util.find_spec("flask") is None,
    reason="live test: set SHIPCHECK_LIVE=1 and have flask + curl installed",
)

VULNSHOP = Path(__file__).resolve().parent.parent / "fixtures" / "vulnshop"


def _free_port() -> int:
    """Ask the OS for a free ephemeral port (avoids the macOS port-5000 squatter)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _run_probe(plan: AttackPlan):
    client = SandboxClient(backend_type="mock")
    sandbox = client.create_sandbox()
    await sandbox.apply_files({
        "app.py": (VULNSHOP / "app.py").read_text(),
        "files/readme.txt": (VULNSHOP / "files" / "readme.txt").read_text(),
    })
    port = _free_port()
    harness = ProbeHarness(port=port)
    return await harness.execute_step(
        sandbox,
        plan,
        # sys.executable: the sandbox shell may not have a bare `python` on PATH
        app_cmd=f"PORT={port} {shlex.quote(sys.executable)} app.py",
        target_dir=str(sandbox.workdir),
    )


async def test_live_sqli_marker_fires():
    plan = AttackPlan(
        vuln_class=VulnClass.SQLI, target_file="app.py", sink="conn.execute",
        payload_strategy="tautology login bypass", expected_marker="admin@vulnshop.local",
        route="/login", http_method="POST", parameter_name="username",
        suggested_payload="' OR 1=1--",
    )
    evidence = await _run_probe(plan)
    assert evidence.marker_found, evidence.response_excerpt


async def test_live_xss_marker_fires():
    plan = AttackPlan(
        vuln_class=VulnClass.XSS, target_file="app.py", sink="return html",
        payload_strategy="script reflection", expected_marker="<script>alert(1)</script>",
        route="/search", http_method="GET", parameter_name="q",
        suggested_payload="<script>alert(1)</script>",
    )
    evidence = await _run_probe(plan)
    assert evidence.marker_found, evidence.response_excerpt


async def test_live_cmdi_marker_fires():
    plan = AttackPlan(
        vuln_class=VulnClass.CMDI, target_file="app.py", sink="subprocess.run",
        payload_strategy="shell separator", expected_marker="uid=",
        route="/export", http_method="GET", parameter_name="ip",
        suggested_payload="8.8.8.8; id",
    )
    evidence = await _run_probe(plan)
    assert evidence.marker_found, evidence.response_excerpt


async def test_live_traversal_marker_fires():
    plan = AttackPlan(
        vuln_class=VulnClass.TRAVERSAL, target_file="app.py", sink="open()",
        payload_strategy="dot-dot-slash", expected_marker="root:",
        route="/download", http_method="GET", parameter_name="file",
        suggested_payload="../" * 12 + "etc/passwd",
    )
    evidence = await _run_probe(plan)
    assert evidence.marker_found, evidence.response_excerpt
