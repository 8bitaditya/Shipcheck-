"""DockerBackend against real containers of the probe image.

Opt-in (needs Docker and the shipcheck-probe image, ~1.6 GB):
    SHIPCHECK_DOCKER=1 pytest tests/test_docker_backend.py -v
"""

import os
import shutil
from pathlib import Path

import pytest

from shipcheck.contracts.attack_plan import AttackPlan, VulnClass
from shipcheck.probes.harness import ProbeHarness
from shipcheck.sandbox.docker_backend import DockerBackend

pytestmark = pytest.mark.skipif(
    os.environ.get("SHIPCHECK_DOCKER") != "1" or shutil.which("docker") is None,
    reason="docker test: set SHIPCHECK_DOCKER=1 with Docker running and shipcheck-probe built",
)

VULNSHOP = Path(__file__).resolve().parent.parent / "fixtures" / "vulnshop"


@pytest.fixture
def sandbox():
    sb = DockerBackend()
    yield sb
    sb.cleanup()


async def test_files_run_and_read_back(sandbox):
    await sandbox.apply_files({"a/b.txt": "hello", "/tmp/x.bin": b"\x00\x01"})
    assert await sandbox.read_file("a/b.txt") == b"hello"
    assert await sandbox.read_file("/tmp/x.bin") == b"\x00\x01"
    res = await sandbox.run(shell="pwd; cat a/b.txt; echo; echo \"$FOO\"", env={"FOO": "bar"})
    assert res.exit_code == 0
    assert res.stdout.split() == ["/workspace", "hello", "bar"]
    assert sandbox.default_workdir == "/workspace"


async def test_fork_is_isolated(sandbox):
    await sandbox.apply_files({"app.py": "v1"})
    child = await sandbox.fork()
    try:
        await child.apply_files({"app.py": "v2"})
        assert await child.read_file("app.py") == b"v2"
        assert await sandbox.read_file("app.py") == b"v1"
    finally:
        child.cleanup()


async def test_timeout_returns_124(sandbox):
    res = await sandbox.run(shell="sleep 30", timeout=2)
    assert res.exit_code == 124


async def test_sqli_probe_lands_inside_the_container(sandbox):
    await sandbox.apply_files({n: (VULNSHOP / n).read_text() for n in ("app.py", "files/readme.txt")})
    plan = AttackPlan(
        vuln_class=VulnClass.SQLI, target_file="app.py", sink="conn.execute",
        payload_strategy="tautology", expected_marker="admin@vulnshop.local",
        route="/login", http_method="POST", parameter_name="username",
        suggested_payload="' OR 1=1--",
    )
    evidence = await ProbeHarness(port=5000).execute_step(sandbox, plan, app_cmd="python app.py")
    assert evidence.marker_found, evidence.response_excerpt
