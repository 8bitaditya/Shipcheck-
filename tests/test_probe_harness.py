"""Tests for ProbeHarness curl command construction.

Payloads are attacker strings by design (quotes, separators, '&', '#'), so the
probe command must deliver them to the target intact. shlex.split stands in for
the shell: if quoting is wrong, the payload comes back mangled or split.
"""

import shlex

import pytest

from shipcheck.contracts.attack_plan import AttackPlan, VulnClass
from shipcheck.probes.harness import ProbeHarness

PAYLOADS = [
    "' OR 1=1--",
    "admin'--",
    "\" OR \"\"=\"",
    "8.8.8.8; id",
    "a&password=b#c",
    "$(id) `id`",
    "<script>alert(1)</script>",
]


def _plan(method: str, vuln_class: VulnClass, param: str) -> AttackPlan:
    return AttackPlan(
        vuln_class=vuln_class, target_file="app.py", sink="sink",
        payload_strategy="s", expected_marker="m",
        route="/login", http_method=method, parameter_name=param,
    )


@pytest.mark.parametrize("payload", PAYLOADS)
def test_post_payload_survives_shell_quoting(payload):
    cmd = ProbeHarness(port=5000)._build_probe_command(
        _plan("POST", VulnClass.SQLI, "username"), payload
    )
    argv = shlex.split(cmd)
    assert argv[:4] == ["curl", "-s", "-X", "POST"]
    assert argv[4] == "http://127.0.0.1:5000/login"
    # each form field is its own --data-urlencode arg, so '&' in the payload
    # cannot inject or clobber the password field
    assert argv[5:] == [
        "--data-urlencode", f"username={payload}",
        "--data-urlencode", "password=x",
    ]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_get_payload_survives_shell_quoting(payload):
    cmd = ProbeHarness(port=5000)._build_probe_command(
        _plan("GET", VulnClass.CMDI, "ip"), payload
    )
    argv = shlex.split(cmd)
    assert argv == [
        "curl", "-s", "-G", "http://127.0.0.1:5000/login",
        "--data-urlencode", f"ip={payload}",
    ]


class _ScriptSandbox:
    """Captures the probe script instead of running it."""

    def __init__(self, workdir):
        self.default_workdir = workdir
        self.scripts = []

    async def run(self, command=None, *, shell=None, **kwargs):
        from shipcheck.sandbox.base import SandboxResult
        self.scripts.append(shell)
        return SandboxResult(exit_code=0, stdout="", stderr="")


async def test_probe_defaults_to_the_sandboxes_own_workdir():
    sandbox = _ScriptSandbox("/tmp/sandbox dir/child")
    plan = _plan("GET", VulnClass.XSS, "q")
    await ProbeHarness(port=5000).execute_step(sandbox, plan)
    assert "cd '/tmp/sandbox dir/child' ||" in sandbox.scripts[0]


async def test_explicit_target_dir_wins():
    sandbox = _ScriptSandbox("/tmp/ignored")
    await ProbeHarness(port=5000).execute_step(sandbox, _plan("GET", VulnClass.XSS, "q"), target_dir="/workspace")
    assert "cd /workspace ||" in sandbox.scripts[0]


def test_local_backend_reports_its_temp_dir():
    from shipcheck.sandbox.local_docker_backend import LocalDockerBackend
    sb = LocalDockerBackend()
    try:
        assert sb.default_workdir == str(sb.workdir)
    finally:
        sb.cleanup()


@pytest.mark.parametrize("payload, expected", [
    ("../../../etc/passwd", "../" * 12 + "etc/passwd"),
    ("../" * 15 + "etc/passwd", "../" * 15 + "etc/passwd"),  # never shortened
    ("/etc/passwd", "/etc/passwd"),                          # no leading run: untouched
    ("..%2f..%2fetc/passwd", "..%2f..%2fetc/passwd"),         # encoded variants untouched
])
def test_traversal_payload_padding(payload, expected):
    assert ProbeHarness._deepen_traversal(payload) == expected


async def test_traversal_probe_sends_padded_payload():
    sandbox = _ScriptSandbox("/w")
    plan = AttackPlan(vuln_class=VulnClass.TRAVERSAL, target_file="app.py", sink="open",
                      payload_strategy="s", expected_marker="root:", route="/download",
                      http_method="GET", parameter_name="file", suggested_payload="../../etc/passwd")
    evidence = await ProbeHarness(port=5000).execute_step(sandbox, plan)
    assert evidence.payload == "../" * 12 + "etc/passwd"  # evidence records what was sent
    assert "file=" + "../" * 12 + "etc/passwd" in sandbox.scripts[0]
