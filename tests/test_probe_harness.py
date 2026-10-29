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
