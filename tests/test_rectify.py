"""Tests for the FR-6 rectification engine (fix generation + re-verify gate).

These run fully offline: fix generation uses an injected fake LLM (or the
bundled mock), and the re-verify loop uses stub sandbox/harness so the gate
logic is exercised deterministically without real containers, ports or curl.
"""

from pathlib import Path
from typing import Dict, Optional, Union

import pytest

from shipcheck.contracts.attack_plan import AttackPlan, VulnClass
from shipcheck.contracts.evidence import Evidence, ProbeVerdict
from shipcheck.contracts.finding import Finding, FindingTarget
from shipcheck.contracts.fix import FixStatus
from shipcheck.rectify.fixer import RectificationEngine
from shipcheck.sandbox.base import SandboxBase, SandboxResult

# A tiny vulnerable source file and the exact fix for it.
VULN_LINE = "    q = \"SELECT * FROM users WHERE n='\" + name + \"'\""
SOURCE = "def login(name):\n" + VULN_LINE + "\n    return db.execute(q)\n"
FIXED_LINE = "    q = \"SELECT * FROM users WHERE n=?\"  # parameterized"

VALID_PAYLOAD = {
    "hunks": [{"file": "app.py", "search": VULN_LINE, "replace": FIXED_LINE}],
    "root_cause": "user input concatenated into SQL",
    "explanation": "parameterized query removes the injection",
}
ABSENT_PAYLOAD = {
    "hunks": [{"file": "app.py", "search": "this text is not in the file", "replace": "x"}],
}


# --------------------------------------------------------------------------- #
# Stubs                                                                       #
# --------------------------------------------------------------------------- #
class FakeLLM:
    """Returns a fixed JSON object from complete_json, ignoring the prompt."""

    def __init__(self, payload):
        self.payload = payload

    async def complete_json(self, prompt, system_prompt=None, tier="super", max_tokens=4096):
        return self.payload


class StubSandbox(SandboxBase):
    """In-memory sandbox: holds files, forks by copy, returns a fixed test exit code."""

    def __init__(self, files: Dict[str, str], test_exit: int = 0):
        self.files = dict(files)
        self.test_exit = test_exit

    async def read_file(self, remote_path: str) -> bytes:
        if remote_path not in self.files:
            raise FileNotFoundError(remote_path)
        return self.files[remote_path].encode("utf-8")

    async def apply_files(self, files: Dict[str, Union[str, bytes, Path]]) -> None:
        for k, v in files.items():
            self.files[k] = v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else str(v)

    async def fork(self) -> "StubSandbox":
        return StubSandbox(self.files, self.test_exit)

    async def run(self, command=None, *, shell=None, env=None, cwd=None,
                  timeout=45.0, disposable=True, files=None) -> SandboxResult:
        out = "collected 3 items\n3 passed" if self.test_exit == 0 else "1 failed, 2 passed"
        return SandboxResult(exit_code=self.test_exit, stdout=out, stderr="")

    async def checkpoint(self, tag: Optional[str] = None) -> str:
        return tag or "cp"

    async def download_file(self, remote_path, local_path):
        return Path(local_path)


class StubHarness:
    """Returns an Evidence whose marker_found is fixed, standing in for a re-probe."""

    def __init__(self, marker_found: bool):
        self.marker_found = marker_found

    async def execute_step(self, sandbox, plan, app_cmd="python app.py", target_dir="/workspace"):
        return Evidence(
            plan_id=plan.plan_id,
            payload=plan.suggested_payload or "x",
            request={"endpoint": plan.route or "/"},
            response_status=200,
            response_excerpt="patched output",
            verdict=ProbeVerdict.CONFIRMED if self.marker_found else ProbeVerdict.UNCONFIRMED,
            marker_found=self.marker_found,
            target_marker=plan.expected_marker,
        )


# --------------------------------------------------------------------------- #
# Fixtures / helpers                                                          #
# --------------------------------------------------------------------------- #
def _sqli_plan() -> AttackPlan:
    return AttackPlan(
        vuln_class=VulnClass.SQLI,
        target_file="app.py",
        sink="db.execute(q)",
        payload_strategy="boolean bypass",
        expected_marker="admin",
        route="/login",
        http_method="POST",
        parameter_name="name",
        suggested_payload="' OR 1=1--",
    )


def _sqli_finding() -> Finding:
    evidence = Evidence.capture(
        payload="' OR 1=1--",
        request={"endpoint": "/login", "method": "POST"},
        response_status=200,
        raw_output="... admin@shop.local ...",
        expected_marker="admin",
    )
    return Finding(
        vuln_class=VulnClass.SQLI,
        title="SQL injection in login",
        target=FindingTarget(file="app.py", sink="db.execute(q)", endpoint="/login"),
        evidence=evidence,
        tool="semgrep",
        rule_id="python.sqli",
    )


def _engine(llm_payload=None, marker_found=False) -> RectificationEngine:
    eng = RectificationEngine(harness=StubHarness(marker_found=marker_found))
    if llm_payload is not None:
        eng.llm = FakeLLM(llm_payload)
    return eng


# --------------------------------------------------------------------------- #
# Stage 1: fix generation / parsing                                           #
# --------------------------------------------------------------------------- #
async def test_generate_fix_parses_bundled_mock():
    """The bundled mock LLM returns canonical {file,search,replace} hunks."""
    eng = RectificationEngine(harness=StubHarness(marker_found=False))
    patch = await eng.generate_fix(_sqli_finding(), SOURCE)
    assert len(patch.hunks) == 1
    assert patch.hunks[0].file == "app.py"
    assert "SELECT" in patch.hunks[0].search
    assert patch.finding_id is not None


def test_parse_legacy_hunk_shape():
    """Legacy field names (file_path/search_block/replace_block) still parse."""
    patch = RectificationEngine._parse_fix(
        {"hunks": [{"file_path": "a.py", "search_block": "x = 1", "replace_block": "x = 2"}]},
        "find-1",
    )
    assert len(patch.hunks) == 1
    assert patch.hunks[0].file == "a.py"
    assert patch.hunks[0].search == "x = 1"
    assert patch.hunks[0].replace == "x = 2"


# --------------------------------------------------------------------------- #
# Stage 2: apply + re-verify gate                                             #
# --------------------------------------------------------------------------- #
async def test_reject_when_search_not_found():
    """A hunk whose search text is absent is rejected before any re-probe."""
    eng = _engine(llm_payload=ABSENT_PAYLOAD, marker_found=False)
    sandbox = StubSandbox({"app.py": SOURCE})
    patch = await eng.apply_and_verify(_sqli_finding(), _sqli_plan(), sandbox)
    assert patch.status == FixStatus.REJECTED_SEARCH_NOT_FOUND
    assert patch.recheck_attack_marker_absent is None  # never got to re-probe
    assert patch.is_verified_for_pr() is False


async def test_verified_passed_when_marker_gone_and_tests_pass():
    """Marker absent after patch AND repo tests pass -> VERIFIED_PASSED (eligible for PR)."""
    eng = _engine(llm_payload=VALID_PAYLOAD, marker_found=False)
    sandbox = StubSandbox({"app.py": SOURCE}, test_exit=0)
    patch = await eng.apply_and_verify(_sqli_finding(), _sqli_plan(), sandbox)
    assert patch.status == FixStatus.VERIFIED_PASSED
    assert patch.recheck_attack_marker_absent is True
    assert patch.repo_tests_passed is True
    assert patch.is_verified_for_pr() is True
    # The original sandbox is untouched; the patch was applied in a fork.
    assert sandbox.files["app.py"] == SOURCE


async def test_verified_failed_when_marker_still_present():
    """If the re-attack still fires, the fix fails -- never silently downgraded."""
    eng = _engine(llm_payload=VALID_PAYLOAD, marker_found=True)
    sandbox = StubSandbox({"app.py": SOURCE}, test_exit=0)
    patch = await eng.apply_and_verify(_sqli_finding(), _sqli_plan(), sandbox)
    assert patch.status == FixStatus.VERIFIED_FAILED
    assert patch.recheck_attack_marker_absent is False
    assert patch.is_verified_for_pr() is False


async def test_verified_failed_when_tests_break():
    """Marker gone but repo tests fail -> VERIFIED_FAILED (regression gate)."""
    eng = _engine(llm_payload=VALID_PAYLOAD, marker_found=False)
    sandbox = StubSandbox({"app.py": SOURCE}, test_exit=1)
    patch = await eng.apply_and_verify(_sqli_finding(), _sqli_plan(), sandbox)
    assert patch.status == FixStatus.VERIFIED_FAILED
    assert patch.recheck_attack_marker_absent is True
    assert patch.repo_tests_passed is False
    assert patch.is_verified_for_pr() is False
