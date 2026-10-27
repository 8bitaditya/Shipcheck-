"""Tests for the scan orchestrator (chains triage -> plan -> probe -> verdict -> rectify).

Each stage is replaced with a deterministic stub so the wiring, plan-to-finding
matching, verdict scoring and the rectify gate are exercised offline without
containers, network or an LLM.
"""

from pathlib import Path
from typing import Dict, List, Optional, Union

from shipcheck.contracts.attack_plan import AttackPlan, AttackPlanBatch, VulnClass
from shipcheck.contracts.evidence import Evidence, ProbeVerdict
from shipcheck.contracts.finding import Finding, FindingTarget
from shipcheck.contracts.fix import DiffHunk, FixPatch, FixStatus
from shipcheck.contracts.verdict import VerdictStatus
from shipcheck.orchestrator import ScanResult, ShipCheckScanner
from shipcheck.sandbox.base import SandboxBase, SandboxResult


# --------------------------------------------------------------------------- #
# Stubs                                                                       #
# --------------------------------------------------------------------------- #
class StubTriage:
    def __init__(self, findings: List[Finding]):
        self._findings = findings

    async def run_triage(self, sandbox, changed_files=None) -> List[Finding]:
        return list(self._findings)


class StubPlanner:
    def __init__(self, batch: AttackPlanBatch):
        self._batch = batch

    async def plan_attacks(self, diff_text, findings, commit_sha="HEAD") -> AttackPlanBatch:
        return self._batch


class StubHarness:
    def __init__(self, marker_found: bool):
        self.marker_found = marker_found

    async def execute_step(self, sandbox, plan, app_cmd="python app.py", target_dir="/workspace"):
        return Evidence(
            plan_id=plan.plan_id,
            payload=plan.suggested_payload or "x",
            request={"endpoint": plan.route or "/"},
            response_status=200,
            response_excerpt="out",
            verdict=ProbeVerdict.CONFIRMED if self.marker_found else ProbeVerdict.UNCONFIRMED,
            marker_found=self.marker_found,
            target_marker=plan.expected_marker,
            matched_text=plan.expected_marker if self.marker_found else None,
        )


class StubRectifier:
    def __init__(self, verified: bool = True):
        self.verified = verified
        self.calls = 0

    async def apply_and_verify(self, finding, plan, sandbox, **kwargs) -> FixPatch:
        self.calls += 1
        return FixPatch(
            finding_id=finding.finding_id,
            hunks=[DiffHunk(file="app.py", search="a = 1", replace="a = 2")],
            status=FixStatus.VERIFIED_PASSED if self.verified else FixStatus.VERIFIED_FAILED,
            recheck_attack_marker_absent=self.verified,
            repo_tests_passed=self.verified,
        )


class StubSandbox(SandboxBase):
    def __init__(self):
        self.files: Dict[str, str] = {"app.py": "a = 1\n"}

    async def read_file(self, remote_path: str) -> bytes:
        return self.files.get(remote_path, "").encode("utf-8")

    async def apply_files(self, files: Dict[str, Union[str, bytes, Path]]) -> None:
        for k, v in files.items():
            self.files[k] = v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else str(v)

    async def fork(self) -> "StubSandbox":
        return StubSandbox()

    async def run(self, command=None, *, shell=None, env=None, cwd=None,
                  timeout=45.0, disposable=True, files=None) -> SandboxResult:
        return SandboxResult(exit_code=0, stdout="ok", stderr="")

    async def checkpoint(self, tag: Optional[str] = None) -> str:
        return tag or "cp"

    async def download_file(self, remote_path, local_path):
        return Path(local_path)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def _finding(vuln: VulnClass, file: str, endpoint: str) -> Finding:
    return Finding(
        vuln_class=vuln,
        title=f"{vuln.value} in {file}",
        target=FindingTarget(file=file, sink="sink()", endpoint=endpoint),
        tool="semgrep",
        rule_id="r",
    )


def _plan(vuln: VulnClass, file: str, route: str, marker: str) -> AttackPlan:
    return AttackPlan(
        vuln_class=vuln,
        target_file=file,
        sink="sink()",
        payload_strategy="s",
        expected_marker=marker,
        route=route,
        suggested_payload="payload",
    )


def _scanner(findings, plans, *, marker_found, rectifier) -> ShipCheckScanner:
    return ShipCheckScanner(
        triage=StubTriage(findings),
        planner=StubPlanner(AttackPlanBatch(plans=plans)),
        harness=StubHarness(marker_found=marker_found),
        rectifier=rectifier,
    )


DIFF = "diff --git a/app.py b/app.py\n+++ b/app.py\n"


# --------------------------------------------------------------------------- #
# Tests                                                                       #
# --------------------------------------------------------------------------- #
async def test_scan_confirmed_is_scored_and_fixed():
    finding = _finding(VulnClass.SQLI, "app.py", "/login")
    plan = _plan(VulnClass.SQLI, "app.py", "/login", "admin")
    rect = StubRectifier(verified=True)
    scanner = _scanner([finding], [plan], marker_found=True, rectifier=rect)

    result = await scanner.scan(StubSandbox(), DIFF, changed_files={"app.py"})

    assert isinstance(result, ScanResult)
    assert result.findings_count == 1
    assert result.confirmed_count == 1
    assert result.fixed_count == 1
    f = result.findings[0]
    assert f.probe is plan
    assert f.evidence is not None and f.evidence.marker_found is True
    assert f.verdict is not None and f.verdict.status == VerdictStatus.CONFIRMED
    assert f.verdict.score > 0
    assert f.fix is not None and f.fix.is_verified_for_pr() is True
    assert result.overall_risk_score == f.verdict.score


async def test_scan_unconfirmed_is_not_rectified():
    finding = _finding(VulnClass.SQLI, "app.py", "/login")
    plan = _plan(VulnClass.SQLI, "app.py", "/login", "admin")
    rect = StubRectifier(verified=True)
    scanner = _scanner([finding], [plan], marker_found=False, rectifier=rect)

    result = await scanner.scan(StubSandbox(), DIFF, changed_files={"app.py"})

    assert result.confirmed_count == 0
    assert result.fixed_count == 0
    assert rect.calls == 0  # rectifier never invoked for unconfirmed findings
    f = result.findings[0]
    assert f.verdict.status == VerdictStatus.UNCONFIRMED
    assert f.verdict.score <= 5.0  # 0.05x dampener keeps unconfirmed near zero
    assert f.fix is None


async def test_plans_matched_to_correct_findings():
    f_sql = _finding(VulnClass.SQLI, "app.py", "/login")
    f_xss = _finding(VulnClass.XSS, "views.py", "/search")
    p_sql = _plan(VulnClass.SQLI, "app.py", "/login", "admin")
    p_xss = _plan(VulnClass.XSS, "views.py", "/search", "<script>")
    scanner = _scanner(
        [f_sql, f_xss], [p_sql, p_xss], marker_found=True, rectifier=StubRectifier()
    )

    result = await scanner.scan(StubSandbox(), DIFF, changed_files={"app.py", "views.py"})

    by_file = {f.target.file: f for f in result.findings}
    assert by_file["app.py"].probe is p_sql
    assert by_file["views.py"].probe is p_xss
    assert by_file["app.py"].evidence.plan_id == p_sql.plan_id
    assert by_file["views.py"].evidence.plan_id == p_xss.plan_id


async def test_rectify_can_be_disabled():
    finding = _finding(VulnClass.SQLI, "app.py", "/login")
    plan = _plan(VulnClass.SQLI, "app.py", "/login", "admin")
    rect = StubRectifier(verified=True)
    scanner = _scanner([finding], [plan], marker_found=True, rectifier=rect)

    result = await scanner.scan(StubSandbox(), DIFF, changed_files={"app.py"}, rectify=False)

    assert result.confirmed_count == 1
    assert rect.calls == 0
    assert result.fixed_count == 0
    assert result.findings[0].fix is None
