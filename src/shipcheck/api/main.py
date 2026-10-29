"""FastAPI app + dashboard for ShipCheck (FR-8).

Endpoints:
    GET  /          single-page dashboard
    GET  /health    liveness probe
    POST /scan      run a scan, return a ScanResult as JSON
    GET  /api/demo  a recorded sample ScanResult (watchable without a live scan)

The app is stateless. The scan runner is a dependency so tests (and a future
golden-run replay) can override it without the real sandbox/LLM pipeline.
"""

from __future__ import annotations

import shlex
import socket
import sys
from typing import Callable, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from shipcheck import config
from shipcheck.api.dashboard import DASHBOARD_HTML
from shipcheck.contracts.attack_plan import AttackPlan, VulnClass
from shipcheck.contracts.evidence import Evidence
from shipcheck.contracts.finding import Finding, FindingTarget
from shipcheck.contracts.fix import DiffHunk, FixPatch, FixStatus
from shipcheck.contracts.verdict import SeverityLevel, VerdictCard
from shipcheck.golden import load_golden
from shipcheck.orchestrator import ScanResult, ShipCheckScanner
from shipcheck.planning.tavily_client import TavilyGroundingClient
from shipcheck.probes.harness import ProbeHarness
from shipcheck.rectify.fixer import RectificationEngine
from shipcheck.sandbox.client import SandboxClient
from shipcheck.sandbox.local_docker_backend import LocalDockerBackend

app = FastAPI(title="ShipCheck", version="0.1.0")


class ScanRequest(BaseModel):
    """Input for POST /scan."""

    diff: str = Field(default="", description="Unified PR diff")
    commit_sha: str = Field(default="HEAD")
    source_files: Dict[str, str] = Field(
        default_factory=dict,
        description="Map of repo-relative path -> file content to materialize in the sandbox",
    )
    changed_files: Optional[List[str]] = None
    open_prs: bool = False
    app_cmd: Optional[str] = Field(
        default=None, description="Command that starts the target app (default: python app.py)"
    )
    test_cmd: Optional[str] = Field(
        default=None, description="Repo test command for the regression gate (default: python -m pytest -q)"
    )


async def default_scan_runner(req: ScanRequest) -> ScanResult:
    """Production scan: materialize the files in a sandbox and run the orchestrator."""
    client = SandboxClient(backend_type=config.SANDBOX_BACKEND)
    sandbox = client.create_sandbox()
    app_cmd = req.app_cmd or "python app.py"
    test_cmd = req.test_cmd or "python -m pytest -q"
    if isinstance(sandbox, LocalDockerBackend):
        # Local sandboxes share the host network: macOS already listens on
        # :5000 (AirPlay) and parallel probes would collide, so use one free
        # port, one probe at a time, and this interpreter (no bare `python`).
        port = _free_port()
        py = shlex.quote(sys.executable)
        app_cmd = f"PORT={port} " + (req.app_cmd or f"{py} app.py")
        test_cmd = req.test_cmd or f"{py} -m pytest -q"
        harness = ProbeHarness(port=port)
        scanner = ShipCheckScanner(
            harness=harness, rectifier=RectificationEngine(harness=harness), max_concurrent=1
        )
    else:
        # Container / microVM sandboxes each have their own loopback.
        scanner = ShipCheckScanner()
    try:
        if req.source_files:
            await sandbox.apply_files(dict(req.source_files))
        return await scanner.scan(
            sandbox,
            req.diff,
            commit_sha=req.commit_sha,
            changed_files=set(req.changed_files) if req.changed_files else None,
            app_cmd=app_cmd,
            test_cmd=test_cmd,
            open_prs=req.open_prs,
        )
    finally:
        sandbox.cleanup()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get_scan_runner() -> Callable[[ScanRequest], "ScanResult"]:
    """Dependency returning the scan runner. Overridden in tests / replay mode."""
    return default_scan_runner


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "shipcheck"}


@app.get("/api/config")
async def api_config() -> Dict[str, bool]:
    """What the dashboard may offer on this deployment."""
    return {"public_demo": config.PUBLIC_DEMO}


@app.post("/scan", response_model=ScanResult)
async def scan(req: ScanRequest, runner=Depends(get_scan_runner)) -> ScanResult:
    if config.PUBLIC_DEMO:
        # A live scan executes the submitted code and spends Nemotron/Tavily
        # credits, so a public demo URL must not offer it to anyone.
        raise HTTPException(
            status_code=403,
            detail="Live scans are disabled on the public demo. It replays a recorded real scan "
                   "(GET /api/demo). Run ShipCheck locally to scan your own code.",
        )
    return await runner(req)


@app.get("/api/demo", response_model=ScanResult)
async def demo(response: Response) -> ScanResult:
    """Replay the recorded real scan (golden/), so the demo never needs a live call.

    Falls back to a hand-built sample if no recording is present. The
    X-ShipCheck-Demo-Source header says which one was served.
    """
    golden = load_golden()
    response.headers["X-ShipCheck-Demo-Source"] = "golden" if golden else "sample"
    return golden or _demo_result()


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    return DASHBOARD_HTML


def _demo_result() -> ScanResult:
    """Hand-built fallback (one confirmed-and-fixed SQLi) used when golden/ is absent."""
    finding = Finding(
        vuln_class=VulnClass.SQLI,
        title="SQL injection in login handler",
        target=FindingTarget(
            file="app.py", line=42, sink="db.execute(query)", endpoint="/login",
            code_snippet="query = \"... WHERE username = '%s'\" % username",
        ),
        severity=SeverityLevel.CRITICAL,
        tool="semgrep",
        rule_id="python.flask.sqli",
        cwe_id="CWE-89",
    )
    finding.probe = AttackPlan(
        vuln_class=VulnClass.SQLI, target_file="app.py", sink="db.execute(query)",
        payload_strategy="boolean authentication bypass", expected_marker="admin@vulnshop.local",
        route="/login", http_method="POST", parameter_name="username",
        suggested_payload="admin' OR '1'='1' -- ",
    )
    finding.evidence = Evidence.capture(
        payload="admin' OR '1'='1' -- ",
        request={"endpoint": "/login", "method": "POST"},
        response_status=200,
        raw_output="Welcome: admin <admin@vulnshop.local>, alice <alice@vulnshop.local>",
        expected_marker="admin@vulnshop.local",
    )
    finding.verdict = VerdictCard.from_probe(
        finding_id=finding.finding_id, severity=SeverityLevel.CRITICAL,
        marker_verified=True, expected_marker="admin@vulnshop.local",
        observed_marker="admin@vulnshop.local", vuln_title=finding.title,
    )
    finding.fix = FixPatch(
        finding_id=finding.finding_id,
        hunks=[DiffHunk(
            file="app.py",
            search="query = \"SELECT username, email FROM users WHERE username = '%s' AND password = '%s'\" % (username, password)",
            replace="query = \"SELECT username, email FROM users WHERE username = ? AND password = ?\"\n    rows = conn.execute(query, (username, password)).fetchall()",
        )],
        root_cause="User input concatenated directly into the SQL string.",
        explanation="Use a parameterized query so input is bound, not interpolated.",
        status=FixStatus.VERIFIED_PASSED,
        recheck_attack_marker_absent=True,
        repo_tests_passed=True,
        verification_log="Re-probe verdict: UNCONFIRMED (marker_found=False)\nRepo tests exit_code=0",
    )
    # Sample view only: offline CWE/OWASP grounding, labelled as such (not a Tavily call).
    finding.grounding = TavilyGroundingClient.static_grounding(
        finding, note="Demo sample: offline reference shown; live scans query Tavily when TAVILY_API_KEY is set"
    )
    return ScanResult(
        commit_sha="demo",
        findings=[finding],
        findings_count=1,
        confirmed_count=1,
        fixed_count=1,
        overall_risk_score=finding.verdict.score,
        pull_requests=[{
            "finding_id": finding.finding_id,
            "number": 7,
            "url": "https://github.com/8bitaditya/Shipcheck-/pull/7",
        }],
    )
