"""Tests for the FR-8 FastAPI app.

The scan runner is overridden with a canned ScanResult so the HTTP layer
(routing, request/response shapes, the dashboard, the demo view) is tested
without the real sandbox/LLM pipeline.
"""

import pytest
from fastapi.testclient import TestClient

from shipcheck.api.main import app, get_scan_runner
from shipcheck.contracts.attack_plan import VulnClass
from shipcheck.contracts.finding import Finding, FindingTarget
from shipcheck.orchestrator import ScanResult


@pytest.fixture
def client():
    return TestClient(app)


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_dashboard_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "ShipCheck" in resp.text
    assert 'id="scan"' in resp.text  # the scan button is present


def test_demo_returns_confirmed_fixed_finding(client):
    resp = client.get("/api/demo")
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings_count"] == 1
    assert data["confirmed_count"] == 1
    assert data["fixed_count"] == 1
    assert data["pull_requests"][0]["number"] == 7
    f = data["findings"][0]
    assert f["vuln_class"] == "sqli"
    assert f["verdict"]["score"] > 0
    assert f["fix"]["recheck_attack_marker_absent"] is True
    # demo grounding is the offline reference and says so
    assert f["grounding"]["provider"] == "static"
    assert "CWE-89" in f["grounding"]["advisory_ids"]


def test_scan_uses_injected_runner(client):
    canned = ScanResult(
        commit_sha="t",
        findings=[Finding(
            vuln_class=VulnClass.XSS, title="x",
            target=FindingTarget(file="views.py"), tool="semgrep", rule_id="r",
        )],
        findings_count=1, confirmed_count=0, fixed_count=0, overall_risk_score=4.0,
    )

    async def fake_runner(req):
        return canned

    app.dependency_overrides[get_scan_runner] = lambda: fake_runner
    try:
        resp = client.post("/scan", json={"diff": "d", "source_files": {"views.py": "x"}})
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    body = resp.json()
    assert body["findings_count"] == 1
    assert body["overall_risk_score"] == 4.0
    assert body["findings"][0]["vuln_class"] == "xss"
