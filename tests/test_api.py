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


def test_demo_replays_the_golden_run(client):
    resp = client.get("/api/demo")
    assert resp.status_code == 200
    assert resp.headers["X-ShipCheck-Demo-Source"] == "golden"
    data = resp.json()
    assert data["confirmed_count"] == 4 and data["fixed_count"] == 4
    classes = {f["vuln_class"] for f in data["findings"] if f["evidence"] and f["evidence"]["marker_found"]}
    assert classes == {"sqli", "cmdi", "traversal", "xss"}
    for f in data["findings"]:
        if f["fix"]:
            assert f["fix"]["status"] == "VERIFIED_PASSED"
            assert f["grounding"]["provider"] == "tavily"
    assert data["pull_requests"][0]["url"].endswith("/pull/1")
    assert "groups=<redacted>" in resp.text or "groups=" not in resp.text  # recorder redacted


def test_demo_falls_back_to_sample_without_golden(client, monkeypatch, tmp_path):
    monkeypatch.setattr("shipcheck.golden.GOLDEN_PATH", tmp_path / "missing.json")
    resp = client.get("/api/demo")
    assert resp.headers["X-ShipCheck-Demo-Source"] == "sample"
    data = resp.json()
    assert data["findings_count"] == 1 and data["pull_requests"][0]["number"] == 7
    f = data["findings"][0]
    assert f["grounding"]["provider"] == "static"  # sample says it is offline
    assert "CWE-89" in f["grounding"]["advisory_ids"]


def test_redaction_strips_local_details():
    from shipcheck.golden import redact_local_details
    raw = ("uid=501(alice) gid=20(staff) groups=20(staff),12(everyone) "
           "/private/var/folders/3q/abc/T/shipcheck_sandbox_x1y2/app.py")
    out = redact_local_details(raw)
    assert out.startswith("uid=501(sandbox) gid=20(sandbox) groups=<redacted>")
    assert "<sandbox>/app.py" in out and "alice" not in out


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



def test_public_demo_disables_live_scans(client, monkeypatch):
    from shipcheck import config
    monkeypatch.setattr(config, "PUBLIC_DEMO", True)
    called = []

    async def runner(req):
        called.append(req)

    app.dependency_overrides[get_scan_runner] = lambda: runner
    try:
        resp = client.post("/scan", json={"diff": "d", "source_files": {"app.py": "x"}})
    finally:
        app.dependency_overrides.clear()
    assert resp.status_code == 403 and called == []
    assert client.get("/api/config").json() == {"public_demo": True}
    assert client.get("/api/demo").status_code == 200  # the replay still works


def test_live_scans_allowed_by_default(client):
    assert client.get("/api/config").json() == {"public_demo": False}
