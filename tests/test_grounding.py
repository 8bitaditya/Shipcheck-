"""Tests for Tavily advisory grounding (FR-5 / G4).

Tavily is replaced with httpx.MockTransport, so the request shape, ID and
version extraction, URL sanitising and the honest offline fallback are tested
without network or an API key.
"""

import json

import httpx

from shipcheck.contracts.attack_plan import VulnClass
from shipcheck.contracts.finding import Finding, FindingTarget
from shipcheck.contracts.fix import DiffHunk, FixPatch, FixStatus
from shipcheck.planning.tavily_client import TAVILY_SEARCH_URL, TavilyGroundingClient
from shipcheck.pr.body import render_pr_body


def _finding(vuln=VulnClass.SQLI, **kw) -> Finding:
    return Finding(
        vuln_class=vuln, title="SQL injection in login",
        target=FindingTarget(file="app.py", sink="conn.execute", endpoint="/login"),
        tool="semgrep", rule_id="r", **kw,
    )


TAVILY_RESPONSE = {
    "answer": "Use parameterized queries. See CVE-2024-12345 and GHSA-2c2j-m6r6-xmq9 (CWE-89).",
    "results": [
        {"title": "NVD CVE-2024-12345", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
         "content": "SQL injection in foo before 2.3.1 allows ..."},
        {"title": "evil", "url": "javascript:alert(1)", "content": ""},
        {"title": "OWASP\nCheat <b>Sheet</b>", "url": "https://cheatsheetseries.owasp.org/x.html",
         "content": "prepared statements"},
    ],
}


def _client(captured: list, status: int = 200) -> TavilyGroundingClient:
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(status, json=TAVILY_RESPONSE)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return TavilyGroundingClient(api_key="tvly-test", client=http)


async def test_live_grounding_extracts_ids_and_sources():
    captured = []
    g = await _client(captured).ground_finding(_finding())

    req = captured[0]
    assert str(req.url) == TAVILY_SEARCH_URL
    assert req.headers["Authorization"] == "Bearer tvly-test"
    body = json.loads(req.content)
    assert body["include_answer"] is True
    assert "api_key" not in body  # key travels in the header only
    assert "CWE-89" in body["query"] and len(body["query"]) <= 400

    assert g.provider == "tavily" and g.is_live
    assert g.advisory_ids[:3] == ["CVE-2024-12345", "GHSA-2C2J-M6R6-XMQ9", "CWE-89"]
    assert g.cwe_id == "CWE-89"
    assert g.canonical_fix.startswith("Use parameterized queries")
    # the javascript: URL is dropped; titles are flattened
    assert [s.url for s in g.sources] == [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
        "https://cheatsheetseries.owasp.org/x.html",
    ]
    assert "\n" not in g.sources[1].title
    # first-party code: no affected-version claims borrowed from unrelated CVEs
    assert g.affected_versions == []


async def test_dependency_finding_gets_affected_versions():
    g = await _client([]).ground_finding(
        _finding(VulnClass.DEPS, cve_id="CVE-2024-12345")
    )
    assert g.advisory_ids[0] == "CVE-2024-12345"
    assert "before 2.3.1" in g.affected_versions


async def test_no_api_key_uses_labelled_static_fallback():
    calls = []
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: calls.append(r)))
    g = await TavilyGroundingClient(api_key="", client=http).ground_finding(_finding())

    assert calls == []  # never touches the network
    assert g.provider == "static" and not g.is_live
    assert g.advisory_ids == ["CWE-89"]
    assert "parameterized" in g.canonical_fix
    assert "TAVILY_API_KEY" in g.note


async def test_tavily_http_error_falls_back():
    g = await _client([], status=500).ground_finding(_finding())
    assert g.provider == "static"
    assert "HTTPStatusError" in g.note


async def test_pr_body_cites_grounding():
    f = _finding()
    f.grounding = await _client([]).ground_finding(f)
    f.fix = FixPatch(
        finding_id=f.finding_id,
        hunks=[DiffHunk(file="app.py", search="a", replace="b")],
        status=FixStatus.VERIFIED_PASSED,
        recheck_attack_marker_absent=True, repo_tests_passed=True,
    )
    body = render_pr_body(f)

    assert "### 2. Advisory grounding" in body
    assert "_Source: Tavily search._" in body
    assert "`CVE-2024-12345`" in body
    assert "first-party code" in body
    assert "(https://nvd.nist.gov/vuln/detail/CVE-2024-12345)" in body
    assert "javascript:" not in body
    assert "<b>" not in body  # untrusted HTML in titles is escaped


def test_pr_body_marks_static_fallback_honestly():
    f = _finding()
    f.grounding = TavilyGroundingClient.static_grounding(f, note="TAVILY_API_KEY not set")
    body = render_pr_body(f)
    assert "not a live Tavily lookup" in body
    assert "`CWE-89`" in body
