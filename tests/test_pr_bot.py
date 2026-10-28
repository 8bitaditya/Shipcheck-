"""Tests for the FR-7 GitHub PR bot.

All GitHub calls go through an httpx.MockTransport, so the bot's behaviour is
asserted offline: the draft flag, dedupe by head ref, the "No PASS, No PR"
refusal, and that the merge endpoint is never touched.
"""

import base64
import json
from typing import List, Optional

import httpx
import pytest

from shipcheck.contracts.attack_plan import AttackPlan, VulnClass
from shipcheck.contracts.evidence import Evidence
from shipcheck.contracts.finding import Finding, FindingTarget
from shipcheck.contracts.fix import DiffHunk, FixPatch, FixStatus
from shipcheck.contracts.verdict import SeverityLevel, VerdictCard
from shipcheck.pr import GitHubPRBot, branch_name, pr_title, render_pr_body

SOURCE = "a = 1\n"


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #
def _finding(*, verified: bool = True) -> Finding:
    f = Finding(
        vuln_class=VulnClass.SQLI,
        title="SQL injection in login",
        target=FindingTarget(file="app.py", sink="db.execute", endpoint="/login"),
        severity=SeverityLevel.HIGH,
        tool="semgrep",
        rule_id="python.sqli",
    )
    f.probe = AttackPlan(
        vuln_class=VulnClass.SQLI, target_file="app.py", sink="db.execute",
        payload_strategy="bypass", expected_marker="admin", route="/login",
        suggested_payload="' OR 1=1--",
    )
    f.evidence = Evidence.capture(
        payload="' OR 1=1--", request={"endpoint": "/login"}, response_status=200,
        raw_output="... admin@shop.local ...", expected_marker="admin",
    )
    f.verdict = VerdictCard.from_probe(
        finding_id=f.finding_id, severity=SeverityLevel.HIGH,
        marker_verified=True, expected_marker="admin", vuln_title=f.title,
    )
    f.fix = FixPatch(
        finding_id=f.finding_id,
        hunks=[DiffHunk(file="app.py", search="a = 1", replace="a = 2")],
        root_cause="input concatenated into SQL",
        explanation="use a parameterized query",
        status=FixStatus.VERIFIED_PASSED if verified else FixStatus.VERIFIED_FAILED,
        recheck_attack_marker_absent=True,
        repo_tests_passed=verified,
    )
    return f


class _Recorder:
    """httpx.MockTransport handler that records requests and returns canned replies."""

    def __init__(self, existing_prs: Optional[List[dict]] = None):
        self.requests: List[httpx.Request] = []
        self.existing_prs = existing_prs or []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path, method = request.url.path, request.method

        if path.endswith("/pulls") and method == "GET":
            return httpx.Response(200, json=self.existing_prs)
        if path.endswith("/pulls") and method == "POST":
            return httpx.Response(201, json={"number": 7, "draft": True,
                                             "html_url": "https://github.com/o/r/pull/7"})
        if "/pulls/" in path and method == "PATCH":
            return httpx.Response(200, json={"number": self.existing_prs[0]["number"]})
        if "/git/ref/heads/" in path and method == "GET":
            return httpx.Response(200, json={"object": {"sha": "basesha123"}})
        if path.endswith("/git/refs") and method == "POST":
            return httpx.Response(201, json={})
        if "/contents/" in path and method == "GET":
            return httpx.Response(200, json={
                "content": base64.b64encode(SOURCE.encode()).decode(), "sha": "filesha"})
        if "/contents/" in path and method == "PUT":
            return httpx.Response(201, json={})
        return httpx.Response(404, json={"message": f"unhandled {method} {path}"})

    def paths(self, method: str) -> List[str]:
        return [r.url.path for r in self.requests if r.method == method]

    def json_for(self, method: str, suffix: str) -> dict:
        for r in self.requests:
            if r.method == method and r.url.path.endswith(suffix):
                return json.loads(r.content.decode())
        raise AssertionError(f"no {method} to ...{suffix}")


def _bot(recorder: _Recorder) -> GitHubPRBot:
    client = httpx.AsyncClient(transport=httpx.MockTransport(recorder),
                               base_url="https://api.github.com")
    return GitHubPRBot(repo="o/r", token="t", client=client)


# --------------------------------------------------------------------------- #
# Pure helpers                                                                #
# --------------------------------------------------------------------------- #
def test_branch_name_and_title():
    f = _finding()
    assert branch_name(f).startswith("shipcheck/fix-sqli-app-")
    assert "sqli" in pr_title(f) and "app.py" in pr_title(f)


def test_body_has_evidence_and_never_merge_note():
    body = render_pr_body(_finding(), repo="o/r")
    assert "' OR 1=1--" in body            # payload
    assert "never auto-merges" in body     # the human-gate note
    assert "```diff" in body               # fix diff
    assert "Reviewer checklist" in body
    assert "/100" in body                  # risk score


# --------------------------------------------------------------------------- #
# Bot behaviour                                                               #
# --------------------------------------------------------------------------- #
async def test_refuses_pr_for_unverified_fix():
    rec = _Recorder()
    pr = await _bot(rec).open_draft_pr(_finding(verified=False))
    assert pr is None
    assert rec.requests == []  # No PASS, No PR -- not a single API call


async def test_opens_draft_pr_and_never_merges():
    rec = _Recorder(existing_prs=[])
    pr = await _bot(rec).open_draft_pr(_finding(), base="main")

    assert pr["number"] == 7
    # A draft PR was created with the fix branch as head.
    created = rec.json_for("POST", "/pulls")
    assert created["draft"] is True
    assert created["head"].startswith("shipcheck/fix-sqli-")
    assert created["base"] == "main"
    # Branch created and file patched along the way.
    assert any(p.endswith("/git/refs") for p in rec.paths("POST"))
    assert any("/contents/app.py" in p for p in rec.paths("PUT"))
    # The merge endpoint is NEVER called.
    assert not any("/merge" in r.url.path for r in rec.requests)


async def test_dedupes_and_updates_existing_pr():
    rec = _Recorder(existing_prs=[{"number": 9, "html_url": "x", "draft": True}])
    pr = await _bot(rec).open_draft_pr(_finding())

    assert pr["number"] == 9
    # Updated the existing PR body; did not create a new PR or branch.
    assert any("/pulls/9" in p for p in rec.paths("PATCH"))
    assert not any(p.endswith("/pulls") for p in rec.paths("POST"))
    assert not any(p.endswith("/git/refs") for p in rec.paths("POST"))
