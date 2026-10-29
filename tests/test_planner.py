"""Tests for AttackPlanner output parsing.

Ultra is replaced by a fake that returns fixed JSON, so the canonical schema,
the legacy `steps` schema (which the old prompt asked for), per-plan validation
and the template gap-filling are all tested offline.
"""

from shipcheck.contracts.attack_plan import CANONICAL_ATTACK_TEMPLATES, VulnClass
from shipcheck.contracts.finding import Finding, FindingTarget
from shipcheck.planning.planner import AttackPlanner


class FakeLLM:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    async def complete_json(self, prompt, system_prompt=None, tier="super", max_tokens=4096):
        self.calls.append((tier, system_prompt))
        return self.payload


class FakeTavily:
    async def search_exploit_context(self, query):
        return {"answer": "a", "sources": "s"}


def _finding(vuln, endpoint, sink):
    return Finding(vuln_class=vuln, title=f"{vuln.value}", tool="semgrep", rule_id="r",
                   target=FindingTarget(file="app.py", sink=sink, endpoint=endpoint))


SQLI = _finding(VulnClass.SQLI, "/login", "conn.execute(query)")
XSS = _finding(VulnClass.XSS, "/search", "return html")


def _planner(payload):
    p = AttackPlanner(llm_client=None, tavily_client=FakeTavily())
    p.llm = FakeLLM(payload)
    return p


async def test_canonical_batch_is_used_as_is():
    plan = {"vuln_class": "sqli", "target_file": "app.py", "sink": "conn.execute(query)",
            "payload_strategy": "tautology", "expected_marker": "admin@vulnshop.local",
            "route": "/login", "http_method": "post", "parameter_name": "username",
            "suggested_payload": "admin'--"}
    p = _planner({"plans": [plan]})
    batch = await p.plan_attacks("diff", [SQLI], "sha")

    assert p.llm.calls[0][0] == "ultra"
    assert '"plans"' in p.llm.calls[0][1]  # prompt documents the canonical schema
    assert len(batch.plans) == 1
    got = batch.plans[0]
    assert got.suggested_payload == "admin'--"
    assert got.expected_marker == "admin@vulnshop.local"
    assert got.http_method == "POST"


async def test_legacy_steps_shape_is_normalized():
    """The exact shape Ultra returned in the first real run."""
    legacy = {"plan_id": "p", "commit_sha": "sha", "summary": "s", "steps": [
        {"step_id": "1", "finding_id": SQLI.finding_id, "vuln_class": "SQLi",
         "target_file": "app.py", "target_endpoint": "/login", "http_method": "POST",
         "payload_strategy": "bypass", "expected_marker": "admin",
         "suggested_payloads": ["' OR '1'='1' --", "x"]},
        {"step_id": "2", "vuln_class": "Reflected XSS", "target_endpoint": "/search",
         "http_method": "GET", "suggested_payloads": ["<img src=x onerror=alert(1)>"]},
    ]}
    batch = await _planner(legacy).plan_attacks("diff", [SQLI, XSS], "sha")

    by_class = {p.vuln_class: p for p in batch.plans}
    assert set(by_class) == {VulnClass.SQLI, VulnClass.XSS}
    sqli = by_class[VulnClass.SQLI]
    assert sqli.route == "/login" and sqli.suggested_payload == "' OR '1'='1' --"
    assert sqli.sink == "conn.execute(query)"  # filled from the matching finding
    xss = by_class[VulnClass.XSS]
    assert xss.target_file == "app.py"
    assert xss.expected_marker == CANONICAL_ATTACK_TEMPLATES[VulnClass.XSS]["expected_marker"]
    assert xss.suggested_payload == "<img src=x onerror=alert(1)>"


async def test_missing_findings_get_template_plans():
    plan = {"vuln_class": "sqli", "target_file": "app.py", "sink": "s",
            "payload_strategy": "p", "expected_marker": "admin", "route": "/login"}
    batch = await _planner({"plans": [plan]}).plan_attacks("diff", [SQLI, XSS], "sha")
    assert {p.vuln_class for p in batch.plans} == {VulnClass.SQLI, VulnClass.XSS}
    xss = next(p for p in batch.plans if p.vuln_class == VulnClass.XSS)
    assert "Heuristic plan" in (xss.rationale or "")


async def test_garbage_falls_back_to_templates():
    batch = await _planner({"nonsense": True}).plan_attacks("diff", [SQLI], "sha")
    assert len(batch.plans) == 1
    assert batch.plans[0].suggested_payload == CANONICAL_ATTACK_TEMPLATES[VulnClass.SQLI]["default_payload"]


async def test_non_actionable_plans_are_dropped():
    plan = {"vuln_class": "ssrf", "target_file": "app.py", "sink": "s",
            "payload_strategy": "p", "expected_marker": "ami-id"}
    batch = await _planner({"plans": [plan]}).plan_attacks("diff", [SQLI], "sha")
    assert [p.vuln_class for p in batch.plans] == [VulnClass.SQLI]


XSS_EXPORT = Finding(vuln_class=VulnClass.XSS, title="xss export", tool="semgrep", rule_id="r",
                     target=FindingTarget(file="app.py", line=60,
                                          sink='return "<pre>" + result.stdout + result.stderr'))
XSS_SEARCH = Finding(vuln_class=VulnClass.XSS, title="xss search", tool="semgrep", rule_id="r",
                     target=FindingTarget(file="app.py", line=76,
                                          sink='return "<h1>Results for " + query + "</h1>"'))


def _xss_plan(**kw):
    base = {"vuln_class": "xss", "target_file": "app.py", "payload_strategy": "p",
            "expected_marker": "<script>alert(1)</script>", "http_method": "GET"}
    return {**base, **kw}


async def test_same_class_findings_are_matched_by_id():
    payload = {"plans": [_xss_plan(finding_id=XSS_SEARCH.finding_id, sink="x", route="/search"),
                         _xss_plan(finding_id=XSS_EXPORT.finding_id, sink="y", route="/export")]}
    batch = await _planner(payload).plan_attacks("diff", [XSS_EXPORT, XSS_SEARCH], "sha")
    by_route = {p.route: p.finding_id for p in batch.plans}
    assert by_route == {"/search": XSS_SEARCH.finding_id, "/export": XSS_EXPORT.finding_id}


async def test_without_ids_the_closest_sink_wins():
    """Regression: the /search plan used to be credited to the /export finding."""
    payload = {"plans": [_xss_plan(sink='return "<h1>Results for " + query', route="/search")]}
    batch = await _planner(payload).plan_attacks("diff", [XSS_EXPORT, XSS_SEARCH], "sha")
    assert len(batch.plans) == 1  # no template guess for the other same-class finding
    assert batch.plans[0].finding_id == XSS_SEARCH.finding_id
