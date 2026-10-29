"""Triage scanners and SARIF normalisation, without running real scanners.

A fake sandbox returns canned scanner output in the run-and-cat report format,
so command shape, report parsing, classification, severity and merging are
tested offline.
"""

import json

from shipcheck.contracts.attack_plan import VulnClass
from shipcheck.contracts.finding import Finding, FindingTarget
from shipcheck.contracts.verdict import SeverityLevel
from shipcheck.sandbox.base import SandboxResult
from shipcheck.triage.deps import DependencyScanner
from shipcheck.triage.report import REPORT_MARKER, report_script
from shipcheck.triage.runner import merge_nearby
from shipcheck.triage.sarif import _map_vuln_class, parse_sarif_to_findings
from shipcheck.triage.semgrep import SemgrepScanner


def _sarif(results, rules):
    return {"runs": [{"tool": {"driver": {"rules": rules}}, "results": results}]}


def _result(rule, line, msg="m", uri="app.py"):
    return {"ruleId": rule, "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                "region": {"startLine": line, "snippet": {"text": "code"}}}}]}


class ReportSandbox:
    def __init__(self, report):
        self.report = report
        self.scripts = []

    async def run(self, command=None, *, shell=None, **kw):
        self.scripts.append(shell)
        body = json.dumps(self.report) if self.report is not None else ""
        return SandboxResult(exit_code=0, stdout=f"noise\n{REPORT_MARKER}\n{body}\n", stderr="")


def test_report_script_writes_to_tempfile_and_cats_it():
    script = report_script('tool --out "$OUT"')
    assert 'OUT="$(mktemp)"' in script and 'cat "$OUT"' in script
    assert "/tmp/semgrep.sarif" not in script


async def test_semgrep_parses_stdout_report_and_ships_traversal_rule():
    sarif = _sarif([_result("shipcheck.python.flask.path-traversal", 68,
                            "User input from a Flask request reaches a filesystem path (path traversal)")],
                   [{"id": "shipcheck.python.flask.path-traversal", "defaultConfiguration": {"level": "error"}}])
    sb = ReportSandbox(sarif)
    findings = await SemgrepScanner().scan(sb)
    assert "p/owasp-top-ten" in sb.scripts[0] and "shipcheck.python.flask.path-traversal" in sb.scripts[0]
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_class == VulnClass.TRAVERSAL  # not CMDI ("filesystem" contains "system")
    assert f.severity == SeverityLevel.CRITICAL  # from the rule's defaultConfiguration
    assert f.target.file == "app.py" and f.target.line == 68


async def test_no_report_means_no_findings():
    assert await SemgrepScanner().scan(ReportSandbox(None)) == []


async def test_pip_audit_targets_requirements_not_the_running_env():
    sb = ReportSandbox({"dependencies": [{"name": "flask", "version": "0.12",
                                          "vulns": [{"id": "CVE-2018-1000656", "description": "DoS"}]}]})
    findings = await DependencyScanner().scan(sb)
    assert "pip-audit -r requirements.txt" in sb.scripts[0]
    assert findings[0].cve_id == "CVE-2018-1000656" and findings[0].vuln_class == VulnClass.DEPS


def test_classification_keywords():
    assert _map_vuln_class("python.flask.security.injection.tainted-sql-string", "") == VulnClass.SQLI
    assert _map_vuln_class("python.lang.security.audit.subprocess-shell-true", "") == VulnClass.CMDI
    assert _map_vuln_class("x", "reaches a filesystem path") != VulnClass.CMDI


def test_sarif_paths_keep_leading_dots():
    f = parse_sarif_to_findings(_sarif([_result("r", 1, uri="./.github/app.py")], []), "semgrep")[0]
    assert f.target.file == ".github/app.py"


def _f(vuln, line, rule, sev=SeverityLevel.HIGH, file="app.py"):
    return Finding(vuln_class=vuln, title=rule, rule_id=rule, severity=sev, description="d",
                   target=FindingTarget(file=file, line=line))


def test_merge_nearby_collapses_overlapping_rules():
    merged = merge_nearby([
        _f(VulnClass.SQLI, 39, "a"), _f(VulnClass.SQLI, 43, "b", SeverityLevel.CRITICAL),
        _f(VulnClass.SQLI, 47, "c"),
        _f(VulnClass.XSS, 60, "x"), _f(VulnClass.XSS, 76, "y"),        # far apart: separate
        _f(VulnClass.SQLI, 40, "d", file="other.py"),                 # other file: separate
    ])
    sqli = [m for m in merged if m.vuln_class == VulnClass.SQLI and m.target.file == "app.py"]
    assert len(sqli) == 1
    assert sqli[0].severity == SeverityLevel.CRITICAL
    assert "Also flagged by: b, c" in sqli[0].description
    assert len([m for m in merged if m.vuln_class == VulnClass.XSS]) == 2
    assert len(merged) == 4
