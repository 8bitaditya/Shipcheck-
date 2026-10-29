"""Dependency vulnerability scanners: pip-audit, npm audit, and osv-scanner."""

from typing import List
from shipcheck.contracts.attack_plan import VulnClass
from shipcheck.contracts.finding import Finding, FindingTarget
from shipcheck.contracts.verdict import SeverityLevel
from shipcheck.sandbox.base import SandboxBase
from shipcheck.triage.report import run_json_report
from shipcheck.triage.sarif import parse_sarif_to_findings


class DependencyScanner:
    """Scans requirements.txt and package.json for known vulnerabilities."""

    async def scan(self, sandbox: SandboxBase) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Python dependency check via pip-audit. Audit the target's
        #    requirements.txt -- without -r, pip-audit audits whatever Python
        #    environment it runs in (ShipCheck's own, on the local backend).
        cmd_pip = (
            "[ -f requirements.txt ] && pip-audit -r requirements.txt "
            '--progress-spinner off --format json -o "$OUT"'
        )
        data = await run_json_report(sandbox, cmd_pip)
        deps = data.get("dependencies", []) if isinstance(data, dict) else []
        for vuln in deps:
            for v in vuln.get("vulns", []):
                cve_id = v.get("id", "CVE-UNKNOWN")
                desc = v.get("description", "Vulnerable package")
                findings.append(
                    Finding(
                        finding_id=f"pip-audit:{cve_id}",
                        tool="pip-audit",
                        rule_id=cve_id,
                        vuln_class=VulnClass.DEPS,
                        title=f"{vuln.get('name')} {vuln.get('version')}: {desc}",
                        description=desc,
                        target=FindingTarget(file="requirements.txt", line=1),
                        severity=SeverityLevel.HIGH,
                        cve_id=cve_id,
                    )
                )

        # 2. OSV-Scanner for transitive CVEs
        cmd_osv = 'osv-scanner scan source -r --format sarif --output "$OUT" .'
        data_osv = await run_json_report(sandbox, cmd_osv)
        if isinstance(data_osv, dict):
            findings.extend(parse_sarif_to_findings(data_osv, "osv-scanner"))

        return findings
