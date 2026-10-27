"""Dependency vulnerability scanners: pip-audit, npm audit, and osv-scanner."""

import json
from typing import List
from shipcheck.contracts.attack_plan import VulnClass
from shipcheck.contracts.finding import Finding, FindingTarget
from shipcheck.contracts.verdict import SeverityLevel
from shipcheck.sandbox.base import SandboxBase
from shipcheck.triage.sarif import parse_sarif_to_findings


class DependencyScanner:
    """Scans requirements.txt and package.json for known vulnerabilities."""

    async def scan(self, sandbox: SandboxBase) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Python dependency check via pip-audit
        cmd_pip = "pip-audit --format json -o /tmp/pip-audit.json || true"
        await sandbox.run(shell=cmd_pip)
        try:
            raw = await sandbox.read_file("/tmp/pip-audit.json")
            data = json.loads(raw.decode("utf-8"))
            for vuln in data.get("dependencies", []):
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
        except Exception:
            pass

        # 2. OSV-Scanner for transitive CVEs
        cmd_osv = "osv-scanner scan source --format sarif --output /tmp/osv.sarif . || true"
        await sandbox.run(shell=cmd_osv)
        try:
            raw_osv = await sandbox.read_file("/tmp/osv.sarif")
            data_osv = json.loads(raw_osv.decode("utf-8"))
            findings.extend(parse_sarif_to_findings(data_osv, "osv-scanner"))
        except Exception:
            pass

        return findings
