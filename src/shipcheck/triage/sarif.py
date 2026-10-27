"""SARIF parser converting standard SARIF v2.1.0 into ShipCheck Finding objects."""

import hashlib
from typing import Any, Dict, List

from shipcheck.contracts.attack_plan import VulnClass
from shipcheck.contracts.finding import Finding, FindingTarget
from shipcheck.contracts.verdict import SeverityLevel


def _map_vuln_class(rule_id: str, message: str) -> VulnClass:
    """Classify a finding into one of the targeted classes or other."""
    text = f"{rule_id} {message}".lower()
    if any(k in text for k in ["sqli", "sql-injection", "sqlite", "raw-sql"]):
        return VulnClass.SQLI
    if any(k in text for k in ["command-injection", "shell-true", "subprocess", "exec", "system"]):
        return VulnClass.CMDI
    if any(k in text for k in ["path-traversal", "directory-traversal", "traversal", "send-file"]):
        return VulnClass.TRAVERSAL
    if any(k in text for k in ["xss", "cross-site", "unescaped", "reflected"]):
        return VulnClass.XSS
    if any(k in text for k in ["ssrf", "server-side-request"]):
        return VulnClass.SSRF
    if any(k in text for k in ["ssti", "template-injection"]):
        return VulnClass.SSTI
    if any(k in text for k in ["idor", "object-level-authorization", "bola"]):
        return VulnClass.IDOR
    if any(k in text for k in ["deserialization", "pickle", "unsafe-yaml"]):
        return VulnClass.DESERIALIZATION
    if any(k in text for k in ["secret", "token", "password", "key", "gitleaks"]):
        return VulnClass.SECRETS
    if any(k in text for k in ["cve-", "vulnerable-dependency", "audit"]):
        return VulnClass.DEPS
    return VulnClass.OTHER


def _map_severity(level: str) -> SeverityLevel:
    """Map SARIF level to SeverityLevel."""
    lvl = (level or "").lower()
    if lvl in ["error", "critical"]:
        return SeverityLevel.CRITICAL
    if lvl == "warning":
        return SeverityLevel.HIGH
    if lvl == "note":
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


def parse_sarif_to_findings(sarif_data: Dict[str, Any], tool_name: str) -> List[Finding]:
    """Extract standard Finding objects from SARIF JSON."""
    findings: List[Finding] = []
    runs = sarif_data.get("runs", [])

    for run in runs:
        results = run.get("results", [])
        for res in results:
            rule_id = res.get("ruleId", "unknown-rule")
            message = res.get("message", {}).get("text", "")
            level = res.get("level", "warning")

            locations = res.get("locations", [])
            file_path = "unknown"
            line_start = 1
            line_end = 1
            snippet = None

            if locations:
                phys = locations[0].get("physicalLocation", {})
                artifact_uri = phys.get("artifactLocation", {}).get("uri", "")
                if artifact_uri:
                    # Strip leading file:// or ./
                    file_path = artifact_uri.replace("file://", "").lstrip("./")

                region = phys.get("region", {})
                line_start = region.get("startLine", 1)
                line_end = region.get("endLine", line_start)
                snippet = region.get("snippet", {}).get("text", None)

            # Generate stable deterministic ID
            seed = f"{tool_name}:{rule_id}:{file_path}:{line_start}"
            finding_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]

            findings.append(
                Finding(
                    finding_id=finding_id,
                    tool=tool_name,
                    vuln_class=_map_vuln_class(rule_id, message),
                    rule_id=rule_id,
                    title=message or rule_id,
                    description=message,
                    target=FindingTarget(
                        file=file_path,
                        line=line_start,
                        end_line=line_end,
                        sink=snippet,
                        code_snippet=snippet,
                    ),
                    severity=_map_severity(level),
                )
            )

    return findings
