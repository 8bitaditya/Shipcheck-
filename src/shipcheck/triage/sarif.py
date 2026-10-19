"""SARIF parser converting standard SARIF v2.1.0 into ShipCheck Finding objects."""

import hashlib
import json
from typing import Any, Dict, List
from shipcheck.contracts.finding import Finding, FindingSeverity, VulnClass


def _map_vuln_class(rule_id: str, message: str) -> VulnClass:
    """Classify a finding into one of the 4 targeted classes or other."""
    text = f"{rule_id} {message}".lower()
    if any(k in text for k in ["sqli", "sql-injection", "sqlite", "raw-sql"]):
        return VulnClass.SQLI
    if any(k in text for k in ["command-injection", "shell-true", "subprocess", "exec", "system"]):
        return VulnClass.COMMAND_INJECTION
    if any(k in text for k in ["path-traversal", "directory-traversal", "traversal", "send-file"]):
        return VulnClass.PATH_TRAVERSAL
    if any(k in text for k in ["xss", "cross-site", "unescaped", "reflected"]):
        return VulnClass.REFLECTED_XSS
    if any(k in text for k in ["secret", "token", "password", "key", "gitleaks"]):
        return VulnClass.SECRET_LEAK
    if any(k in text for k in ["cve-", "vulnerable-dependency", "audit"]):
        return VulnClass.INSECURE_DEPENDENCY
    return VulnClass.OTHER


def _map_severity(level: str) -> FindingSeverity:
    """Map SARIF level to FindingSeverity."""
    lvl = (level or "").lower()
    if lvl in ["error", "critical"]:
        return FindingSeverity.CRITICAL
    if lvl == "warning":
        return FindingSeverity.HIGH
    if lvl == "note":
        return FindingSeverity.MEDIUM
    return FindingSeverity.LOW


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
                    id=finding_id,
                    tool=tool_name,
                    vuln_class=_map_vuln_class(rule_id, message),
                    rule_id=rule_id,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    severity_hint=_map_severity(level),
                    message=message,
                    sink_snippet=snippet,
                    raw_sarif=res,
                )
            )

    return findings
