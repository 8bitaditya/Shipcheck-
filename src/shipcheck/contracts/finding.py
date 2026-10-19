"""Contract: Static Triage Findings. Frozen for Week 1."""

from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnClass(str, Enum):
    SQLI = "SQLi"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    REFLECTED_XSS = "Reflected XSS"
    SECRET_LEAK = "Secret Leak"
    INSECURE_DEPENDENCY = "Insecure Dependency"
    OTHER = "Other"


class Finding(BaseModel):
    """Normalized finding produced by static triage tools (Semgrep, Gitleaks, osv-scanner, pip-audit)."""

    id: str = Field(..., description="Unique deterministic identifier (hash of tool+rule+file+line)")
    tool: str = Field(..., description="Scanner name: semgrep, gitleaks, pip-audit, osv-scanner")
    vuln_class: VulnClass = Field(default=VulnClass.OTHER, description="Normalized vulnerability class")
    rule_id: str = Field(..., description="Original scanner rule ID")
    file_path: str = Field(..., description="Relative file path in repository")
    line_start: int = Field(default=1, description="Start line number")
    line_end: int = Field(default=1, description="End line number")
    severity_hint: FindingSeverity = Field(default=FindingSeverity.MEDIUM, description="Initial triage severity")
    message: str = Field(default="", description="Descriptive triage message")
    sink_snippet: Optional[str] = Field(default=None, description="Suspect code snippet at target sink")
    raw_sarif: Optional[Dict[str, Any]] = Field(default=None, description="Original raw SARIF block if available")

    def fingerprint(self) -> str:
        """Deterministic fingerprint for deduplication."""
        return f"{self.tool}:{self.rule_id}:{self.file_path}:{self.line_start}"
