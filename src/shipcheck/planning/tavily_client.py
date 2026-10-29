"""Tavily search client for CVE grounding, exploit writeups, and canonical fix advisories."""

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from shipcheck import config
from shipcheck.contracts.attack_plan import VulnClass
from shipcheck.contracts.finding import Finding
from shipcheck.contracts.grounding import AdvisoryGrounding, AdvisorySource

logger = logging.getLogger(__name__)

TAVILY_SEARCH_URL = "https://api.tavily.com/search"
TAVILY_MAX_QUERY_CHARS = 400

# Offline fallback per class: (CWE, human label, canonical fix, reference title, reference URL).
# Used when TAVILY_API_KEY is unset or Tavily errors; always reported as provider="static".
STATIC_ADVISORIES: Dict[VulnClass, tuple] = {
    VulnClass.SQLI: (
        "CWE-89", "SQL injection",
        "Use parameterized queries / prepared statements; never build SQL with string formatting or concatenation.",
        "OWASP SQL Injection Prevention Cheat Sheet",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ),
    VulnClass.CMDI: (
        "CWE-78", "OS command injection",
        "Do not pass user input to a shell: call subprocess with an argument list (shell=False) and validate input against an allowlist.",
        "OWASP OS Command Injection Defense Cheat Sheet",
        "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
    ),
    VulnClass.TRAVERSAL: (
        "CWE-22", "path traversal",
        "Resolve the requested path and reject it unless it stays inside the allowed base directory (e.g. werkzeug.utils.safe_join).",
        "OWASP Path Traversal",
        "https://owasp.org/www-community/attacks/Path_Traversal",
    ),
    VulnClass.XSS: (
        "CWE-79", "cross-site scripting",
        "HTML-escape untrusted data on output (template autoescaping or markupsafe.escape) and set a Content-Security-Policy.",
        "OWASP Cross Site Scripting Prevention Cheat Sheet",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ),
    VulnClass.SSRF: (
        "CWE-918", "server-side request forgery",
        "Allowlist outbound destinations and block internal/metadata address ranges after DNS resolution.",
        "OWASP SSRF Prevention Cheat Sheet",
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ),
    VulnClass.SSTI: (
        "CWE-1336", "server-side template injection",
        "Never render user input as a template; pass it only as template context with a sandboxed environment.",
        "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
        "https://cwe.mitre.org/data/definitions/1336.html",
    ),
    VulnClass.IDOR: (
        "CWE-639", "insecure direct object reference",
        "Enforce an authorization check that the current user owns the requested object on every access.",
        "OWASP Authorization Cheat Sheet",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
    ),
    VulnClass.DESERIALIZATION: (
        "CWE-502", "insecure deserialization",
        "Never deserialize untrusted data with pickle/yaml.load; use a data-only format such as JSON with schema validation.",
        "OWASP Deserialization Cheat Sheet",
        "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
    ),
    VulnClass.SECRETS: (
        "CWE-798", "hard-coded credentials",
        "Remove the secret from source, rotate it, and load it from the environment or a secrets manager.",
        "OWASP Secrets Management Cheat Sheet",
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    ),
    VulnClass.DEPS: (
        "CWE-1395", "vulnerable dependency",
        "Upgrade the dependency to a patched release listed in the advisory.",
        "OSV.dev vulnerability database",
        "https://osv.dev/",
    ),
}

_ID_PATTERNS = [
    re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.IGNORECASE),
    re.compile(r"\bCWE-\d{1,4}\b", re.IGNORECASE),
]
_VERSION_PATTERN = re.compile(
    r"\b(?:before|prior to|through|up to|<=?|>=?)\s*v?\d+(?:\.\d+){1,3}[a-z0-9]*",
    re.IGNORECASE,
)


def _clean_text(text: Any, limit: int) -> str:
    """Collapse whitespace/control chars and cap length (sources are untrusted web content)."""
    s = re.sub(r"[\x00-\x1f\x7f\s]+", " ", str(text or "")).strip()
    return s[:limit]


def _safe_url(url: Any) -> Optional[str]:
    """Accept only plain http(s) URLs."""
    s = str(url or "").strip()
    if not s or len(s) > 500 or re.search(r"[\s<>\"'`]", s):
        return None
    parsed = urlparse(s)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return s


def _extract_ids(texts: List[str], limit: int = 8) -> List[str]:
    seen: List[str] = []
    for text in texts:
        for pat in _ID_PATTERNS:
            for m in pat.findall(text or ""):
                ident = m.upper()
                if ident not in seen:
                    seen.append(ident)
    return seen[:limit]


def _extract_versions(texts: List[str], limit: int = 5) -> List[str]:
    seen: List[str] = []
    for text in texts:
        for m in _VERSION_PATTERN.findall(text or ""):
            v = _clean_text(m, 40)
            if v not in seen:
                seen.append(v)
    return seen[:limit]


class TavilyGroundingClient:
    """Grounds vulnerability findings with live CVE advisories and exploit techniques."""

    def __init__(self, api_key: Optional[str] = None, *, client: Optional[httpx.AsyncClient] = None):
        self.api_key = api_key if api_key is not None else config.TAVILY_API_KEY
        self._client = client

    async def _search(self, query: str, *, max_results: int = 3) -> Dict[str, Any]:
        """POST a Tavily search and return the raw JSON response."""
        payload = {
            "query": query[:TAVILY_MAX_QUERY_CHARS],
            "search_depth": "advanced",
            "include_answer": True,
            "max_results": max_results,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        if self._client is not None:
            res = await self._client.post(TAVILY_SEARCH_URL, json=payload, headers=headers, timeout=15.0)
        else:
            async with httpx.AsyncClient() as client:
                res = await client.post(TAVILY_SEARCH_URL, json=payload, headers=headers, timeout=15.0)
        res.raise_for_status()
        return res.json()

    async def search_exploit_context(self, query: str) -> Dict[str, str]:
        """Search Tavily for exploit techniques and canonical fixes for a vulnerability."""
        if not self.api_key:
            logger.info("TAVILY_API_KEY not set. Returning offline fallback grounding.")
            return {
                "answer": f"Standard vulnerability pattern for {query}. Recommended mitigation: input sanitization and parameterized bindings.",
                "sources": "https://cve.mitre.org",
            }

        try:
            data = await self._search(f"{query} exploit proof of concept remediation")
            answer = data.get("answer", "")
            sources = ", ".join(
                [r.get("url", "") for r in data.get("results", [])]
            )
            return {"answer": answer, "sources": sources}
        except Exception as err:
            logger.warning("Tavily search error: %s. Using default grounding.", err)
            return {
                "answer": f"Security guidance for {query}.",
                "sources": "https://nvd.nist.gov",
            }

    # ------------------------------------------------------------------ #
    # Per-finding grounding for the verdict report and PR body (FR-5 / G4)
    # ------------------------------------------------------------------ #
    @staticmethod
    def build_query(finding: Finding) -> str:
        """Deterministic search query for one finding."""
        cwe, label = STATIC_ADVISORIES.get(finding.vuln_class, (None, finding.vuln_class.value))[:2]
        if finding.vuln_class == VulnClass.DEPS:
            ident = finding.cve_id or finding.rule_id or ""
            return _clean_text(
                f"{ident} {finding.title} affected versions patched version advisory", TAVILY_MAX_QUERY_CHARS
            )
        sink = finding.target.sink or ""
        cwe_part = finding.cwe_id or cwe or ""
        return _clean_text(
            f"{cwe_part} {label} {sink} Python remediation canonical fix CVE advisory",
            TAVILY_MAX_QUERY_CHARS,
        )

    @staticmethod
    def static_grounding(finding: Finding, note: Optional[str] = None) -> AdvisoryGrounding:
        """Offline CWE/OWASP grounding. Never claims to be a Tavily result."""
        entry = STATIC_ADVISORIES.get(finding.vuln_class)
        ids: List[str] = [finding.cve_id] if finding.cve_id else []
        if entry is None:
            return AdvisoryGrounding(
                finding_id=finding.finding_id, provider="static",
                query=TavilyGroundingClient.build_query(finding),
                advisory_ids=ids, cwe_id=finding.cwe_id, note=note,
            )
        cwe, _label, fix, ref_title, ref_url = entry
        cwe_id = finding.cwe_id or cwe
        if cwe_id not in ids:
            ids.append(cwe_id)
        return AdvisoryGrounding(
            finding_id=finding.finding_id,
            provider="static",
            query=TavilyGroundingClient.build_query(finding),
            advisory_ids=ids,
            cwe_id=cwe_id,
            canonical_fix=fix,
            sources=[AdvisorySource(title=ref_title, url=ref_url)],
            note=note,
        )

    async def ground_finding(self, finding: Finding) -> AdvisoryGrounding:
        """Ground one finding with Tavily, falling back to the static reference."""
        if not self.api_key:
            return self.static_grounding(finding, note="TAVILY_API_KEY not set; offline CWE/OWASP reference used")

        query = self.build_query(finding)
        try:
            data = await self._search(query, max_results=5)
        except Exception as err:
            logger.warning("Tavily grounding failed for %s: %s", finding.finding_id, err)
            return self.static_grounding(finding, note=f"Tavily lookup failed ({type(err).__name__}); offline reference used")

        results = [r for r in (data.get("results") or []) if isinstance(r, dict)]
        answer = _clean_text(data.get("answer"), 800)
        texts = [answer] + [f"{r.get('title', '')} {r.get('content', '')}" for r in results]

        sources: List[AdvisorySource] = []
        for r in results:
            url = _safe_url(r.get("url"))
            if url:
                sources.append(AdvisorySource(title=_clean_text(r.get("title") or url, 120), url=url))

        fallback = self.static_grounding(finding)
        ids = _extract_ids(([finding.cve_id] if finding.cve_id else []) + texts)
        if fallback.cwe_id and fallback.cwe_id not in ids:
            ids.append(fallback.cwe_id)
        # Version ranges only mean something for a third-party package; for
        # first-party code the CVEs Tavily returns are related, not this bug.
        versions = _extract_versions(texts) if finding.vuln_class == VulnClass.DEPS else []

        return AdvisoryGrounding(
            finding_id=finding.finding_id,
            provider="tavily",
            query=query,
            advisory_ids=ids,
            cwe_id=fallback.cwe_id,
            affected_versions=versions,
            canonical_fix=answer or fallback.canonical_fix,
            sources=sources or fallback.sources,
        )
