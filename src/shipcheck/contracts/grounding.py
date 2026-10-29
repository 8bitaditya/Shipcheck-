"""Advisory Grounding Contract for ShipCheck.

Per the PRD (FR-5 / G4): every confirmed finding cites Tavily-grounded
CVE/advisory IDs, affected versions and the canonical fix, in both the
verdict report and the PR body.

`provider` records where the grounding came from, so the report never passes
off the offline fallback as a live Tavily lookup:
    "tavily"  - live Tavily search results
    "static"  - built-in CWE/OWASP reference (no TAVILY_API_KEY, or Tavily failed)

JSON Shape:
    {
        "finding_id": "find-sqli-001",
        "provider": "tavily",
        "query": "CWE-89 SQL injection db.execute Python remediation advisory",
        "advisory_ids": ["CWE-89", "CVE-2024-12345"],
        "cwe_id": "CWE-89",
        "affected_versions": [],
        "canonical_fix": "Use parameterized queries ...",
        "sources": [{"title": "SQL Injection Prevention Cheat Sheet", "url": "https://..."}],
        "note": null
    }
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class AdvisorySource(BaseModel):
    """A single cited advisory / reference page."""
    title: str = Field(..., description="Page or advisory title")
    url: str = Field(..., description="http(s) URL of the source")


class AdvisoryGrounding(BaseModel):
    """External advisory context attached to a confirmed finding."""
    finding_id: str = Field(..., description="Reference to the Finding ID")
    provider: str = Field(
        ...,
        description="'tavily' for a live Tavily lookup, 'static' for the offline CWE/OWASP fallback"
    )
    query: str = Field(default="", description="Search query sent to Tavily")
    advisory_ids: List[str] = Field(
        default_factory=list,
        description="CVE / GHSA / CWE identifiers cited by the sources"
    )
    cwe_id: Optional[str] = Field(default=None, description="Weakness class, e.g. CWE-89")
    affected_versions: List[str] = Field(
        default_factory=list,
        description="Affected version ranges (dependency findings only; empty for first-party code)"
    )
    canonical_fix: str = Field(default="", description="Canonical remediation guidance")
    sources: List[AdvisorySource] = Field(default_factory=list)
    note: Optional[str] = Field(
        default=None,
        description="Why the static fallback was used, if it was"
    )

    @property
    def is_live(self) -> bool:
        return self.provider == "tavily"
