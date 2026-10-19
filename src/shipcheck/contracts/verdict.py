"""Contract: Verdict Report and Scoring. Frozen for Week 1."""

from typing import List, Optional
from pydantic import BaseModel, Field
from shipcheck.contracts.finding import Finding
from shipcheck.contracts.evidence import EvidenceBlob
from shipcheck.contracts.fix import PatchResult


class FindingVerdict(BaseModel):
    """Complete dossier for an individual finding."""

    finding: Finding
    evidence: Optional[EvidenceBlob] = None
    fix_result: Optional[PatchResult] = None
    exploitability_multiplier: float = Field(
        default=0.0,
        description="1.5-2.0x for sandbox-confirmed PoC; ~0.0 for unconfirmed/false positive",
    )
    reachability: float = Field(
        default=1.0,
        description="Factor (0.0 to 1.0) whether sink is reachable from external entrypoint",
    )
    exposure: float = Field(
        default=1.0,
        description="Factor (0.5 to 1.0) reflecting network service vs internal library",
    )
    risk_score: float = Field(
        default=0.0,
        description="Calculated risk score component (0 to 100 capped)",
    )
    one_sentence_reason: str = Field(
        default="",
        description="One sentence explaining 'why is this #1' or risk rationale",
    )
    tavily_grounding: Optional[str] = Field(
        default=None,
        description="Tavily-retrieved CVE/advisory citations and canonical patch references",
    )


class Verdict(BaseModel):
    """Aggregate verdict report for the entire pull request or repository scan."""

    scan_id: str = Field(..., description="Unique scan run ID")
    repo_url_or_path: str = Field(..., description="Target repository or PR reference")
    overall_risk_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Aggregate 0-100 risk score (capped points model)",
    )
    findings_count: int = 0
    confirmed_count: int = 0
    cards: List[FindingVerdict] = Field(default_factory=list)
    draft_pr_url: Optional[str] = Field(
        default=None,
        description="URL to the generated draft GitHub PR",
    )
    summary_markdown: str = Field(default="", description="Rendered markdown summary")
