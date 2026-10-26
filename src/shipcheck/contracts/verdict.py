"""Verdict Contract for ShipCheck.

Defines the per-finding risk card and objective 0-100 risk score combining:
    severity x confirmed x reachability x exposure

Per ShipCheck specification:
    "Verdict: a risk-ranked report with evidence and a 0-100 score.
     Unconfirmed findings score near 0."
    "No LLM decides this. LLMs hallucinate; a string match doesn't.
     Combine severity, confirmed exploit, reachability, and exposure into 0-100
     with a sentence explaining each factor."

JSON Shape:
    {
        "finding_id": "find-sqli-001",
        "status": "CONFIRMED",
        "score": 85.0,
        "score_breakdown": {
            "severity": "CRITICAL",
            "severity_base_score": 100.0,
            "confirmed_factor": 1.0,
            "reachability": "DIRECT",
            "reachability_factor": 1.0,
            "exposure": "PUBLIC",
            "exposure_factor": 1.0,
            "final_score": 100.0,
            "explanation": "Critical severity (100) confirmed by live sandbox exploit (x1.0) with direct reachability (x1.0) on a public endpoint (x1.0)."
        },
        "summary": "Confirmed SQL Injection in login() on /login route leaking administrative session.",
        "marker_verified": true
    }
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator


class VerdictStatus(str, Enum):
    """Status of the finding verification."""
    CONFIRMED = "CONFIRMED"           # Sandbox probe observed expected marker
    UNCONFIRMED = "UNCONFIRMED"       # Scanner suspect, but exploit failed / marker not found
    FALSE_POSITIVE = "FALSE_POSITIVE" # Determined non-exploitable / safe
    ERROR = "ERROR"                   # Execution crashed / inconclusive


class GateVerdict(str, Enum):
    """Strict binary gate: PASS means safe/fixed, NO_PASS means active vulnerability."""
    PASS_ = "PASS"        # Trailing underscore avoids Python keyword collision
    NO_PASS = "NO_PASS"


class SeverityLevel(str, Enum):
    """Vulnerability severity tier."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ReachabilityLevel(str, Enum):
    """Code reachability from external input."""
    DIRECT = "DIRECT"                 # Direct flow from HTTP/public input to sink
    CONDITIONAL = "CONDITIONAL"       # Reachable only under specific branches/admin auth
    UNKNOWN = "UNKNOWN"               # Not evaluated (default safe assumption)
    UNREACHABLE = "UNREACHABLE"       # Dead code or blocked by framework middleware


class ExposureLevel(str, Enum):
    """Network exposure context of the component."""
    PUBLIC = "PUBLIC"                 # Public internet facing endpoint
    AUTHENTICATED = "AUTHENTICATED"   # Requires authenticated session
    INTERNAL = "INTERNAL"             # Internal microservice or intranet only
    LOCAL = "LOCAL"                   # CLI / local developer environment only


SEVERITY_WEIGHTS: Dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 100.0,
    SeverityLevel.HIGH: 80.0,
    SeverityLevel.MEDIUM: 50.0,
    SeverityLevel.LOW: 20.0,
    SeverityLevel.INFO: 5.0,
}

REACHABILITY_WEIGHTS: Dict[ReachabilityLevel, float] = {
    ReachabilityLevel.DIRECT: 1.0,
    ReachabilityLevel.CONDITIONAL: 0.7,
    ReachabilityLevel.UNKNOWN: 0.5,
    ReachabilityLevel.UNREACHABLE: 0.05,
}

EXPOSURE_WEIGHTS: Dict[ExposureLevel, float] = {
    ExposureLevel.PUBLIC: 1.0,
    ExposureLevel.AUTHENTICATED: 0.75,
    ExposureLevel.INTERNAL: 0.5,
    ExposureLevel.LOCAL: 0.25,
}


class RiskScoreBreakdown(BaseModel):
    """Detailed mathematical breakdown of the 0-100 risk score."""
    severity: SeverityLevel
    severity_base_score: float = Field(ge=0.0, le=100.0)
    confirmed_factor: float = Field(
        ge=0.0,
        le=1.0,
        description="1.0 if exploit was confirmed in sandbox; 0.05 if unconfirmed (unconfirmed score near 0)"
    )
    reachability: ReachabilityLevel
    reachability_factor: float = Field(ge=0.0, le=1.0)
    exposure: ExposureLevel
    exposure_factor: float = Field(ge=0.0, le=1.0)
    final_score: float = Field(ge=0.0, le=100.0)
    explanation: str = Field(description="Sentence explaining each factor in plain terms")


def compute_risk_score(
    severity: SeverityLevel,
    is_confirmed: bool,
    reachability: ReachabilityLevel = ReachabilityLevel.DIRECT,
    exposure: ExposureLevel = ExposureLevel.PUBLIC,
) -> RiskScoreBreakdown:
    """Calculates the 0-100 risk score via deterministic formula:
    
        final_score = severity_base * confirmed_factor * reachability_factor * exposure_factor
        
    Key design constraint from PRoject.txt:
        'Unconfirmed findings score near 0.'
        Therefore:
        - Confirmed exploit factor = 1.0
        - Unconfirmed exploit factor = 0.05 (e.g. Critical 100 becomes 5.0 or less)
    """
    base_score = SEVERITY_WEIGHTS.get(severity, 50.0)
    confirmed_factor = 1.0 if is_confirmed else 0.05
    reachability_factor = REACHABILITY_WEIGHTS.get(reachability, 0.5)
    exposure_factor = EXPOSURE_WEIGHTS.get(exposure, 1.0)

    raw_score = base_score * confirmed_factor * reachability_factor * exposure_factor
    final_score = round(max(0.0, min(100.0, raw_score)), 1)

    # Generate explanatory sentence
    conf_str = "confirmed by live sandbox exploit (1.0x)" if is_confirmed else "UNCONFIRMED by exploit probe (0.05x dampener)"
    reach_str = f"{reachability.value.lower()} reachability ({reachability_factor}x)"
    exp_str = f"{exposure.value.lower()} exposure ({exposure_factor}x)"
    
    explanation = (
        f"{severity.value} base score ({base_score:.0f}) modulated by: "
        f"{conf_str}, {reach_str}, and {exp_str} -> Final Score: {final_score:.1f}/100."
    )

    return RiskScoreBreakdown(
        severity=severity,
        severity_base_score=base_score,
        confirmed_factor=confirmed_factor,
        reachability=reachability,
        reachability_factor=reachability_factor,
        exposure=exposure,
        exposure_factor=exposure_factor,
        final_score=final_score,
        explanation=explanation,
    )


class VerdictCard(BaseModel):
    """The per-finding verdict card summarizing risk, proof, and gating status."""
    verdict_id: str = Field(
        default_factory=lambda: f"v-{uuid.uuid4().hex[:12]}"
    )
    finding_id: str = Field(
        ...,
        description="Reference to the Finding ID"
    )
    status: VerdictStatus = Field(
        ...,
        description="CONFIRMED if marker verified, else UNCONFIRMED/FALSE_POSITIVE"
    )
    score: float = Field(
        ge=0.0,
        le=100.0,
        description="Calculated risk score from 0 to 100"
    )
    score_breakdown: RiskScoreBreakdown = Field(
        ...,
        description="Component-by-component mathematical audit trail"
    )
    summary: str = Field(
        ...,
        description="1-2 sentence human-readable card summary for dashboard and PR"
    )
    marker_verified: bool = Field(
        ...,
        description="Deterministic boolean check from sandbox probe output"
    )
    expected_marker: Optional[str] = Field(
        default=None,
        description="Expected marker string"
    )
    observed_marker: Optional[str] = Field(
        default=None,
        description="Actual observed marker substring if confirmed"
    )
    gate_verdict: GateVerdict = Field(
        default=GateVerdict.NO_PASS,
        description="Gating recommendation: PASS (safe/fixed) or NO_PASS (confirmed active vulnerability)"
    )

    @classmethod
    def from_probe(
        cls,
        finding_id: str,
        severity: SeverityLevel,
        marker_verified: bool,
        expected_marker: str,
        observed_marker: Optional[str] = None,
        reachability: ReachabilityLevel = ReachabilityLevel.DIRECT,
        exposure: ExposureLevel = ExposureLevel.PUBLIC,
        vuln_title: Optional[str] = None,
    ) -> VerdictCard:
        """Constructs a complete VerdictCard directly from probe harness output."""
        status = VerdictStatus.CONFIRMED if marker_verified else VerdictStatus.UNCONFIRMED
        breakdown = compute_risk_score(
            severity=severity,
            is_confirmed=marker_verified,
            reachability=reachability,
            exposure=exposure,
        )
        gate_verdict = GateVerdict.NO_PASS if marker_verified else GateVerdict.PASS_

        if marker_verified:
            summary = (
                f"CONFIRMED vulnerability ({breakdown.final_score}/100): "
                f"Marker '{expected_marker}' verified in sandbox response."
            )
        else:
            summary = (
                f"UNCONFIRMED suspect ({breakdown.final_score}/100): "
                f"Exploit probe did not yield marker '{expected_marker}'."
            )
        if vuln_title:
            summary = f"{vuln_title} - {summary}"

        return cls(
            finding_id=finding_id,
            status=status,
            score=breakdown.final_score,
            score_breakdown=breakdown,
            summary=summary,
            marker_verified=marker_verified,
            expected_marker=expected_marker,
            observed_marker=observed_marker,
            gate_verdict=gate_verdict,
        )
