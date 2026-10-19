"""Contract: PoC Evidence Blob captured from Sandbox execution. Frozen for Week 1."""

from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ProbeVerdict(str, Enum):
    CONFIRMED_EXPLOITABLE = "CONFIRMED_EXPLOITABLE"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    PROBE_FAILED = "PROBE_FAILED"
    TIMEOUT = "TIMEOUT"


class RequestMeta(BaseModel):
    """Metadata regarding the request sent to the sandbox application."""

    endpoint: str = Field(..., description="Target URL / path requested")
    method: str = Field(default="GET", description="HTTP method used")
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = Field(default=None)


class EvidenceBlob(BaseModel):
    """Deterministic evidence block produced after probe harness execution in a microVM."""

    step_id: str = Field(..., description="Attack step ID")
    finding_id: str = Field(..., description="Triage finding ID")
    payload: str = Field(..., description="Actual payload fired in the sandbox")
    request: RequestMeta = Field(..., description="Request details sent")
    response_status: int = Field(default=0, description="HTTP status code returned")
    response_excerpt: str = Field(default="", description="Relevant excerpt of response containing or missing marker")
    verdict: ProbeVerdict = Field(..., description="Objective verdict derived from boolean marker check")
    marker_found: bool = Field(..., description="True if expected marker was definitively discovered")
    observed_marker: Optional[str] = Field(default=None, description="Exact text snippet matched")
    duration_ms: float = Field(default=0.0, description="Elapsed probe duration in milliseconds")
    raw_logs: Optional[str] = Field(default=None, description="Captured stdout/stderr from microVM execution")
