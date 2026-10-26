"""Evidence Contract for ShipCheck.

Defines the structure of exploit evidence captured by the sandbox probe harness.
Evidence provides objective proof of vulnerability confirmation and is fed
directly into the rectification engine (fixer model) to guide targeted patches.

JSON Shape:
    {
        "payload": "' OR 1=1--",
        "request": "POST /login HTTP/1.1\\nHost: localhost:5000\\n...\\nusername=' OR 1=1--",
        "response_status": 200,
        "response_excerpt": "Welcome admin! User ID: 1, Role: administrator",
        "verdict": "CONFIRMED",
        "marker_found": true
    }
"""

from __future__ import annotations

import datetime
import uuid
from enum import Enum
from typing import Any, Dict, Optional, Union
from pydantic import BaseModel, Field, field_validator


class ProbeVerdict(str, Enum):
    """The outcome of an exploit probe execution.
    
    Per ShipCheck rules:
        - CONFIRMED: The expected marker was objectively found in the execution output.
        - UNCONFIRMED: The probe finished, but the expected marker was NOT found.
        - ERROR: The probe failed to execute (timeout, app crash, network failure).
        - TIMEOUT: The probe exceeded execution time limit.
    """
    CONFIRMED = "CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


class Evidence(BaseModel):
    """The Evidence contract defining the concrete proof of an exploit attempt.
    
    Fields strictly implement:
        {payload, request, response_status, response_excerpt, verdict, marker_found}
    """
    evidence_id: str = Field(
        default_factory=lambda: f"ev-{uuid.uuid4().hex[:12]}",
        description="Unique identifier for this captured evidence artifact"
    )
    plan_id: Optional[str] = Field(
        default=None,
        description="Reference to the originating AttackPlan ID"
    )
    payload: str = Field(
        ...,
        description="The exact payload string injected during the probe"
    )
    request: Union[str, Dict[str, Any]] = Field(
        ...,
        description="Full request string (e.g. curl cmd / HTTP wire format) or structured request dictionary"
    )
    response_status: int = Field(
        ...,
        description="HTTP status code (e.g. 200, 500) or shell process exit code"
    )
    response_excerpt: str = Field(
        ...,
        description="Crucial excerpt of response body or terminal output demonstrating exploit impact"
    )
    verdict: ProbeVerdict = Field(
        ...,
        description="Objective probe verdict: CONFIRMED if marker_found is True, else UNCONFIRMED/ERROR"
    )
    marker_found: bool = Field(
        ...,
        description="Deterministic boolean check: true if expected marker appeared in output"
    )

    # Contextual metadata for tracing & reporting
    target_marker: Optional[str] = Field(
        default=None,
        description="The specific expected marker string searched for in the output"
    )
    matched_text: Optional[str] = Field(
        default=None,
        description="Exact text snippet that matched the expected marker"
    )
    sandbox_branch_id: Optional[str] = Field(
        default=None,
        description="Sandbox branch/container ID where this probe executed"
    )
    execution_time_ms: Optional[float] = Field(
        default=None,
        description="Wall-clock time of the probe execution in milliseconds"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(),
        description="UTC timestamp of evidence capture"
    )
    truncated: bool = Field(
        default=False,
        description="Indicates whether response_excerpt was truncated to protect token budget"
    )

    @field_validator("verdict", mode="before")
    @classmethod
    def normalize_verdict(cls, v: Any) -> ProbeVerdict:
        if isinstance(v, ProbeVerdict):
            return v
        if isinstance(v, str):
            val = v.strip().upper()
            if val in ProbeVerdict.__members__:
                return ProbeVerdict[val]
            if val in ("PASS", "SUCCESS", "CONFIRMED", "VULNERABLE", "TRUE"):
                return ProbeVerdict.CONFIRMED
            if val in ("FAIL", "FAILED", "UNCONFIRMED", "SAFE", "FALSE"):
                return ProbeVerdict.UNCONFIRMED
            if val in ("TIMEOUT", "TIMED_OUT"):
                return ProbeVerdict.TIMEOUT
        return ProbeVerdict.ERROR

    @classmethod
    def capture(
        cls,
        payload: str,
        request: Union[str, Dict[str, Any]],
        response_status: int,
        raw_output: str,
        expected_marker: str,
        plan_id: Optional[str] = None,
        sandbox_branch_id: Optional[str] = None,
        execution_time_ms: Optional[float] = None,
        max_excerpt_chars: int = 2048,
        case_sensitive: bool = True,
    ) -> Evidence:
        """Deterministic factory that creates Evidence by string-matching expected_marker.
        
        Per ShipCheck core philosophy:
        'Verdict by marker. Code checks a boolean: is uid= in the output? is root: in the response?
         No LLM decides this. LLMs hallucinate; a string match doesn't.'

        Args:
            case_sensitive: If False, performs case-insensitive marker matching.
                            Default True preserves strict deterministic behavior.
        """
        if case_sensitive:
            marker_found = expected_marker in raw_output
            marker_idx = raw_output.find(expected_marker) if marker_found else -1
        else:
            marker_found = expected_marker.lower() in raw_output.lower()
            marker_idx = raw_output.lower().find(expected_marker.lower()) if marker_found else -1
        verdict = ProbeVerdict.CONFIRMED if marker_found else ProbeVerdict.UNCONFIRMED

        # Extract focused excerpt around marker if found, else take head/tail
        truncated = False
        if marker_found:
            # Window of 200 chars before, rest after up to max_excerpt_chars
            start_idx = max(0, marker_idx - 200)
            end_idx = min(len(raw_output), start_idx + max_excerpt_chars)
            excerpt = raw_output[start_idx:end_idx]
            if len(raw_output) > max_excerpt_chars:
                truncated = True
        else:
            if len(raw_output) > max_excerpt_chars:
                excerpt = raw_output[:max_excerpt_chars]
                truncated = True
            else:
                excerpt = raw_output

        return cls(
            plan_id=plan_id,
            payload=payload,
            request=request,
            response_status=response_status,
            response_excerpt=excerpt,
            verdict=verdict,
            marker_found=marker_found,
            target_marker=expected_marker,
            matched_text=expected_marker if marker_found else None,
            sandbox_branch_id=sandbox_branch_id,
            execution_time_ms=execution_time_ms,
            truncated=truncated,
        )

    @staticmethod
    def _sanitize_for_prompt(text: str, max_length: int = 2048) -> str:
        """Sanitize untrusted text before embedding in an LLM prompt.

        - Truncates to max_length to prevent context flooding
        - Escapes markdown code fences to prevent fence-breaking injection
        - Wraps content so the model can distinguish data from instructions
        """
        truncated = text[:max_length]
        # Escape triple backticks so attacker cannot break out of code fences
        sanitized = truncated.replace("```", "` ` `")
        return sanitized

    def to_fixer_prompt_context(self) -> str:
        """Formats this evidence into a concise markdown context block for the LLM fixer.

        Note: All untrusted fields (payload, request, response) are sanitized
        to mitigate indirect prompt injection from attacker-controlled output.
        """
        req_str = self.request if isinstance(self.request, str) else str(self.request)
        safe_payload = self._sanitize_for_prompt(self.payload, max_length=512)
        safe_request = self._sanitize_for_prompt(req_str, max_length=1024)
        safe_excerpt = self._sanitize_for_prompt(self.response_excerpt, max_length=2048)
        safe_marker = self._sanitize_for_prompt(
            self.target_marker or "", max_length=256
        )
        return (
            f"### Exploit Evidence ({self.verdict.value})\n"
            f"<BEGIN_EVIDENCE_DATA>\n"
            f"- **Injected Payload:** `{safe_payload}`\n"
            f"- **Target Marker Proven:** `{safe_marker}` (Found: {self.marker_found})\n"
            f"- **Response Status:** `{self.response_status}`\n"
            f"```http\n{safe_request}\n```\n"
            f"**Leaked Output Excerpt:**\n"
            f"```\n{safe_excerpt}\n```\n"
            f"<END_EVIDENCE_DATA>"
        )
