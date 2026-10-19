"""Contract: Diff-hunk JSON and Rectification Fix. Frozen for Week 1."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class FixStatus(str, Enum):
    PATCH_PENDING = "PATCH_PENDING"
    PATCH_APPLIED = "PATCH_APPLIED"
    VERIFIED_CLOSED = "VERIFIED_CLOSED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    TESTS_BROKEN = "TESTS_BROKEN"


class FixHunk(BaseModel):
    """Diff hunk JSON model for mechanical search-and-replace."""

    file_path: str = Field(..., description="Target file path relative to repo root")
    search_block: str = Field(..., description="Exact string block in source code to find")
    replace_block: str = Field(..., description="Exact replacement string block to substitute")
    rationale: str = Field(default="", description="Nemotron explanation of why this fix closes the vulnerability")


class PatchResult(BaseModel):
    """Result of patch application and child branch re-verification."""

    finding_id: str = Field(..., description="Associated finding ID")
    hunks: List[FixHunk] = Field(default_factory=list, description="List of hunks applied")
    status: FixStatus = Field(default=FixStatus.PATCH_PENDING)
    reprobe_passed: bool = Field(
        default=False,
        description="True if exploit probe now fails to reproduce (marker is absent)",
    )
    repo_tests_passed: bool = Field(
        default=False,
        description="True if existing repository test suite continues to pass",
    )
    error_message: Optional[str] = Field(default=None, description="Details if patch application failed")
