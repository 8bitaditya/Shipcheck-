"""Fix Contract for ShipCheck.

Defines the structured diff-hunk representation produced by the rectification engine
(Nemotron fixer model) and mechanically applied by patcher.py.

Per ShipCheck specification:
    "Output: structured JSON like {file, search, replace}. Your code finds
     the exact search text and swaps it. If the text isn't found, the patch is rejected.
     This is safer than letting the model rewrite whole files, because it can't
     silently change unrelated code."

JSON Shape:
    {
        "file": "app.py",
        "search": "db.execute(f\\"SELECT * FROM users WHERE name='{name}' AND pw='{pw}'\\")",
        "replace": "db.execute(\\"SELECT * FROM users WHERE name=? AND pw=?\\", (name, pw))"
    }
"""

from __future__ import annotations

import uuid
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field, field_validator, model_validator


class FixStatus(str, Enum):
    """Lifecycle status of a proposed fix patch."""
    PROPOSED = "PROPOSED"
    APPLIED = "APPLIED"
    REJECTED_SEARCH_NOT_FOUND = "REJECTED_SEARCH_NOT_FOUND"
    REJECTED_AMBIGUOUS_MATCH = "REJECTED_AMBIGUOUS_MATCH"
    VERIFIED_PASSED = "VERIFIED_PASSED"       # Exploit marker gone AND repo tests pass
    VERIFIED_FAILED = "VERIFIED_FAILED"       # Re-attack still worked OR repo tests failed


class DiffHunk(BaseModel):
    """A single atomic search-and-replace hunk for a file.
    
    Fields strictly implement:
        {file, search, replace}
    """
    file: str = Field(
        ...,
        description="Relative path of the target file to patch (e.g. app.py)"
    )
    search: str = Field(
        ...,
        description="Exact character-for-character text block to locate and replace"
    )
    replace: str = Field(
        ...,
        description="Replacement text block to substitute in place of search. "
                    "Empty string means code deletion (use intentionally)."
    )
    allow_deletion: bool = Field(
        default=False,
        description="Must be explicitly set to True if replace is empty (code deletion)"
    )

    @field_validator("file")
    @classmethod
    def validate_file_path(cls, v: str) -> str:
        """Validates the file path is safe: non-empty, relative, no traversal, no null bytes."""
        if not v or not v.strip():
            raise ValueError("file cannot be empty")
        v = v.strip()
        # Reject null bytes (CWE-158)
        if "\x00" in v:
            raise ValueError("file path contains null byte")
        # Reject absolute paths (Unix and Windows)
        if v.startswith("/") or v.startswith("\\") or (len(v) >= 2 and v[1] == ":"):
            raise ValueError(f"file must be a relative path, got: '{v}'")
        # Reject directory traversal components
        parts = PurePosixPath(v).parts
        if ".." in parts:
            raise ValueError(f"file path contains '..' traversal: '{v}'")
        return v

    @field_validator("search")
    @classmethod
    def must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("search cannot be empty")
        return v

    @model_validator(mode="after")
    def check_empty_replace(self) -> DiffHunk:
        """Guard against accidental code deletion by LLM-generated patches."""
        if not self.replace and not self.allow_deletion:
            raise ValueError(
                "replace is empty, which would delete the matched code. "
                "Set allow_deletion=True if this is intentional."
            )
        return self

    def apply_to_text(self, content: str) -> Tuple[str, bool, str]:
        """Mechanically applies this hunk to the provided source text.
        
        Returns:
            (new_content, success, reason)
        Rules:
            1. If search is not found -> REJECT (avoids hallucinated patches)
            2. If search matches multiple times -> REJECT (avoids ambiguous edits)
            3. If search matches exactly once -> Replace and succeed
        """
        occurrences = content.count(self.search)
        if occurrences == 0:
            return content, False, f"Target search string not found in '{self.file}'"
        if occurrences > 1:
            return (
                content,
                False,
                f"Ambiguous match: search string appears {occurrences} times in '{self.file}'. Exact context required."
            )
        
        new_content = content.replace(self.search, self.replace, 1)
        return new_content, True, "Hunk applied successfully"


class FixPatch(BaseModel):
    """Complete patch package for one or more findings.
    
    Contains one or more DiffHunk items, along with root-cause explanation
    and verification gate indicators (No PASS, No PR rule).
    """
    fix_id: str = Field(
        default_factory=lambda: f"fix-{uuid.uuid4().hex[:12]}",
        description="Unique identifier for this fix proposal"
    )
    finding_id: Optional[str] = Field(
        default=None,
        description="Reference to the Finding ID being rectified"
    )
    hunks: List[DiffHunk] = Field(
        default_factory=list,
        description="List of atomic search-and-replace diff hunks"
    )
    root_cause: Optional[str] = Field(
        default=None,
        description="Explanation of why the vulnerability occurred"
    )
    explanation: Optional[str] = Field(
        default=None,
        description="Explanation of how the proposed change fixes the vulnerability safely"
    )
    status: FixStatus = Field(
        default=FixStatus.PROPOSED,
        description="Current status of the fix patch"
    )
    
    # Gate verification results (PRoject.txt Section 1.3 & Section 3)
    recheck_attack_marker_absent: Optional[bool] = Field(
        default=None,
        description="True if re-running identical attack on patched code proved marker is GONE"
    )
    repo_tests_passed: Optional[bool] = Field(
        default=None,
        description="True if the target repo's own automated test suite passed on patched code"
    )
    verification_log: Optional[str] = Field(
        default=None,
        description="Output logs from the child sandbox re-probe and test runner"
    )

    @classmethod
    def from_hunk(
        cls,
        file: str,
        search: str,
        replace: str,
        finding_id: Optional[str] = None,
        root_cause: Optional[str] = None,
        explanation: Optional[str] = None
    ) -> FixPatch:
        """Convenience factory to create a FixPatch from a single {file, search, replace} dict."""
        hunk = DiffHunk(file=file, search=search, replace=replace)
        return cls(
            finding_id=finding_id,
            hunks=[hunk],
            root_cause=root_cause,
            explanation=explanation,
            status=FixStatus.PROPOSED
        )

    def is_verified_for_pr(self) -> bool:
        """Strict verification gate: 'No PASS, No PR' rule.
        
        Fix must pass BOTH:
            1. Re-attack: marker must be gone (recheck_attack_marker_absent is True)
            2. Regression tests: repo's tests must pass (repo_tests_passed is True)
        """
        return bool(self.recheck_attack_marker_absent and self.repo_tests_passed)
