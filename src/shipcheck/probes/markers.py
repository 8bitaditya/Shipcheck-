"""Deterministic boolean marker verifiers (PRD Section 5 FR-4).

Verdict rule is strictly boolean on an objective marker, never on LLM judgment.
"""

import re
from typing import Optional, Tuple


def check_sqli_marker(response_text: str, custom_marker: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """Confirms SQL injection if response contains multiple user records or admin email/row."""
    if custom_marker and custom_marker.lower() in response_text.lower():
        return True, custom_marker

    # Common database markers in response text
    patterns = [
        r"admin@(?:[a-zA-Z0-9.-]+)",
        r"(?:id|user_id)[\s:=]+1[\s,]+(?:username|name)[\s:=]+admin",
        r"sqlite_master",
        r"syntax error in query",
    ]
    for pat in patterns:
        match = re.search(pat, response_text, re.IGNORECASE)
        if match:
            return True, match.group(0)

    # Check for authentication bypass indicators
    if any(phrase in response_text.lower() for phrase in ["welcome, admin", "logged in as admin", "role: admin"]):
        return True, "admin session indicator"

    return False, None


def check_cmdi_marker(stdout_text: str, custom_marker: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """Confirms command injection if stdout contains uid= / root / etc."""
    if custom_marker and custom_marker in stdout_text:
        return True, custom_marker

    # Standard POSIX id output
    match = re.search(r"uid=\d+\([a-zA-Z0-9_-]+\)", stdout_text)
    if match:
        return True, match.group(0)

    # Windows whoami output
    match_win = re.search(r"[a-zA-Z0-9_-]+\\[a-zA-Z0-9_-]+", stdout_text)
    if "nt authority" in stdout_text.lower() or "administrator" in stdout_text.lower():
        return True, "system user token"

    return False, None


def check_traversal_marker(response_text: str, custom_marker: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """Confirms path traversal if response contains root: / passwd file markers."""
    if custom_marker and custom_marker in response_text:
        return True, custom_marker

    # /etc/passwd signature
    if re.search(r"root:[x*]:0:0:", response_text):
        return True, "root:x:0:0:"

    if "root:*" in response_text or "/bin/bash" in response_text or "/bin/sh" in response_text:
        return True, "passwd file content"

    # Windows win.ini signature
    if "[fonts]" in response_text.lower() or "[extensions]" in response_text.lower():
        return True, "win.ini file content"

    return False, None


def check_xss_marker(response_text: str, payload: str) -> Tuple[bool, Optional[str]]:
    """Confirms reflected XSS if raw HTML contains the unescaped script payload."""
    if not payload:
        return False, None

    # Exact unescaped payload reflection
    if payload in response_text:
        # Check that it is not safely escaped as &lt;script&gt;
        escaped_version = payload.replace("<", "&lt;").replace(">", "&gt;")
        if escaped_version in response_text and payload not in response_text.replace(escaped_version, ""):
            return False, None
        return True, payload

    # Common script reflection
    if "<script>alert(1)</script>" in response_text:
        return True, "<script>alert(1)</script>"

    return False, None
