"""Golden-run replay: a recorded real scan served by GET /api/demo.

Per the build plan, the judges' demo must never depend on a live model or
sandbox call, so a real end-to-end scan is recorded once (scripts/record_golden.py)
and replayed. Recording redacts details of the machine it ran on.
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

from shipcheck import config

logger = logging.getLogger(__name__)

GOLDEN_PATH = Path(
    os.getenv("SHIPCHECK_GOLDEN_PATH", str(config.BASE_DIR / "golden" / "vulnshop_scan.json"))
)

_ID_OUTPUT = [
    # `id` output from the command-injection probe names the local user and groups
    (re.compile(r"\b(uid|gid)=(\d+)\((?!root\))[^)]*\)"), r"\1=\2(sandbox)"),  # root is not personal
    (re.compile(r"\bgroups=[^\s\"<\\]+"), "groups=<redacted>"),
    # local sandbox temp dirs
    (re.compile(r"(?:/private)?/var/folders/[^\s\"'\\]+?/shipcheck_sandbox_\w+"), "<sandbox>"),
    (re.compile(r"/tmp/shipcheck_sandbox_\w+"), "<sandbox>"),
]


def redact_local_details(text: str) -> str:
    """Strip the recording machine's username, home dir, groups and temp paths."""
    for pattern, repl in _ID_OUTPUT:
        text = pattern.sub(repl, text)
    home = str(Path.home())
    if home and home != "/":
        text = text.replace(home, "~")
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = ""
    if user and len(user) > 2:
        text = re.sub(rf"\b{re.escape(user)}\b", "sandbox", text)
    return text


def load_golden(path: Optional[Path] = None) -> Optional[Any]:
    """Return the recorded ScanResult, or None if there is no (valid) recording."""
    from shipcheck.orchestrator import ScanResult  # local import: avoids a cycle

    p = Path(path or GOLDEN_PATH)
    if not p.is_file():
        return None
    try:
        return ScanResult.model_validate(json.loads(p.read_text(encoding="utf-8")))
    except Exception as err:  # noqa: BLE001 - a bad recording falls back to the sample
        logger.warning("Ignoring invalid golden run %s: %s", p, err)
        return None
