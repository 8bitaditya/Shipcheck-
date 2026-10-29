"""Run a scanner inside the sandbox and read its report back from the same run.

Scanners write their report to a fresh temp file which is `cat`-ed at the end of
the same shell run, so the report comes back on stdout. This works on every
backend (a ConTree disposable run discards its filesystem, so a report file
can't be read afterwards) and parallel scans never share a fixed /tmp path.
"""

import json
import logging
from typing import Any, Optional

from shipcheck.sandbox.base import SandboxBase

logger = logging.getLogger(__name__)

REPORT_MARKER = "=== SHIPCHECK_REPORT ==="


def report_script(scan_cmd: str) -> str:
    """Wrap `scan_cmd` (which writes to "$OUT") so the report is printed after a marker."""
    return (
        'OUT="$(mktemp)"\n'
        f"{scan_cmd} >/dev/null 2>&1 || true\n"
        f'echo "{REPORT_MARKER}"\n'
        'cat "$OUT" 2>/dev/null\n'
        'rm -f "$OUT"\n'
    )


async def run_json_report(
    sandbox: SandboxBase, scan_cmd: str, *, timeout: float = 300.0
) -> Optional[Any]:
    """Run a scanner and return its parsed JSON/SARIF report, or None."""
    res = await sandbox.run(shell=report_script(scan_cmd), timeout=timeout)
    out = res.stdout or ""
    if REPORT_MARKER not in out:
        logger.warning("Scanner produced no report marker (exit %s): %s", res.exit_code, (res.stderr or "")[-300:])
        return None
    body = out.split(REPORT_MARKER, 1)[1].strip()
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError as err:
        logger.warning("Scanner report is not valid JSON: %s", err)
        return None
