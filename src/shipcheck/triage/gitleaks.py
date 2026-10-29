"""Gitleaks scanner runner with --redact flag (PRD NFR-4)."""

from typing import List
from shipcheck.contracts.finding import Finding
from shipcheck.sandbox.base import SandboxBase
from shipcheck.triage.report import run_json_report
from shipcheck.triage.sarif import parse_sarif_to_findings


class GitleaksScanner:
    """Detects leaked API keys, tokens, and credentials with automatic redaction."""

    async def scan(self, sandbox: SandboxBase) -> List[Finding]:
        # --no-git: the sandbox holds the PR's files, not necessarily a git checkout
        cmd = (
            "gitleaks detect --no-git --source . --redact "
            '--report-format sarif --report-path "$OUT"'
        )
        data = await run_json_report(sandbox, cmd)
        return parse_sarif_to_findings(data, "gitleaks") if data else []
