"""Gitleaks scanner runner with --redact flag (PRD NFR-4)."""

import json
from typing import List
from shipcheck.contracts.finding import Finding
from shipcheck.sandbox.base import SandboxBase
from shipcheck.triage.sarif import parse_sarif_to_findings


class GitleaksScanner:
    """Detects leaked API keys, tokens, and credentials with automatic redaction."""

    async def scan(self, sandbox: SandboxBase) -> List[Finding]:
        cmd = "gitleaks detect --redact --report-format sarif --report-path /tmp/gitleaks.sarif || true"
        res = await sandbox.run(shell=cmd)

        try:
            raw = await sandbox.read_file("/tmp/gitleaks.sarif")
            data = json.loads(raw.decode("utf-8"))
            return parse_sarif_to_findings(data, "gitleaks")
        except Exception:
            # Fallback if no secrets found or gitleaks was not present
            return []
