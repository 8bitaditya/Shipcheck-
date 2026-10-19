"""Semgrep SAST scanner runner with OWASP Top 10 rules."""

import json
from typing import List, Optional
from shipcheck.contracts.finding import Finding
from shipcheck.sandbox.base import SandboxBase
from shipcheck.triage.sarif import parse_sarif_to_findings


class SemgrepScanner:
    """Executes Semgrep inside the sandbox against changed files or entire repository."""

    async def scan(
        self, sandbox: SandboxBase, target_path: Optional[str] = None
    ) -> List[Finding]:
        target = target_path or "."
        cmd = (
            f"semgrep scan --config p/owasp-top-ten --sarif "
            f"--output /tmp/semgrep.sarif {target} || true"
        )
        await sandbox.run(shell=cmd)

        try:
            raw = await sandbox.read_file("/tmp/semgrep.sarif")
            data = json.loads(raw.decode("utf-8"))
            return parse_sarif_to_findings(data, "semgrep")
        except Exception:
            return []
