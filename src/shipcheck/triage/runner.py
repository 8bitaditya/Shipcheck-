"""Triage pipeline runner coordinating scanners in order (cheap -> expensive) with deduplication."""

import logging
from typing import Dict, List, Optional, Set
from shipcheck.contracts.finding import Finding
from shipcheck.sandbox.base import SandboxBase
from shipcheck.triage.gitleaks import GitleaksScanner
from shipcheck.triage.deps import DependencyScanner
from shipcheck.triage.semgrep import SemgrepScanner

logger = logging.getLogger(__name__)


class TriageRunner:
    """Coordinates static analysis scanners and normalizes outputs into Finding contracts."""

    def __init__(self):
        self.gitleaks = GitleaksScanner()
        self.deps = DependencyScanner()
        self.semgrep = SemgrepScanner()

    async def run_triage(
        self,
        sandbox: SandboxBase,
        changed_files: Optional[Set[str]] = None,
    ) -> List[Finding]:
        all_findings: List[Finding] = []
        seen_fingerprints: Set[str] = set()

        logger.info("Starting static triage: Gitleaks -> Deps -> Semgrep")

        # 1. Fast secret scan
        secrets = await self.gitleaks.scan(sandbox)
        for s in secrets:
            fp = s.fingerprint()
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                all_findings.append(s)

        # 2. Dependency audit
        deps = await self.deps.scan(sandbox)
        for d in deps:
            fp = d.fingerprint()
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                all_findings.append(d)

        # 3. Semgrep SAST scan
        sast = await self.semgrep.scan(sandbox)
        for f in sast:
            # If changed_files provided, scope to PR diff
            if changed_files and f.target.file not in changed_files:
                continue
            fp = f.fingerprint()
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                all_findings.append(f)

        logger.info("Triage complete. Discovered %d unique findings.", len(all_findings))
        return all_findings
