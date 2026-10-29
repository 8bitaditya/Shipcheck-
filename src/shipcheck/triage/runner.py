"""Triage pipeline runner coordinating scanners in order (cheap -> expensive) with deduplication."""

import logging
from typing import Dict, List, Optional, Set
from shipcheck.contracts.attack_plan import VulnClass
from shipcheck.contracts.finding import Finding
from shipcheck.contracts.verdict import SeverityLevel
from shipcheck.sandbox.base import SandboxBase
from shipcheck.triage.gitleaks import GitleaksScanner
from shipcheck.triage.deps import DependencyScanner
from shipcheck.triage.semgrep import SemgrepScanner

logger = logging.getLogger(__name__)

# Findings of the same class in the same file this close together are one bug.
MERGE_WINDOW_LINES = 6

_SEVERITY_RANK = {s: i for i, s in enumerate(
    [SeverityLevel.INFO, SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
)}


def merge_nearby(findings: List[Finding], window: int = MERGE_WINDOW_LINES) -> List[Finding]:
    """Collapse same-class findings within `window` lines of each other in one file.

    Semgrep packs overlap, so one SQL injection is often reported by 3-4 rules on
    adjacent lines. Each would get its own probe and (if unconfirmed) its own
    near-zero card. The merged finding keeps the first location and the highest
    severity, and lists every rule in its description.
    """
    merged: List[Finding] = []
    ordered = sorted(findings, key=lambda f: (f.target.file, f.vuln_class.value, f.target.line or 0))
    for f in ordered:
        last = merged[-1] if merged else None
        if (
            last is not None
            and f.vuln_class != VulnClass.OTHER
            and last.vuln_class == f.vuln_class
            and last.target.file == f.target.file
            and (f.target.line or 0) - (last.target.end_line or last.target.line or 0) <= window
        ):
            last.target.end_line = max(last.target.end_line or 0, f.target.end_line or f.target.line or 0)
            if _SEVERITY_RANK[f.severity] > _SEVERITY_RANK[last.severity]:
                last.severity = f.severity
            rules = (last.description or "").split("Also flagged by: ")
            extra = f.rule_id or "unknown-rule"
            last.description = (
                f"{rules[0].rstrip()} Also flagged by: {rules[1]}, {extra}"
                if len(rules) > 1 else f"{(last.description or '').rstrip()} Also flagged by: {extra}"
            ).strip()
            continue
        merged.append(f)
    return merged


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

        # 3. Semgrep SAST scan (several rules often flag the same sink)
        sast = merge_nearby(await self.semgrep.scan(sandbox))
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
