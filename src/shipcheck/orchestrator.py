"""ShipCheck scan orchestrator: chains the full pipeline into one scan() call.

    diff -> triage -> plan -> probe -> verdict -> ground -> rectify

Per the PRD, probes fan out in parallel (one forked sandbox branch per plan)
behind an asyncio.Semaphore capped at MAX_CONCURRENT_OPS, the verdict is a
deterministic risk score, and confirmed findings are rectified with the
"No PASS, No PR" gate. The orchestrator fills each Finding's probe, evidence,
verdict, grounding and fix fields and returns a ScanResult. Every confirmed
finding is grounded with Tavily CVE/advisory context (FR-5) for the report
and the PR body.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from shipcheck import config
from shipcheck.contracts.attack_plan import AttackPlan
from shipcheck.contracts.finding import Finding
from shipcheck.contracts.verdict import (
    ExposureLevel,
    ReachabilityLevel,
    SeverityLevel,
    VerdictCard,
)
from shipcheck.ingest.diff import extract_changed_filenames
from shipcheck.planning.planner import AttackPlanner
from shipcheck.planning.tavily_client import TavilyGroundingClient
from shipcheck.pr.github_bot import GitHubPRBot
from shipcheck.probes.harness import ProbeHarness
from shipcheck.rectify.fixer import RectificationEngine
from shipcheck.sandbox.base import SandboxBase, rebase_workdir
from shipcheck.scoring.reachability import ReachabilityAnalyzer
from shipcheck.triage.runner import TriageRunner

logger = logging.getLogger(__name__)


class ScanResult(BaseModel):
    """Aggregate output of a single ShipCheck scan over a PR diff."""

    scan_id: str = Field(default_factory=lambda: f"scan-{uuid.uuid4().hex[:12]}")
    commit_sha: str = Field(default="HEAD")
    findings: List[Finding] = Field(default_factory=list)
    findings_count: int = 0
    confirmed_count: int = 0
    fixed_count: int = 0
    overall_risk_score: float = 0.0
    pull_requests: List[Dict[str, Any]] = Field(default_factory=list)


def _reachability_level(score: float) -> ReachabilityLevel:
    """Map the reachability heuristic's 0.1-1.0 score onto a ReachabilityLevel."""
    if score >= 1.0:
        return ReachabilityLevel.DIRECT
    if score >= 0.7:
        return ReachabilityLevel.CONDITIONAL
    if score >= 0.5:
        return ReachabilityLevel.UNKNOWN
    return ReachabilityLevel.UNREACHABLE


class ShipCheckScanner:
    """Runs the end-to-end scan pipeline. Each stage is injectable for testing."""

    def __init__(
        self,
        *,
        triage: Optional[TriageRunner] = None,
        planner: Optional[AttackPlanner] = None,
        harness: Optional[ProbeHarness] = None,
        rectifier: Optional[RectificationEngine] = None,
        pr_bot: Optional[GitHubPRBot] = None,
        grounder: Optional[TavilyGroundingClient] = None,
        max_concurrent: Optional[int] = None,
    ):
        self.triage = triage or TriageRunner()
        self.planner = planner or AttackPlanner()
        self.harness = harness or ProbeHarness()
        self.rectifier = rectifier or RectificationEngine()
        self.pr_bot = pr_bot
        self.grounder = grounder or TavilyGroundingClient()
        self.max_concurrent = max_concurrent or config.MAX_CONCURRENT_OPS

    async def scan(
        self,
        sandbox: SandboxBase,
        diff_text: str,
        *,
        commit_sha: str = "HEAD",
        changed_files: Optional[Set[str]] = None,
        app_cmd: str = "python app.py",
        target_dir: Optional[str] = None,
        test_cmd: Optional[str] = "python -m pytest -q",
        rectify: bool = True,
        open_prs: bool = False,
        pr_base: str = "main",
    ) -> ScanResult:
        """Run triage -> plan -> probe -> verdict -> ground -> rectify over a PR diff.

        The code under test must already be materialized in `sandbox`.
        `target_dir` defaults to the sandbox's own working dir (each fork's).
        """
        changed = changed_files or extract_changed_filenames(diff_text)

        # 1. Triage: static suspects scoped to the diff.
        findings: List[Finding] = await self.triage.run_triage(sandbox, changed)
        logger.info("Triage produced %d findings", len(findings))

        # 2. Plan: attack plans for actionable findings.
        batch = await self.planner.plan_attacks(diff_text, findings, commit_sha)
        logger.info("Planner produced %d attack plans", len(batch.plans))

        # 3. Probe: fan out, one forked sandbox branch per plan, capped concurrency.
        plan_finding = self._match_plans_to_findings(batch.plans, findings)
        sem = asyncio.Semaphore(self.max_concurrent)

        async def _probe(plan: AttackPlan):
            async with sem:
                child = await sandbox.fork()
                evidence = await self.harness.execute_step(
                    child, plan, app_cmd=app_cmd,
                    target_dir=rebase_workdir(target_dir, sandbox, child),
                )
                return plan, evidence

        probe_pairs = await asyncio.gather(*[_probe(p) for p in batch.plans])

        for plan, evidence in probe_pairs:
            finding = plan_finding.get(plan.plan_id)
            if finding is None:
                continue
            finding.probe = plan
            finding.evidence = evidence

        # 4. Verdict: deterministic risk score per finding.
        for finding in findings:
            self._attach_verdict(finding)

        # 5. Ground: Tavily CVE/advisory context for every confirmed finding.
        await self._ground_confirmed(findings, sem)

        # 6. Rectify: fix + re-verify every confirmed finding, then (opt-in)
        #    open a draft PR for each fix that passed the gate.
        fixed = 0
        pull_requests: List[Dict[str, Any]] = []
        bot = self.pr_bot if open_prs else None
        if open_prs and bot is None:
            bot = GitHubPRBot()

        if rectify:
            for finding in findings:
                if not finding.is_confirmed:
                    continue
                plan = finding.probe
                if plan is None:
                    continue
                finding.fix = await self.rectifier.apply_and_verify(
                    finding, plan, sandbox,
                    app_cmd=app_cmd, target_dir=target_dir, test_cmd=test_cmd,
                )
                if not finding.fix.is_verified_for_pr():
                    continue
                fixed += 1
                if bot is not None:
                    pr = await bot.open_draft_pr(finding, base=pr_base)
                    if pr:
                        pull_requests.append(
                            {
                                "finding_id": finding.finding_id,
                                "number": pr.get("number"),
                                "url": pr.get("html_url"),
                            }
                        )

        confirmed = sum(1 for f in findings if f.is_confirmed)
        overall = max((f.score for f in findings), default=0.0)

        return ScanResult(
            commit_sha=commit_sha,
            findings=findings,
            findings_count=len(findings),
            confirmed_count=confirmed,
            fixed_count=fixed,
            overall_risk_score=overall,
            pull_requests=pull_requests,
        )

    # ------------------------------------------------------------------ #
    @staticmethod
    def _match_plans_to_findings(
        plans: List[AttackPlan], findings: List[Finding]
    ) -> Dict[str, Finding]:
        """Associate each plan with a finding.

        AttackPlan carries no finding_id, so match on (vuln_class, target_file),
        then fall back to vuln_class alone. Each finding is consumed once.
        """
        by_key: Dict[Tuple, List[Finding]] = {}
        by_class: Dict = {}
        for f in findings:
            by_key.setdefault((f.vuln_class, f.target.file), []).append(f)
            by_class.setdefault(f.vuln_class, []).append(f)

        mapping: Dict[str, Finding] = {}
        used: Set[int] = set()
        for plan in plans:
            candidates = by_key.get((plan.vuln_class, plan.target_file)) or by_class.get(
                plan.vuln_class, []
            )
            chosen = next((f for f in candidates if id(f) not in used), None)
            if chosen is not None:
                used.add(id(chosen))
                mapping[plan.plan_id] = chosen
        return mapping

    async def _ground_confirmed(self, findings: List[Finding], sem: asyncio.Semaphore) -> None:
        """Attach AdvisoryGrounding to each confirmed finding (in parallel)."""

        async def _ground(finding: Finding) -> None:
            async with sem:
                try:
                    finding.grounding = await self.grounder.ground_finding(finding)
                except Exception as err:  # grounding must never sink a scan
                    logger.warning("Grounding failed for %s: %s", finding.finding_id, err)
                    finding.grounding = TavilyGroundingClient.static_grounding(
                        finding, note=f"grounding error ({type(err).__name__}); offline reference used"
                    )
            if finding.cwe_id is None and finding.grounding.cwe_id:
                finding.cwe_id = finding.grounding.cwe_id

        await asyncio.gather(*[_ground(f) for f in findings if f.is_confirmed])

    def _attach_verdict(self, finding: Finding) -> None:
        """Compute and attach a VerdictCard using the reachability + exposure heuristics."""
        marker_verified = finding.is_confirmed
        reach = _reachability_level(ReachabilityAnalyzer.analyze(finding))
        exposure = (
            ExposureLevel.PUBLIC if finding.target.endpoint else ExposureLevel.INTERNAL
        )
        severity = finding.severity if isinstance(finding.severity, SeverityLevel) else SeverityLevel.HIGH
        observed = finding.evidence.matched_text if finding.evidence else None
        expected = finding.probe.expected_marker if finding.probe else (
            finding.evidence.target_marker if finding.evidence else ""
        )
        finding.verdict = VerdictCard.from_probe(
            finding_id=finding.finding_id,
            severity=severity,
            marker_verified=marker_verified,
            expected_marker=expected or "",
            observed_marker=observed,
            reachability=reach,
            exposure=exposure,
            vuln_title=finding.title,
        )
