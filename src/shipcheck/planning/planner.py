"""Attack planner leveraging Nemotron-3-Ultra (1M context) and Tavily grounding."""

import json
import logging
from pathlib import Path
from typing import List, Optional

from shipcheck import config
from shipcheck.contracts.attack_plan import (
    CANONICAL_ATTACK_TEMPLATES,
    AttackPlan,
    AttackPlanBatch,
    VulnClass,
)
from shipcheck.contracts.finding import Finding
from shipcheck.llm.nemotron_client import NemotronClient
from shipcheck.llm.mock_llm import MockNemotronClient
from shipcheck.planning.tavily_client import TavilyGroundingClient

logger = logging.getLogger(__name__)

# Vulnerability classes the live probe harness can execute end-to-end.
ACTIONABLE_CLASSES = {
    VulnClass.SQLI,
    VulnClass.CMDI,
    VulnClass.TRAVERSAL,
    VulnClass.XSS,
}

# Default route + parameter heuristics per class, used when triage has none.
_ROUTE_DEFAULTS = {
    VulnClass.SQLI: ("/login", "POST", "username"),
    VulnClass.CMDI: ("/export", "GET", "ip"),
    VulnClass.TRAVERSAL: ("/download", "GET", "file"),
    VulnClass.XSS: ("/search", "GET", "q"),
}


class AttackPlanner:
    """Synthesizes deterministic attack plans for findings within PR diff scope."""

    def __init__(
        self,
        llm_client: Optional[NemotronClient] = None,
        tavily_client: Optional[TavilyGroundingClient] = None,
    ):
        if config.LLM_BACKEND == "mock" or not config.NEBIUS_API_KEY:
            self.llm = MockNemotronClient()
        else:
            self.llm = llm_client or NemotronClient()

        self.tavily = tavily_client or TavilyGroundingClient()

        # Load system prompt template
        prompt_path = Path(__file__).parent.parent / "llm" / "prompts" / "planner.md"
        self.system_prompt = (
            prompt_path.read_text(encoding="utf-8")
            if prompt_path.exists()
            else "You are an attack planner."
        )

    def _heuristic_plan(self, finding: Finding) -> AttackPlan:
        """Build a deterministic AttackPlan for a finding from canonical templates."""
        tmpl = CANONICAL_ATTACK_TEMPLATES.get(finding.vuln_class, {})
        route, method, param = _ROUTE_DEFAULTS.get(
            finding.vuln_class, ("/", "GET", "q")
        )
        return AttackPlan(
            vuln_class=finding.vuln_class,
            target_file=finding.target.file,
            sink=finding.target.sink or tmpl.get("sink_example", finding.vuln_class.value),
            payload_strategy=tmpl.get("payload_strategy", f"Test {finding.vuln_class.value}"),
            expected_marker=tmpl.get("expected_marker", "uid="),
            route=finding.target.endpoint or route,
            http_method=method,
            parameter_name=param,
            suggested_payload=tmpl.get("default_payload", "' OR 1=1--"),
            rationale=f"Heuristic plan for {finding.finding_id} from canonical template",
        )

    async def plan_attacks(
        self,
        diff_text: str,
        findings: List[Finding],
        commit_sha: str = "HEAD",
    ) -> AttackPlanBatch:
        """Formulate attack plans for actionable findings."""
        actionable_findings = [f for f in findings if f.vuln_class in ACTIONABLE_CLASSES]

        if not actionable_findings:
            logger.info("No actionable findings in target classes for attack planning.")
            return AttackPlanBatch(diff_ref=commit_sha, plans=[])

        # Ground the top finding with Tavily
        primary_class = actionable_findings[0].vuln_class.value
        grounding = await self.tavily.search_exploit_context(primary_class)

        prompt = f"""
DIFF:
{diff_text}

TRIAGE FINDINGS:
{json.dumps([f.model_dump(mode="json") for f in actionable_findings], indent=2)}

TAVILY RESEARCH GROUNDING:
Answer: {grounding.get('answer')}
Sources: {grounding.get('sources')}

Generate a structured AttackPlanBatch JSON.
"""

        plan_json = await self.llm.complete_json(
            prompt=prompt,
            system_prompt=self.system_prompt,
            tier="ultra",
        )

        batch = self._parse_batch(plan_json, commit_sha)
        if batch is not None:
            return batch

        # Fallback to deterministic heuristic mapping from canonical templates
        logger.warning("LLM planning returned invalid JSON. Using heuristic fallback.")
        return AttackPlanBatch(
            diff_ref=commit_sha,
            plans=[self._heuristic_plan(f) for f in actionable_findings],
        )

    @staticmethod
    def _parse_batch(plan_json, commit_sha: str) -> Optional[AttackPlanBatch]:
        """Normalize assorted LLM JSON shapes into an AttackPlanBatch."""
        if not plan_json:
            return None
        try:
            if isinstance(plan_json, list):
                return AttackPlanBatch(diff_ref=commit_sha, plans=plan_json)
            if isinstance(plan_json, dict):
                if "plans" in plan_json:
                    plan_json.setdefault("diff_ref", commit_sha)
                    return AttackPlanBatch.model_validate(plan_json)
                # A single bare plan object
                return AttackPlanBatch(
                    diff_ref=commit_sha,
                    plans=[AttackPlan.model_validate(plan_json)],
                )
        except Exception as exc:  # noqa: BLE001 - fall back to heuristic
            logger.warning("Failed to parse LLM attack plan: %s", exc)
        return None
