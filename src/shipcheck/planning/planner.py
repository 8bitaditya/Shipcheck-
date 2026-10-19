"""Attack planner leveraging Nemotron-3-Ultra (1M context) and Tavily grounding."""

import json
import logging
from pathlib import Path
from typing import List, Optional

from shipcheck import config
from shipcheck.contracts.attack_plan import AttackPlan, AttackStep
from shipcheck.contracts.finding import Finding, VulnClass
from shipcheck.llm.nemotron_client import NemotronClient
from shipcheck.llm.mock_llm import MockNemotronClient
from shipcheck.planning.tavily_client import TavilyGroundingClient

logger = logging.getLogger(__name__)


class AttackPlanner:
    """Synthesizes deterministic attack steps for findings within PR diff scope."""

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

    async def plan_attacks(
        self,
        diff_text: str,
        findings: List[Finding],
        commit_sha: str = "HEAD",
    ) -> AttackPlan:
        """Formulate attack steps for actionable findings."""
        actionable_findings = [
            f
            for f in findings
            if f.vuln_class
            in [
                VulnClass.SQLI,
                VulnClass.COMMAND_INJECTION,
                VulnClass.PATH_TRAVERSAL,
                VulnClass.REFLECTED_XSS,
            ]
        ]

        if not actionable_findings:
            logger.info("No actionable findings in target classes for attack planning.")
            return AttackPlan(
                plan_id="empty-plan",
                commit_sha=commit_sha,
                summary="No actionable vulnerabilities identified in target classes.",
                steps=[],
            )

        # Ground the top finding with Tavily
        primary_class = actionable_findings[0].vuln_class.value
        grounding = await self.tavily.search_exploit_context(primary_class)

        prompt = f"""
DIFF:
{diff_text}

TRIAGE FINDINGS:
{json.dumps([f.model_dump() for f in actionable_findings], indent=2)}

TAVILY RESEARCH GROUNDING:
Answer: {grounding.get('answer')}
Sources: {grounding.get('sources')}

Generate a structured AttackPlan JSON.
"""

        plan_json = await self.llm.complete_json(
            prompt=prompt,
            system_prompt=self.system_prompt,
            tier="ultra",
        )

        if not plan_json:
            # Fallback to direct heuristic mapping
            logger.warning("LLM planning returned invalid JSON. Using heuristic fallback.")
            steps = []
            for f in actionable_findings:
                steps.append(
                    AttackStep(
                        step_id=f"step-{f.id}",
                        finding_id=f.id,
                        vuln_class=f.vuln_class,
                        target_file=f.file_path,
                        target_endpoint="/login" if f.vuln_class == VulnClass.SQLI else "/export",
                        http_method="POST" if f.vuln_class == VulnClass.SQLI else "GET",
                        payload_strategy=f"Test {f.vuln_class.value}",
                        expected_marker="admin" if f.vuln_class == VulnClass.SQLI else "uid=",
                        suggested_payloads=["' OR 1=1--"],
                    )
                )
            return AttackPlan(
                plan_id=f"plan-{commit_sha[:8]}",
                commit_sha=commit_sha,
                summary="Heuristic fallback attack plan",
                steps=steps,
            )

        return AttackPlan.model_validate(plan_json)
