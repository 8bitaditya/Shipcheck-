"""Attack planner leveraging Nemotron-3-Ultra (1M context) and Tavily grounding."""

import difflib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

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

# Context budget for full source files in the planning prompt (Ultra has 1M tokens).
MAX_SOURCE_CHARS_PER_FILE = 60_000
MAX_SOURCE_CHARS_TOTAL = 300_000

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
            finding_id=finding.finding_id,
        )

    async def plan_attacks(
        self,
        diff_text: str,
        findings: List[Finding],
        commit_sha: str = "HEAD",
        sources: Optional[Dict[str, str]] = None,
    ) -> AttackPlanBatch:
        """Formulate attack plans for actionable findings.

        `sources` maps file path -> full content for the files the findings sit
        in. A PR diff often shows only a few changed lines; without the whole
        file the model has to guess routes, parameter names and markers.
        """
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
{self._sources_block(sources)}
TAVILY RESEARCH GROUNDING:
Answer: {grounding.get('answer')}
Sources: {grounding.get('sources')}

Generate a structured attack plan batch (AttackPlanBatch JSON).
"""

        plan_json = await self.llm.complete_json(
            prompt=prompt,
            system_prompt=self.system_prompt,
            tier="ultra",
        )

        batch = self._parse_batch(plan_json, commit_sha, actionable_findings)
        if batch is None:
            # Fallback to deterministic heuristic mapping from canonical templates
            logger.warning("LLM planning returned invalid JSON. Using heuristic fallback.")
            batch = AttackPlanBatch(diff_ref=commit_sha, plans=[])

        # Fill gaps the model left with templates -- but only where nothing of that
        # class in that file was planned: a template guesses the route, so for a
        # second same-class finding it would likely probe (and credit) the wrong one.
        planned_ids = {p.finding_id for p in batch.plans if p.finding_id}
        covered = {(p.vuln_class, p.target_file) for p in batch.plans}
        llm_count = len(batch.plans)
        for f in actionable_findings:
            if f.finding_id in planned_ids or (f.vuln_class, f.target.file) in covered:
                continue
            batch.plans.append(self._heuristic_plan(f))
            planned_ids.add(f.finding_id)
            covered.add((f.vuln_class, f.target.file))
        logger.info(
            "Attack plans: %d from the LLM, %d from canonical templates",
            llm_count, len(batch.plans) - llm_count,
        )
        return batch

    @staticmethod
    def _sources_block(sources: Optional[Dict[str, str]]) -> str:
        """Full current content of the affected files, within a context budget."""
        if not sources:
            return ""
        parts, used = [], 0
        for path, text in sorted(sources.items()):
            text = text[:MAX_SOURCE_CHARS_PER_FILE]
            if used + len(text) > MAX_SOURCE_CHARS_TOTAL:
                break
            used += len(text)
            parts.append(f"### {path}\n```\n{text}\n```")
        return (
            "\nSOURCE FILES (full current content of each file with a finding -- take real "
            "routes, HTTP methods, parameter names and markers from here):\n"
            + "\n\n".join(parts) + "\n"
        )

    @staticmethod
    def _raw_plans(plan_json: Any) -> List[Dict[str, Any]]:
        """Pull plan dicts out of the shapes models actually return."""
        if isinstance(plan_json, list):
            return [p for p in plan_json if isinstance(p, dict)]
        if isinstance(plan_json, dict):
            for key in ("plans", "steps"):  # canonical, then legacy planner.md schema
                if isinstance(plan_json.get(key), list):
                    return [p for p in plan_json[key] if isinstance(p, dict)]
            if "vuln_class" in plan_json:  # a single bare plan object
                return [plan_json]
        return []

    @staticmethod
    def _match_finding(raw: Dict[str, Any], vuln_class: VulnClass, findings: List[Finding]) -> Optional[Finding]:
        """The triage finding a raw plan targets: by id, else the closest same-class sink."""
        by_id = next((f for f in findings if f.finding_id == raw.get("finding_id")), None)
        if by_id:
            return by_id
        same_class = [f for f in findings if f.vuln_class == vuln_class]
        target = raw.get("target_file")
        candidates = [f for f in same_class if f.target.file == target] or same_class
        if len(candidates) <= 1:
            return candidates[0] if candidates else None
        # Several candidates: pick the one whose code best matches the plan's sink/route.
        hint = f"{raw.get('sink') or ''} {raw.get('route') or raw.get('target_endpoint') or ''}"

        def similarity(f: Finding) -> float:
            code = f"{f.target.sink or ''} {f.target.code_snippet or ''} {f.target.endpoint or ''}"
            return difflib.SequenceMatcher(None, hint, code).ratio()

        return max(candidates, key=similarity)

    def _normalize_plan(self, raw: Dict[str, Any], findings: List[Finding]) -> Dict[str, Any]:
        """Map legacy keys onto AttackPlan and fill gaps from the matching finding/template."""
        plan = dict(raw)
        vc = str(plan.get("vuln_class", "")).strip().lower().replace(" ", "_")
        plan["vuln_class"] = vc
        vuln_class = AttackPlan.normalize_vuln_class(vc)

        if not plan.get("route") and plan.get("target_endpoint"):
            plan["route"] = plan["target_endpoint"]
        if not plan.get("suggested_payload"):
            payloads = plan.get("suggested_payloads") or plan.get("payloads")
            if isinstance(payloads, list) and payloads:
                plan["suggested_payload"] = str(payloads[0])
            elif plan.get("payload"):
                plan["suggested_payload"] = str(plan["payload"])
        if isinstance(plan.get("http_method"), str):
            plan["http_method"] = plan["http_method"].upper()

        finding = self._match_finding(plan, vuln_class, findings)
        plan["finding_id"] = finding.finding_id if finding else None
        tmpl = CANONICAL_ATTACK_TEMPLATES.get(vuln_class, {})
        _route, method, param = _ROUTE_DEFAULTS.get(vuln_class, ("/", "GET", "q"))
        fills = {
            "target_file": finding.target.file if finding else None,
            "sink": (finding.target.sink if finding else None) or tmpl.get("sink_example"),
            "payload_strategy": tmpl.get("payload_strategy"),
            "expected_marker": tmpl.get("expected_marker"),
            "route": finding.target.endpoint if finding else None,
            "http_method": method,
            "parameter_name": param,
        }
        for key, value in fills.items():
            if value and not str(plan.get(key) or "").strip():
                plan[key] = value
        # drop legacy-only keys so they don't leak into the contract
        for key in ("step_id", "target_endpoint", "suggested_payloads", "payloads", "payload"):
            plan.pop(key, None)
        return plan

    def _parse_batch(
        self, plan_json: Any, commit_sha: str, findings: Optional[List[Finding]] = None
    ) -> Optional[AttackPlanBatch]:
        """Normalize assorted LLM JSON shapes into an AttackPlanBatch.

        Plans are validated one by one, so a single malformed plan no longer
        discards the model's whole batch. Returns None if nothing usable came back.
        """
        plans: List[AttackPlan] = []
        for raw in self._raw_plans(plan_json):
            try:
                plan = AttackPlan.model_validate(self._normalize_plan(raw, findings or []))
            except Exception as exc:  # noqa: BLE001 - skip just this plan
                logger.warning("Dropping invalid LLM attack plan: %s", exc)
                continue
            if plan.vuln_class in ACTIONABLE_CLASSES:
                plans.append(plan)
        if not plans:
            return None
        return AttackPlanBatch(diff_ref=commit_sha, plans=plans)
