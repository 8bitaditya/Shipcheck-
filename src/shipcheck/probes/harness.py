"""Probe execution harness: runs target app + probe in a single run chain (PRD Gotcha #3)."""

import logging
import re
import time
from typing import Optional, Tuple
from jinja2 import Template

from shipcheck.contracts.attack_plan import AttackPlan, VulnClass
from shipcheck.contracts.evidence import Evidence, ProbeVerdict
from shipcheck.sandbox.base import SandboxBase
from shipcheck.probes.markers import (
    check_sqli_marker,
    check_cmdi_marker,
    check_traversal_marker,
    check_xss_marker,
)

logger = logging.getLogger(__name__)

PROBE_CHAIN_SCRIPT = """
cd {{ target_dir }}
{{ app_cmd }} > /tmp/app_out.log 2> /tmp/app_err.log &
APP_PID=$!

cleanup() {
    kill $APP_PID 2>/dev/null || true
}
trap cleanup EXIT

# Readiness poll
READY=0
for i in $(seq 1 15); do
    if curl -s "http://127.0.0.1:{{ port }}/" > /dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.3
done

echo "=== SHIPCHECK_RESPONSE_START ==="
{{ probe_cmd }}
echo "=== SHIPCHECK_RESPONSE_END ==="
"""


class ProbeHarness:
    """Executes attack steps against the sandboxed target and produces deterministic evidence."""

    def __init__(self, port: int = 5000):
        self.port = port

    def _default_param(self, plan: AttackPlan) -> str:
        """Pick the request parameter name for a probe."""
        if plan.parameter_name:
            return plan.parameter_name
        if plan.vuln_class == VulnClass.XSS:
            return "q"
        if plan.vuln_class == VulnClass.TRAVERSAL:
            return "file"
        return "ip"

    def _build_probe_command(self, plan: AttackPlan, payload: str) -> str:
        """Construct curl invocation for localhost microVM execution."""
        endpoint = (plan.route or "/").lstrip("/")
        url = f"http://127.0.0.1:{self.port}/{endpoint}"

        if plan.http_method.upper() == "POST":
            # For SQLi login or similar POST body
            param = plan.parameter_name or "username"
            return f"curl -s -X POST '{url}' -d '{param}={payload}&password=x'"
        else:
            # For GET parameters
            param = self._default_param(plan)
            return f"curl -s -G '{url}' --data-urlencode '{param}={payload}'"

    def _verify_marker(
        self, vuln_class: VulnClass, response_text: str, payload: str, expected_marker: str
    ) -> Tuple[bool, Optional[str]]:
        """Dispatch to objective boolean marker checker."""
        if vuln_class == VulnClass.SQLI:
            return check_sqli_marker(response_text, expected_marker)
        elif vuln_class == VulnClass.CMDI:
            return check_cmdi_marker(response_text, expected_marker)
        elif vuln_class == VulnClass.TRAVERSAL:
            return check_traversal_marker(response_text, expected_marker)
        elif vuln_class == VulnClass.XSS:
            return check_xss_marker(response_text, payload)
        return False, None

    async def execute_step(
        self,
        sandbox: SandboxBase,
        plan: AttackPlan,
        app_cmd: str = "python app.py",
        target_dir: str = "/workspace",
    ) -> Evidence:
        """Execute an attack plan inside an isolated sandbox microVM branch."""
        payload = plan.suggested_payload or "' OR 1=1--"
        probe_cmd = self._build_probe_command(plan, payload)

        tpl = Template(PROBE_CHAIN_SCRIPT)
        chained_script = tpl.render(
            target_dir=target_dir,
            app_cmd=app_cmd,
            port=self.port,
            probe_cmd=probe_cmd,
        )

        start_time = time.monotonic()
        res = await sandbox.run(shell=chained_script, timeout=30.0, disposable=True)
        duration_ms = (time.monotonic() - start_time) * 1000

        # Extract response from stdout delimiters
        match = re.search(
            r"=== SHIPCHECK_RESPONSE_START ===([\s\S]*?)=== SHIPCHECK_RESPONSE_END ===",
            res.stdout,
        )
        response_body = match.group(1).strip() if match else res.stdout

        marker_found, observed = self._verify_marker(
            plan.vuln_class, response_body, payload, plan.expected_marker
        )

        verdict = ProbeVerdict.CONFIRMED if marker_found else ProbeVerdict.UNCONFIRMED

        # Truncate long response for evidence card readability
        excerpt = response_body[:500] if response_body else "No response recorded"

        return Evidence(
            plan_id=plan.plan_id,
            payload=payload,
            request={
                "endpoint": plan.route or "/",
                "method": plan.http_method,
            },
            response_status=200 if match else 500,
            response_excerpt=excerpt,
            verdict=verdict,
            marker_found=marker_found,
            target_marker=plan.expected_marker,
            matched_text=observed,
            execution_time_ms=duration_ms,
        )
