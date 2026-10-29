"""Probe execution harness: runs target app + probe in a single run chain (PRD Gotcha #3)."""

import logging
import re
import shlex
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

# '../' hops a traversal payload is padded to (see ProbeHarness._deepen_traversal).
TRAVERSAL_MIN_DEPTH = 12

PROBE_CHAIN_SCRIPT = """
cd {{ target_dir }} || { echo "shipcheck: cannot cd to target dir" >&2; exit 2; }
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
        """Construct curl invocation for localhost microVM execution.

        Every argument is shell-quoted and every form value URL-encoded by curl,
        so payloads containing quotes, ';', '&', '#' etc. (e.g. ' OR 1=1--)
        reach the target byte-for-byte instead of breaking the probe command.
        """
        endpoint = (plan.route or "/").lstrip("/")
        url = shlex.quote(f"http://127.0.0.1:{self.port}/{endpoint}")

        if plan.http_method.upper() == "POST":
            # For SQLi login or similar POST body
            param = plan.parameter_name or "username"
            field = shlex.quote(f"{param}={payload}")
            return (
                f"curl -s -X POST {url} --data-urlencode {field} "
                f"--data-urlencode 'password=x'"
            )
        else:
            # For GET parameters
            param = self._default_param(plan)
            field = shlex.quote(f"{param}={payload}")
            return f"curl -s -G {url} --data-urlencode {field}"

    @staticmethod
    def _deepen_traversal(payload: str, depth: int = TRAVERSAL_MIN_DEPTH) -> str:
        """Pad a leading run of '../' to `depth`.

        The planner can't know how deep the app sits (/workspace vs a temp dir),
        and extra '../' are harmless once at '/', so padding only removes false
        negatives; it can't make a non-traversable path succeed.
        """
        m = re.match(r"^(?:\.\./)+", payload)
        if not m:
            return payload
        hops = m.group(0).count("../")
        return "../" * max(hops, depth) + payload[m.end():]

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
        target_dir: Optional[str] = None,
    ) -> Evidence:
        """Execute an attack plan inside an isolated sandbox microVM branch.

        `target_dir` defaults to the given sandbox's own working dir, so a probe
        on a forked (e.g. patched) child runs the child's code, not the parent's.
        """
        payload = plan.suggested_payload or "' OR 1=1--"
        if plan.vuln_class == VulnClass.TRAVERSAL:
            payload = self._deepen_traversal(payload)
        probe_cmd = self._build_probe_command(plan, payload)

        tpl = Template(PROBE_CHAIN_SCRIPT)
        chained_script = tpl.render(
            target_dir=shlex.quote(target_dir or sandbox.default_workdir),
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
