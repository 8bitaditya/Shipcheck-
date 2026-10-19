"""Probe execution harness: runs target app + probe in a single run chain (PRD Gotcha #3)."""

import logging
import re
import time
from typing import Optional, Tuple
from jinja2 import Template

from shipcheck.contracts.attack_plan import AttackStep
from shipcheck.contracts.evidence import EvidenceBlob, ProbeVerdict, RequestMeta
from shipcheck.contracts.finding import VulnClass
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

    def _build_probe_command(self, step: AttackStep, payload: str) -> str:
        """Construct curl invocation for localhost microVM execution."""
        endpoint = step.target_endpoint.lstrip("/")
        url = f"http://127.0.0.1:{self.port}/{endpoint}"

        if step.http_method.upper() == "POST":
            # For SQLi login or similar POST body
            return f"curl -s -X POST '{url}' -d 'username={payload}&password=x'"
        else:
            # For GET parameters
            param = "q" if step.vuln_class == VulnClass.REFLECTED_XSS else ("file" if step.vuln_class == VulnClass.PATH_TRAVERSAL else "ip")
            return f"curl -s -G '{url}' --data-urlencode '{param}={payload}'"

    def _verify_marker(
        self, vuln_class: VulnClass, response_text: str, payload: str, expected_marker: str
    ) -> Tuple[bool, Optional[str]]:
        """Dispatch to objective boolean marker checker."""
        if vuln_class == VulnClass.SQLI:
            return check_sqli_marker(response_text, expected_marker)
        elif vuln_class == VulnClass.COMMAND_INJECTION:
            return check_cmdi_marker(response_text, expected_marker)
        elif vuln_class == VulnClass.PATH_TRAVERSAL:
            return check_traversal_marker(response_text, expected_marker)
        elif vuln_class == VulnClass.REFLECTED_XSS:
            return check_xss_marker(response_text, payload)
        return False, None

    async def execute_step(
        self,
        sandbox: SandboxBase,
        step: AttackStep,
        app_cmd: str = "python app.py",
        target_dir: str = "/workspace",
    ) -> EvidenceBlob:
        """Execute attack step inside isolated sandbox microVM branch."""
        payload = step.suggested_payloads[0] if step.suggested_payloads else "' OR 1=1--"
        probe_cmd = self._build_probe_command(step, payload)

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
            step.vuln_class, response_body, payload, step.expected_marker
        )

        verdict = (
            ProbeVerdict.CONFIRMED_EXPLOITABLE
            if marker_found
            else ProbeVerdict.NOT_EXPLOITABLE
        )

        # Truncate long response for evidence card readability
        excerpt = response_body[:500] if response_body else "No response recorded"

        return EvidenceBlob(
            step_id=step.step_id,
            finding_id=step.finding_id,
            payload=payload,
            request=RequestMeta(
                endpoint=step.target_endpoint,
                method=step.http_method,
            ),
            response_status=200 if match else 500,
            response_excerpt=excerpt,
            verdict=verdict,
            marker_found=marker_found,
            observed_marker=observed,
            duration_ms=duration_ms,
            raw_logs=res.stdout + ("\n" + res.stderr if res.stderr else ""),
        )
