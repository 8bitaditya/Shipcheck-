"""Semgrep SAST scanner runner with OWASP Top 10 rules plus ShipCheck's own rules."""

import shlex
from typing import List, Optional
from shipcheck.contracts.finding import Finding
from shipcheck.sandbox.base import SandboxBase
from shipcheck.triage.report import run_json_report
from shipcheck.triage.sarif import parse_sarif_to_findings

# Registry packs don't flag Flask request -> open() path traversal, one of the
# four classes the probe harness exploits, so ShipCheck ships a taint rule for it.
SHIPCHECK_RULES = """\
rules:
  - id: shipcheck.python.flask.path-traversal
    mode: taint
    languages: [python]
    severity: ERROR
    message: User input from a Flask request reaches a filesystem path (path traversal); an attacker can use '../' to read files outside the intended directory.
    metadata:
      cwe: "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
      category: security
    pattern-sources:
      - pattern: flask.request.$ATTR
      - pattern: flask.request.$ATTR.get(...)
      - pattern: flask.request.$ATTR[...]
    pattern-sanitizers:
      - pattern: werkzeug.utils.secure_filename(...)
      - pattern: werkzeug.utils.safe_join(...)
      - pattern: flask.safe_join(...)
      - pattern: os.path.basename(...)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: open($P, ...)
              - pattern: io.open($P, ...)
              - pattern: flask.send_file($P, ...)
              - pattern: pathlib.Path($P, ...)
          - focus-metavariable: $P
"""


class SemgrepScanner:
    """Executes Semgrep inside the sandbox against changed files or entire repository."""

    async def scan(
        self, sandbox: SandboxBase, target_path: Optional[str] = None
    ) -> List[Finding]:
        target = shlex.quote(target_path or ".")
        cmd = (
            'RULES="$(mktemp).yml"\n'
            f"cat > \"$RULES\" <<'SHIPCHECK_RULES'\n{SHIPCHECK_RULES}SHIPCHECK_RULES\n"
            "semgrep scan --config p/owasp-top-ten --config \"$RULES\" --sarif --quiet "
            f'--metrics off --output "$OUT" {target}'
        )
        data = await run_json_report(sandbox, cmd, timeout=600.0)
        return parse_sarif_to_findings(data, "semgrep") if data else []
