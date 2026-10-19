"""Reachability analysis assessing if a vulnerable code sink is reachable from external entrypoints."""

from typing import List, Optional
from shipcheck.contracts.finding import Finding


class ReachabilityAnalyzer:
    """Estimates external reachability of detected sinks."""

    @staticmethod
    def analyze(finding: Finding, route_endpoints: Optional[List[str]] = None) -> float:
        """Return reachability score between 0.1 (internal/unreachable) and 1.0 (directly exposed on public route)."""
        # If finding occurs directly in a route handler file (e.g. app.py, routes.py, views.py)
        lower_file = finding.file_path.lower()
        if any(name in lower_file for name in ["app.py", "route", "view", "controller", "api", "handler", "server.js"]):
            return 1.0

        # If it's a test or dev script
        if any(name in lower_file for name in ["test", "fixture", "mock", "script"]):
            return 0.1

        # Default moderate reachability
        return 0.7
