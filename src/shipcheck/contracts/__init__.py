"""ShipCheck Contracts Package (P2).

These data contracts represent the frozen core interfaces between:
- Triage scanners (Semgrep, Gitleaks, osv-scanner)
- Attack planner (Nemotron Ultra)
- Sandbox probe harness & marker verification
- Risk scoring & verdict generation
- Fix generator (Nemotron Super) & patcher
- PR Bot & reporting dashboard

FROZEN in Week 1 so all team members can build independently.
"""

from shipcheck.contracts.attack_plan import (
    AttackPlan,
    AttackPlanBatch,
    VulnClass,
    CANONICAL_ATTACK_TEMPLATES,
)
from shipcheck.contracts.evidence import (
    Evidence,
    ProbeVerdict,
)
from shipcheck.contracts.fix import (
    DiffHunk,
    FixPatch,
    FixStatus,
)
from shipcheck.contracts.verdict import (
    ExposureLevel,
    GateVerdict,
    ReachabilityLevel,
    RiskScoreBreakdown,
    SeverityLevel,
    VerdictCard,
    VerdictStatus,
    compute_risk_score,
    SEVERITY_WEIGHTS,
    REACHABILITY_WEIGHTS,
    EXPOSURE_WEIGHTS,
)
from shipcheck.contracts.finding import (
    Finding,
    FindingTarget,
)

__all__ = [
    # finding.py
    "Finding",
    "FindingTarget",
    # attack_plan.py
    "AttackPlan",
    "AttackPlanBatch",
    "VulnClass",
    "CANONICAL_ATTACK_TEMPLATES",
    # evidence.py
    "Evidence",
    "ProbeVerdict",
    # fix.py
    "DiffHunk",
    "FixPatch",
    "FixStatus",
    # verdict.py
    "VerdictCard",
    "VerdictStatus",
    "GateVerdict",
    "SeverityLevel",
    "ReachabilityLevel",
    "ExposureLevel",
    "RiskScoreBreakdown",
    "compute_risk_score",
    "SEVERITY_WEIGHTS",
    "REACHABILITY_WEIGHTS",
    "EXPOSURE_WEIGHTS",
]
