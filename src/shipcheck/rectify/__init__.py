"""ShipCheck rectification engine (FR-6): generate a fix, apply it, and re-verify.

Per the PRD, the fix generator receives the exploit *evidence* (not just the
code), emits diff-hunk JSON applied via search/replace, then the patch is
re-verified in a child sandbox branch: the exploit marker must be absent AND
the repo's own tests must pass. If either check fails, the fix is reported as
failed verification -- never silently downgraded (the "No PASS, No PR" gate).
"""

from shipcheck.rectify.fixer import RectificationEngine

__all__ = ["RectificationEngine"]
