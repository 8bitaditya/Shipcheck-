"""ShipCheck PR bot (FR-7): open a draft GitHub PR for a verified fix.

Per the PRD, the bot applies the patch on a ``shipcheck/fix-<class>-<slug>``
branch and opens a DRAFT pull request (``draft: true``) whose body carries the
full evidence. It dedupes by ``head.ref`` before creating, acts only when the
fix passed the "No PASS, No PR" gate, and never calls ``PUT /pulls/{n}/merge``
-- a human always merges.
"""

from shipcheck.pr.body import branch_name, pr_title, render_pr_body
from shipcheck.pr.github_bot import GitHubPRBot

__all__ = ["GitHubPRBot", "render_pr_body", "branch_name", "pr_title"]
