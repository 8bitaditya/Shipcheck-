"""GitHub PR bot (FR-7): open a draft PR for a verified fix via the REST API.

Fully API-driven (no local checkout): create the branch ref, apply the fix
hunks through the Contents API, then open a draft PR. Dedupes by head ref.
Only ever acts on a fix that passed the "No PASS, No PR" gate, and never calls
the merge endpoint.
"""

from __future__ import annotations

import base64
import logging
from collections import OrderedDict
from typing import Any, Dict, List, Optional

import httpx

from shipcheck import config
from shipcheck.contracts.finding import Finding
from shipcheck.pr.body import branch_name, pr_title, render_pr_body

logger = logging.getLogger(__name__)


class PRBotError(RuntimeError):
    """Raised when the PR cannot be opened (bad config, patch no longer applies)."""


class GitHubPRBot:
    """Opens a single draft PR per verified finding. Never merges."""

    def __init__(
        self,
        repo: Optional[str] = None,
        token: Optional[str] = None,
        *,
        client: Optional[httpx.AsyncClient] = None,
        base_url: str = "https://api.github.com",
    ):
        self.repo = repo or config.GITHUB_REPOSITORY
        self.token = token or config.GITHUB_TOKEN
        self.base_url = base_url.rstrip("/")
        self._client = client  # injected (tests); otherwise one is created per call

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    @property
    def _owner(self) -> str:
        return self.repo.split("/")[0]

    async def open_draft_pr(
        self,
        finding: Finding,
        *,
        base: str = "main",
        commit_message: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Open (or update) a draft PR for `finding`. Returns the PR JSON, or None.

        Returns None when the fix has not passed the gate -- the "No PASS, No PR"
        rule -- so a failed or unverified fix never reaches a reviewer.
        """
        if not (finding.fix and finding.fix.is_verified_for_pr()):
            logger.info("Skipping PR for %s: fix not verified (No PASS, No PR).", finding.finding_id)
            return None
        if not self.repo or not self.token:
            raise PRBotError("GITHUB_REPOSITORY and GITHUB_TOKEN must be set to open a PR.")

        if self._client is not None:
            return await self._open(self._client, finding, base, commit_message)

        async with httpx.AsyncClient(
            base_url=self.base_url, headers=self._headers(), timeout=30.0
        ) as client:
            return await self._open(client, finding, base, commit_message)

    # ------------------------------------------------------------------ #
    async def _open(self, client, finding, base, commit_message) -> Dict[str, Any]:
        head = branch_name(finding)
        body = render_pr_body(finding, repo=self.repo)

        # Dedupe: update the body if a PR for this head is already open.
        existing = await self._find_open_pr(client, head)
        if existing:
            await client.patch(
                f"/repos/{self.repo}/pulls/{existing['number']}", json={"body": body}
            )
            logger.info("Updated existing draft PR #%s for %s", existing["number"], head)
            return existing

        # Create the branch ref from the base branch tip.
        base_sha = await self._base_sha(client, base)
        ref_resp = await client.post(
            f"/repos/{self.repo}/git/refs",
            json={"ref": f"refs/heads/{head}", "sha": base_sha},
        )
        if ref_resp.status_code not in (200, 201, 422):  # 422 = ref already exists
            raise PRBotError(f"Could not create branch {head}: {ref_resp.status_code} {ref_resp.text}")

        # Apply the fix hunks file by file through the Contents API.
        msg = commit_message or f"{pr_title(finding)}\n\nApplied by ShipCheck."
        for file_path, hunks in self._hunks_by_file(finding).items():
            await self._patch_file(client, file_path, hunks, head, msg)

        # Open the DRAFT pull request.
        pr_resp = await client.post(
            f"/repos/{self.repo}/pulls",
            json={
                "title": pr_title(finding),
                "head": head,
                "base": base,
                "body": body,
                "draft": True,
            },
        )
        if pr_resp.status_code not in (200, 201):
            raise PRBotError(f"Could not open PR: {pr_resp.status_code} {pr_resp.text}")
        pr = pr_resp.json()
        logger.info("Opened draft PR #%s for %s", pr.get("number"), head)
        return pr

    @staticmethod
    def _hunks_by_file(finding: Finding) -> "OrderedDict[str, List]":
        grouped: "OrderedDict[str, List]" = OrderedDict()
        for h in (finding.fix.hunks if finding.fix else []):
            grouped.setdefault(h.file, []).append(h)
        return grouped

    async def _find_open_pr(self, client, head: str) -> Optional[Dict[str, Any]]:
        resp = await client.get(
            f"/repos/{self.repo}/pulls",
            params={"state": "open", "head": f"{self._owner}:{head}"},
        )
        if resp.status_code != 200:
            return None
        items = resp.json()
        return items[0] if items else None

    async def _base_sha(self, client, base: str) -> str:
        resp = await client.get(f"/repos/{self.repo}/git/ref/heads/{base}")
        if resp.status_code != 200:
            raise PRBotError(f"Could not read base ref '{base}': {resp.status_code}")
        return resp.json()["object"]["sha"]

    async def _patch_file(self, client, file_path: str, hunks: List, head: str, msg: str) -> None:
        resp = await client.get(f"/repos/{self.repo}/contents/{file_path}", params={"ref": head})
        if resp.status_code != 200:
            raise PRBotError(f"Could not read '{file_path}' on {head}: {resp.status_code}")
        data = resp.json()
        content = base64.b64decode(data["content"]).decode("utf-8", "replace")
        for h in hunks:
            content, ok, reason = h.apply_to_text(content)
            if not ok:
                raise PRBotError(f"Patch no longer applies to '{file_path}': {reason}")
        put = await client.put(
            f"/repos/{self.repo}/contents/{file_path}",
            json={
                "message": msg,
                "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
                "sha": data["sha"],
                "branch": head,
            },
        )
        if put.status_code not in (200, 201):
            raise PRBotError(f"Could not write '{file_path}': {put.status_code} {put.text}")
