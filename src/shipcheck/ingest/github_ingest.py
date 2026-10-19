"""GitHub repository and pull request ingestion."""

import asyncio
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Tuple
import httpx

from shipcheck import config


class GitHubIngest:
    """Clones repositories or fetches PR diffs for analysis."""

    def __init__(self, token: Optional[str] = None):
        self.token = token or config.GITHUB_TOKEN

    async def fetch_pr_diff(self, repo_full_name: str, pr_number: int) -> str:
        """Fetch the unified diff of a GitHub pull request via API."""
        url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
        headers = {
            "Accept": "application/vnd.github.v3.diff",
            "User-Agent": "ShipCheck-Bot",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, follow_redirects=True)
            resp.raise_for_status()
            return resp.text

    async def clone_repo(
        self, repo_url: str, branch: Optional[str] = None
    ) -> Tuple[Path, bool]:
        """Clone repository into a temporary directory."""
        temp_dir = tempfile.mkdtemp(prefix="shipcheck_repo_")
        target_path = Path(temp_dir)

        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd.extend(["-b", branch])
        cmd.extend([repo_url, str(target_path)])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()

        if proc.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Git clone failed: {stderr.decode()}")

        return target_path, True
