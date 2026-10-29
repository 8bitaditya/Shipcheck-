"""Real Docker sandbox backend: each sandbox is a container from the probe image.

The closest local stand-in for ConTree microVMs (`SANDBOX_BACKEND=docker`):
the code under test lives in /workspace inside a container built from
sandbox/image/Dockerfile.probe, so triage uses the image's pinned scanners and
probes hit the app on the container's own loopback (no host port clashes, so
probes can run in parallel). fork() snapshots the container with `docker
commit` and starts a child from the snapshot, so a patched child never touches
its parent -- the same branching model as ConTree images.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Union

from shipcheck import config
from shipcheck.sandbox.base import SandboxBase, SandboxResult

logger = logging.getLogger(__name__)

WORKDIR = "/workspace"


async def _docker(*args: str, stdin: Optional[bytes] = None, timeout: float = 120.0) -> SandboxResult:
    """Run a docker CLI command; exit 124 on timeout (like the other backends)."""
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        "docker", *args,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(stdin), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return SandboxResult(124, "", f"Execution timed out after {timeout} seconds",
                             duration_seconds=time.monotonic() - start)
    return SandboxResult(
        exit_code=proc.returncode if proc.returncode is not None else 1,
        stdout=out.decode("utf-8", "replace"),
        stderr=err.decode("utf-8", "replace"),
        duration_seconds=time.monotonic() - start,
    )


class DockerBackend(SandboxBase):
    """Sandbox backed by one long-running container of the probe image."""

    def __init__(self, image: Optional[str] = None, *, platform: Optional[str] = None):
        self.image = image or config.SHIPCHECK_DOCKER_IMAGE
        self.platform = platform or config.SHIPCHECK_DOCKER_PLATFORM
        self.container: Optional[str] = None
        self._snapshots: List[str] = []  # images this sandbox committed (removed on cleanup)
        self._lock = asyncio.Lock()

    async def _ensure(self) -> str:
        async with self._lock:
            if self.container is None:
                name = f"shipcheck-sbx-{uuid.uuid4().hex[:10]}"
                args = ["run", "-d", "--name", name, "-w", WORKDIR]
                if self.platform:
                    args += ["--platform", self.platform]
                res = await _docker(*args, self.image, "sleep", "infinity", timeout=300.0)
                if res.exit_code != 0:
                    raise RuntimeError(f"docker run {self.image} failed: {res.stderr.strip()}")
                await _docker("exec", name, "mkdir", "-p", WORKDIR)
                self.container = name
            return self.container

    @staticmethod
    def _abs(path: str) -> str:
        return path if path.startswith("/") else f"{WORKDIR}/{path.removeprefix('./')}"

    async def run(
        self,
        command: Optional[str] = None,
        *,
        shell: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        timeout: float = 45.0,
        disposable: bool = True,
        files: Optional[Dict[str, Union[str, bytes, Path]]] = None,
    ) -> SandboxResult:
        """Run a command/script in the container (state persists, like LocalDockerBackend)."""
        name = await self._ensure()
        if files:
            await self.apply_files(files)
        script = shell if shell is not None else command
        if script is None:
            raise ValueError("Either command or shell script must be provided")
        args = ["exec", "-i", "-w", self._abs(cwd) if cwd else WORKDIR]
        for key, value in (env or {}).items():
            args += ["-e", f"{key}={value}"]
        # The script goes in on stdin, so it can be any size and needs no quoting.
        res = await _docker(*args, name, "bash", "-s", stdin=script.encode("utf-8"), timeout=timeout)
        if res.exit_code == 124 and "timed out" in res.stderr:
            # The timed-out process may still run inside the container; stop it.
            await _docker("exec", name, "pkill", "-f", "-9", "python|curl|semgrep", timeout=15.0)
        return res

    async def apply_files(self, files: Dict[str, Union[str, bytes, Path]]) -> None:
        name = await self._ensure()
        for dest, content in files.items():
            data = (
                content.read_bytes() if isinstance(content, Path)
                else content.encode("utf-8") if isinstance(content, str)
                else bytes(content)
            )
            target = self._abs(dest)
            parent = shlex.quote(str(Path(target).parent))
            res = await _docker(
                "exec", "-i", name, "sh", "-c", f"mkdir -p {parent} && cat > {shlex.quote(target)}",
                stdin=data,
            )
            if res.exit_code != 0:
                raise RuntimeError(f"could not write {target}: {res.stderr.strip()}")

    async def read_file(self, remote_path: str) -> bytes:
        name = await self._ensure()
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", name, "cat", self._abs(remote_path),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise FileNotFoundError(f"File not found in sandbox: {remote_path}")
        return out

    async def download_file(self, remote_path: str, local_path: Union[str, Path]) -> Path:
        dest = Path(local_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(await self.read_file(remote_path))
        return dest

    async def checkpoint(self, tag: Optional[str] = None) -> str:
        """Snapshot the container's filesystem as an image and return its id."""
        name = await self._ensure()
        res = await _docker("commit", name, *([tag] if tag else []), timeout=300.0)
        if res.exit_code != 0:
            raise RuntimeError(f"docker commit failed: {res.stderr.strip()}")
        image_id = res.stdout.strip()
        if not tag:
            self._snapshots.append(image_id)
        return tag or image_id

    async def fork(self) -> "DockerBackend":
        """Child sandbox started from a snapshot of this one (parent is untouched)."""
        snapshot = await self.checkpoint()
        return DockerBackend(image=snapshot, platform=self.platform)

    def cleanup(self) -> None:
        """Remove the container and any snapshot images it created."""
        if self.container:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True)
            self.container = None
        for image_id in self._snapshots:
            subprocess.run(["docker", "rmi", "-f", image_id], capture_output=True)
        self._snapshots.clear()
