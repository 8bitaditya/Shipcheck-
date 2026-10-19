"""SandboxClient adapter: coordinates Token Factory sandboxes and local fallbacks with concurrency limits (PRD Gotchas #2, #3, #4)."""

import asyncio
from contextlib import asynccontextmanager
import logging
from pathlib import Path
import re
import time
from typing import Any, AsyncIterator, Callable, Dict, Optional, Set, Union
from jinja2 import Template

from shipcheck import config
from shipcheck.sandbox.base import SandboxBase, SandboxResult
from shipcheck.sandbox.contree_backend import ContreeBackend
from shipcheck.sandbox.local_docker_backend import LocalDockerBackend

logger = logging.getLogger(__name__)

CHAINED_PROBE_TEMPLATE = """#!/usr/bin/env bash
set -e

TARGET_DIR="{{ target_dir }}"
APP_CMD="{{ app_cmd }}"
PORT="{{ port }}"
HEALTH_PATH="{{ health_path }}"
TIMEOUT_SECS="{{ timeout_secs }}"

cd "$TARGET_DIR"

# 1. Start target application in background
echo "[ShipCheck] Starting target: $APP_CMD on port $PORT"
$APP_CMD > /tmp/app_out.log 2> /tmp/app_err.log &
APP_PID=$!

cleanup() {
    echo "[ShipCheck] Cleaning up process $APP_PID"
    kill "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 2. Readiness polling
READY=0
for i in $(seq 1 "$TIMEOUT_SECS"); do
    if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PORT}${HEALTH_PATH}" | grep -q '^[23]'; then
        READY=1
        break
    fi
    sleep 0.5
done

if [ "$READY" -ne 1 ]; then
    echo "[ShipCheck ERROR] Target app failed to start or respond within ${TIMEOUT_SECS}s on port ${PORT}"
    echo "--- App stderr ---"
    cat /tmp/app_err.log
    exit 1
fi

echo "[ShipCheck] Target app is UP. Firing probe payload..."

# 3. Fire probe and capture stdout
START_TS=$(date +%s%N 2>/dev/null || date +%s)
echo "=== SHIPCHECK_RESPONSE_START ==="
{{ probe_cmd }}
echo ""
echo "=== SHIPCHECK_RESPONSE_END ==="
END_TS=$(date +%s%N 2>/dev/null || date +%s)
echo "[ShipCheck] Probe completed."
"""


class SandboxClient:
    """Client adapter isolating all sandbox microVM calls behind Semaphore(40) and client-side timeouts.

    Fully implements PRD FR-1, FR-4, and Gotchas #2, #3, #4.
    """

    def __init__(
        self,
        backend_type: Optional[str] = None,
        max_concurrent: Optional[int] = None,
        default_timeout: Optional[float] = None,
        base_port: int = 5000,
    ):
        self.backend_type = (backend_type or config.SANDBOX_BACKEND).lower()
        self.max_concurrent = max_concurrent or config.MAX_CONCURRENT_OPS
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        self.default_timeout = default_timeout or config.PROBE_TIMEOUT_SECONDS

        # Concurrency port allocator (5000 to 5000 + max_concurrent)
        self._base_port = base_port
        self._available_ports: asyncio.Queue[int] = asyncio.Queue()
        for p in range(self._base_port, self._base_port + self.max_concurrent + 10):
            self._available_ports.put_nowait(p)
        self._allocated_ports: Set[int] = set()

    def create_sandbox(
        self,
        image_or_dir: Optional[Union[str, Path]] = None,
    ) -> SandboxBase:
        """Create a sandbox instance based on configured backend (Contree or LocalDocker)."""
        if self.backend_type == "contree":
            if not config.NEBIUS_API_KEY:
                logger.warning(
                    "NEBIUS_API_KEY not set. Falling back to LocalDockerBackend."
                )
                return LocalDockerBackend(root_dir=image_or_dir)
            try:
                return ContreeBackend(image_ref=image_or_dir)
            except Exception as err:
                logger.error(
                    "Failed to initialize ContreeBackend: %s. Falling back to LocalDockerBackend.",
                    err,
                )
                return LocalDockerBackend(root_dir=image_or_dir)
        else:
            return LocalDockerBackend(root_dir=image_or_dir)

    def spawn(
        self,
        image_or_dir: Optional[Union[str, Path]] = None,
    ) -> SandboxBase:
        """Alias for create_sandbox per PRD/Build Plan nomenclature."""
        return self.create_sandbox(image_or_dir=image_or_dir)

    async def run_guarded(
        self,
        sandbox: SandboxBase,
        command: Optional[str] = None,
        *,
        shell: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        timeout: Optional[float] = None,
        disposable: bool = True,
        files: Optional[Dict[str, Union[str, bytes, Path]]] = None,
    ) -> SandboxResult:
        """Execute inside sandbox bounded by the concurrency semaphore and client-side timeouts."""
        effective_timeout = timeout or self.default_timeout
        async with self.semaphore:
            return await sandbox.run(
                command=command,
                shell=shell,
                env=env,
                cwd=cwd,
                timeout=effective_timeout,
                disposable=disposable,
                files=files,
            )

    async def poll(
        self,
        check_func: Callable[[], Any],
        timeout: float = 15.0,
        interval: float = 0.5,
    ) -> bool:
        """Poll condition until truthy or timeout is reached."""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            res = check_func()
            if asyncio.iscoroutine(res):
                res = await res
            if res:
                return True
            await asyncio.sleep(interval)
        return False

    async def allocate_port(self) -> int:
        """Allocate a dedicated, non-colliding localhost port from the concurrency pool."""
        port = await self._available_ports.get()
        self._allocated_ports.add(port)
        return port

    def release_port(self, port: int) -> None:
        """Return port back to the available queue."""
        if port in self._allocated_ports:
            self._allocated_ports.remove(port)
            self._available_ports.put_nowait(port)

    @asynccontextmanager
    async def managed_port(self) -> AsyncIterator[int]:
        """Context manager for safe port allocation and release."""
        port = await self.allocate_port()
        try:
            yield port
        finally:
            self.release_port(port)

    async def artifacts(
        self,
        sandbox: SandboxBase,
        remote_path: str,
        local_path: Union[str, Path],
    ) -> Path:
        """Download artifact from sandbox to local filesystem."""
        return await sandbox.download_file(remote_path, local_path)

    async def read_artifact(
        self,
        sandbox: SandboxBase,
        remote_path: str,
    ) -> bytes:
        """Read artifact bytes directly from sandbox."""
        return await sandbox.read_file(remote_path)

    async def run_chained_probe(
        self,
        sandbox: SandboxBase,
        app_cmd: str,
        probe_cmd: str,
        target_dir: str = "/workspace",
        health_path: str = "/",
        timeout: float = 45.0,
        port: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute chained run harness (start -> readiness -> attack -> capture -> cleanup).

        Enforces PRD Gotcha #3 (single microVM run chain) and extracts response delimiters.
        """
        allocated = False
        if port is None:
            port = await self.allocate_port()
            allocated = True

        try:
            tpl = Template(CHAINED_PROBE_TEMPLATE)
            chained_script = tpl.render(
                target_dir=target_dir,
                app_cmd=app_cmd,
                port=port,
                health_path=health_path,
                timeout_secs=15,
                probe_cmd=probe_cmd,
            )

            res = await self.run_guarded(
                sandbox,
                shell=chained_script,
                timeout=timeout,
                disposable=True,
            )

            match = re.search(
                r"=== SHIPCHECK_RESPONSE_START ===([\s\S]*?)=== SHIPCHECK_RESPONSE_END ===",
                res.stdout,
            )
            response_body = match.group(1).strip() if match else res.stdout

            return {
                "exit_code": res.exit_code,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "duration_seconds": res.duration_seconds,
                "response_body": response_body,
                "port": port,
                "success": res.exit_code == 0 and match is not None,
            }
        finally:
            if allocated:
                self.release_port(port)

    async def smoke_test(self) -> Dict[str, Any]:
        """Execute Day 1 / PRD §13 verification smoke test checklist.

        Tests images().run(shell="echo ok") and reports environment readiness.
        """
        results: Dict[str, Any] = {
            "backend": self.backend_type,
            "max_concurrent": self.max_concurrent,
            "default_timeout": self.default_timeout,
            "status": "FAILED",
            "checks": {},
        }

        # 1. Base connectivity check
        sandbox = self.create_sandbox()
        start = time.monotonic()
        try:
            res = await self.run_guarded(
                sandbox,
                shell="echo ok",
                timeout=10.0,
                disposable=True,
            )
            elapsed = time.monotonic() - start
            passed = res.exit_code == 0 and "ok" in res.stdout
            results["checks"]["echo_ok"] = {
                "passed": passed,
                "duration_seconds": elapsed,
                "output": res.stdout.strip(),
            }
            if passed:
                results["status"] = "PASSED"
        except Exception as exc:
            results["checks"]["echo_ok"] = {
                "passed": False,
                "error": str(exc),
            }

        # 2. File transfer check
        try:
            await sandbox.apply_files({"test_smoke.txt": b"shipcheck-ok"})
            content = await sandbox.read_file("test_smoke.txt")
            results["checks"]["file_roundtrip"] = {
                "passed": content == b"shipcheck-ok",
            }
        except Exception as exc:
            results["checks"]["file_roundtrip"] = {
                "passed": False,
                "error": str(exc),
            }

        # 3. Port allocator check
        try:
            async with self.managed_port() as p:
                results["checks"]["port_allocator"] = {
                    "passed": isinstance(p, int) and p >= self._base_port,
                    "allocated_port": p,
                }
        except Exception as exc:
            results["checks"]["port_allocator"] = {
                "passed": False,
                "error": str(exc),
            }

        return results
