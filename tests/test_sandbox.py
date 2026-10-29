"""Unit and integration tests for the Sandbox subsystem (LocalDockerBackend, ContreeBackend, SandboxClient).

Runnable directly via `python -m unittest tests/test_sandbox.py` or `pytest`.
"""

import asyncio
import os
from pathlib import Path
import sys
import tempfile
import unittest

# Ensure src/ is on PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from shipcheck.sandbox.base import SandboxResult
from shipcheck.sandbox.client import SandboxClient
from shipcheck.sandbox.contree_backend import ContreeBackend
from shipcheck.sandbox.local_docker_backend import LocalDockerBackend


class TestSandbox(unittest.IsolatedAsyncioTestCase):
    """Test suite for the ShipCheck sandbox subsystem."""

    async def test_local_sandbox_basic_run(self):
        """Verify basic command execution in LocalDockerBackend."""
        sandbox = LocalDockerBackend()
        try:
            res = await sandbox.run(command="echo hello_shipcheck", timeout=5.0)
            self.assertEqual(res.exit_code, 0)
            self.assertIn("hello_shipcheck", res.stdout)
            self.assertGreater(res.duration_seconds, 0)
        finally:
            sandbox.cleanup()

    async def test_local_sandbox_apply_and_read_files(self):
        """Verify file materialization, reading, and downloading in sandbox."""
        sandbox = LocalDockerBackend()
        temp_dir = tempfile.mkdtemp()
        try:
            files = {
                "config.json": '{"app": "vulnshop", "port": 5000}',
                "nested/secret.txt": b"super-secret-token",
            }
            await sandbox.apply_files(files)

            # Test read_file
            cfg_bytes = await sandbox.read_file("config.json")
            self.assertIn(b"vulnshop", cfg_bytes)

            secret_bytes = await sandbox.read_file("nested/secret.txt")
            self.assertEqual(secret_bytes, b"super-secret-token")

            # Test download_file
            local_dest = Path(temp_dir) / "downloaded_secret.txt"
            downloaded = await sandbox.download_file("nested/secret.txt", local_dest)
            self.assertTrue(downloaded.exists())
            self.assertEqual(downloaded.read_bytes(), b"super-secret-token")
        finally:
            sandbox.cleanup()

    async def test_local_sandbox_fork(self):
        """Verify that fork creates an independent cloned directory sandbox."""
        sandbox = LocalDockerBackend()
        try:
            await sandbox.apply_files({"original.txt": "v1"})
            child_sandbox = await sandbox.fork()
            try:
                # Modify file in child
                await child_sandbox.apply_files({"original.txt": "v2", "child_only.txt": "child"})

                # Child should have new content
                child_content = await child_sandbox.read_file("original.txt")
                self.assertEqual(child_content, b"v2")
                self.assertTrue((child_sandbox.workdir / "child_only.txt").exists())

                # Parent should retain original content
                parent_content = await sandbox.read_file("original.txt")
                self.assertEqual(parent_content, b"v1")
                self.assertFalse((sandbox.workdir / "child_only.txt").exists())
            finally:
                child_sandbox.cleanup()
        finally:
            sandbox.cleanup()

    async def test_local_sandbox_timeout(self):
        """Verify that timeout aborts stalled process and returns exit code 124."""
        sandbox = LocalDockerBackend()
        try:
            res = await sandbox.run(
                # sys.executable: macOS has no bare `python` outside a venv
                command=f"\"{sys.executable}\" -c \"import time; time.sleep(10)\"",
                timeout=0.5,
            )
            self.assertEqual(res.exit_code, 124)
            self.assertIn("timed out", res.stderr.lower())
        finally:
            sandbox.cleanup()

    async def test_sandbox_client_port_allocator(self):
        """Verify port allocator provides distinct, non-colliding ports and releases them."""
        client = SandboxClient(base_port=6000, max_concurrent=5)

        p1 = await client.allocate_port()
        p2 = await client.allocate_port()
        self.assertEqual(p1, 6000)
        self.assertEqual(p2, 6001)
        self.assertNotEqual(p1, p2)

        # Test context manager release
        async with client.managed_port() as p3:
            self.assertEqual(p3, 6002)

        # Queue is FIFO: after releasing, p1 (6000) and p3 (6002) are recycled
        client.release_port(p1)
        p_next = await client.allocate_port()
        self.assertIn(p_next, range(6000, 6020))
        self.assertNotIn(p_next, [p2])  # p2 is still in use!
        client.release_port(p2)
        client.release_port(p_next)

    async def test_sandbox_client_run_guarded(self):
        """Verify SandboxClient.run_guarded respects concurrency and executes successfully."""
        client = SandboxClient(backend_type="mock", max_concurrent=2)
        sandbox = client.create_sandbox()

        try:
            async def task(idx: int):
                return await client.run_guarded(
                    sandbox,
                    command=f"echo task_{idx}",
                    timeout=5.0,
                )

            results = await asyncio.gather(*(task(i) for i in range(4)))
            self.assertEqual(len(results), 4)
            for idx, res in enumerate(results):
                self.assertEqual(res.exit_code, 0)
                self.assertIn(f"task_{idx}", res.stdout)
        finally:
            if isinstance(sandbox, LocalDockerBackend):
                sandbox.cleanup()

    async def test_sandbox_client_smoke_test(self):
        """Verify that smoke_test() performs readiness checks on the active backend."""
        client = SandboxClient(backend_type="mock")
        smoke_results = await client.smoke_test()

        self.assertEqual(smoke_results["status"], "PASSED")
        self.assertIn("echo_ok", smoke_results["checks"])
        self.assertTrue(smoke_results["checks"]["echo_ok"]["passed"])
        self.assertTrue(smoke_results["checks"]["file_roundtrip"]["passed"])
        self.assertTrue(smoke_results["checks"]["port_allocator"]["passed"])

    async def test_sandbox_client_run_chained_probe(self):
        """Verify chained microVM execution harness (PRD Gotcha #3) on LocalDockerBackend."""
        client = SandboxClient(backend_type="mock")
        sandbox = client.create_sandbox()
        port = await client.allocate_port()

        # Minimal HTTP target app
        server_code = (
            "from http.server import HTTPServer, BaseHTTPRequestHandler\n"
            "import sys\n"
            "port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000\n"
            "class H(BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        self.send_response(200)\n"
            "        self.end_headers()\n"
            "        self.wfile.write(b'admin@vulnshop.local')\n"
            "    def log_message(self, format, *args): pass\n"
            "HTTPServer(('127.0.0.1', port), H).serve_forever()\n"
        )
        try:
            await sandbox.apply_files({"server.py": server_code})
            probe_result = await client.run_chained_probe(
                sandbox=sandbox,
                app_cmd=f"python server.py {port}",
                probe_cmd=f"curl -s http://127.0.0.1:{port}/",
                target_dir=str(sandbox.workdir),
                health_path="/",
                timeout=15.0,
                port=port,
            )
            self.assertEqual(probe_result["exit_code"], 0)
            self.assertIn("admin@vulnshop.local", probe_result["response_body"])
        finally:
            client.release_port(port)
            if isinstance(sandbox, LocalDockerBackend):
                sandbox.cleanup()

    def test_contree_backend_iam_auth(self):
        """Verify ContreeBackend configures IAMAuth with NEBIUS_PROJECT_ID (PRD Gotcha #2)."""
        try:
            from contree_sdk.config import IAMAuth
            backend = ContreeBackend(image_ref="test-image")
            auth = backend.client._config.auth
            self.assertIsInstance(auth, IAMAuth)
            self.assertTrue(hasattr(auth, "project_id"))
        except ImportError:
            self.skipTest("contree-sdk not available in environment")


if __name__ == "__main__":
    unittest.main()
