"""Local fallback sandbox implementation (Sandforge pattern) for offline development & testing."""

import asyncio
import logging
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Dict, Optional, Union

from shipcheck.sandbox.base import SandboxBase, SandboxResult

logger = logging.getLogger(__name__)


def _find_bash_executable() -> Optional[str]:
    """Locate a functional bash/sh executable across Linux, macOS, and Windows (Git Bash)."""
    if os.name == "nt":
        candidates = [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
            r"C:\Program Files (x86)\Git\bin\bash.exe",
            os.path.expanduser(r"~\AppData\Local\Programs\Git\bin\bash.exe"),
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
    which_sh = shutil.which("sh")
    if which_sh:
        return which_sh
    which_bash = shutil.which("bash")
    if which_bash and (os.name != "nt" or "system32" not in which_bash.lower()):
        return which_bash
    return which_bash or which_sh


class LocalDockerBackend(SandboxBase):
    """Local subprocess/directory sandbox providing the exact same contract as ContreeBackend."""

    def __init__(self, root_dir: Optional[Union[str, Path]] = None):
        if root_dir:
            self.workdir = Path(root_dir).resolve()
            self._cleanup = False
        else:
            self._temp_dir = tempfile.mkdtemp(prefix="shipcheck_sandbox_")
            self.workdir = Path(self._temp_dir).resolve()
            self._cleanup = True

    @property
    def default_workdir(self) -> str:
        """The code lives in this sandbox's own temp dir, not /workspace."""
        return str(self.workdir)

    async def apply_files(self, files: Dict[str, Union[str, bytes, Path]]) -> None:
        """Materialize or overwrite files directly into the sandbox working directory."""
        for rel_path, content in files.items():
            dest = self.workdir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                dest.write_bytes(content)
            elif isinstance(content, Path):
                shutil.copy2(content, dest)
            else:
                dest.write_text(str(content), encoding="utf-8")

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
        """Execute command locally in the sandbox working directory."""
        start_time = time.monotonic()

        # Materialize files if passed
        if files:
            await self.apply_files(files)

        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)

        exec_cwd = self.workdir / cwd if cwd else self.workdir

        bash_exe = _find_bash_executable()
        temp_script_path: Optional[Path] = None

        try:
            if shell:
                # If a full shell script is supplied, write to a temp script to handle multi-line/bash syntax
                if bash_exe:
                    temp_script_path = self.workdir / f"_run_{int(time.time() * 1000)}.sh"
                    # Ensure unix-style line endings for shell scripts
                    clean_script = shell.replace("\r\n", "\n")
                    temp_script_path.write_text(clean_script, encoding="utf-8")

                    proc = await asyncio.create_subprocess_exec(
                        bash_exe,
                        str(temp_script_path),
                        cwd=str(exec_cwd),
                        env=exec_env,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                else:
                    proc = await asyncio.create_subprocess_shell(
                        shell,
                        cwd=str(exec_cwd),
                        env=exec_env,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
            elif command:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    cwd=str(exec_cwd),
                    env=exec_env,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                raise ValueError("Either command or shell script must be provided")

            stdout_data, stderr_data = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            exit_code = proc.returncode if proc.returncode is not None else 0
            stdout_str = stdout_data.decode("utf-8", errors="replace")
            stderr_str = stderr_data.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            exit_code = 124
            stdout_str = ""
            stderr_str = f"Execution timed out after {timeout} seconds"
        except Exception as exc:
            exit_code = 1
            stdout_str = ""
            stderr_str = f"Execution error: {exc}"
        finally:
            if temp_script_path and temp_script_path.exists():
                try:
                    temp_script_path.unlink()
                except Exception:
                    pass

        duration = time.monotonic() - start_time
        return SandboxResult(
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            duration_seconds=duration,
            checkpoint_id=str(self.workdir) if not disposable else None,
        )

    async def fork(self) -> "LocalDockerBackend":
        """Fork by cloning the current working directory into a new sandbox branch."""
        new_sandbox = LocalDockerBackend()
        shutil.copytree(self.workdir, new_sandbox.workdir, dirs_exist_ok=True)
        return new_sandbox

    async def checkpoint(self, tag: Optional[str] = None) -> str:
        """Tag current directory snapshot as a checkpoint."""
        return tag or str(self.workdir)

    async def read_file(self, remote_path: str) -> bytes:
        """Read file bytes from working directory."""
        path = self.workdir / remote_path
        if not path.exists():
            raise FileNotFoundError(f"File not found in sandbox: {remote_path}")
        return path.read_bytes()

    async def download_file(self, remote_path: str, local_path: Union[str, Path]) -> Path:
        """Copy file from sandbox working directory to target destination."""
        src = self.workdir / remote_path
        dest = Path(local_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        return dest

    def cleanup(self):
        """Clean up temporary sandbox directory if managed."""
        if self._cleanup and hasattr(self, "_temp_dir") and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)

    def __del__(self):
        self.cleanup()
