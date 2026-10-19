"""Abstract Base Interface for Sandboxes (Token Factory Contree and Local Fallback)."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Union


@dataclass
class SandboxResult:
    """Output from a sandbox command execution."""
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float = 0.0
    checkpoint_id: Optional[str] = None
    files_created: Dict[str, bytes] = field(default_factory=dict)


class SandboxBase(ABC):
    """Abstract interface defining required sandbox microVM operations."""

    @abstractmethod
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
        """Execute a command or shell script inside the sandbox microVM."""
        pass

    @abstractmethod
    async def fork(self) -> "SandboxBase":
        """Fork a new disposable branch from the current sandbox state."""
        pass

    @abstractmethod
    async def checkpoint(self, tag: Optional[str] = None) -> str:
        """Create an immutable checkpoint image and return its UUID/tag."""
        pass

    @abstractmethod
    async def read_file(self, remote_path: str) -> bytes:
        """Read bytes directly from a file inside the sandbox."""
        pass

    @abstractmethod
    async def download_file(self, remote_path: str, local_path: Union[str, Path]) -> Path:
        """Download a file from the sandbox to the local filesystem."""
        pass

    @abstractmethod
    async def apply_files(self, files: Dict[str, Union[str, bytes, Path]]) -> None:
        """Upload or update files inside the sandbox."""
        pass
