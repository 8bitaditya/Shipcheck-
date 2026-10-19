"""Token Factory Sandboxes backend via official contree-sdk (PRD Section 6 Gotchas #2, #3)."""

import logging
import time
from pathlib import Path
from typing import Dict, Optional, Union

try:
    from contree_sdk import Contree
    from contree_sdk.config import ContreeConfig, IAMAuth
    from contree_sdk.sdk.objects.image._async import ContreeImage
except ImportError:
    Contree = None
    ContreeConfig = None
    IAMAuth = None
    ContreeImage = None

from shipcheck.sandbox.base import SandboxBase, SandboxResult
from shipcheck import config

logger = logging.getLogger(__name__)


class ContreeBackend(SandboxBase):
    """Sandbox implementation running on Nebius Token Factory microVMs."""

    def __init__(
        self,
        image_ref: Optional[Union[str, "ContreeImage"]] = None,
        client: Optional["Contree"] = None,
    ):
        if Contree is None:
            raise ImportError(
                "contree-sdk is not installed. Run 'pip install contree-sdk==0.3.6'."
            )

        if client:
            self.client = client
        else:
            # PRD Gotcha #2: IAM auth needs NEBIUS_PROJECT_ID explicitly set
            try:
                auth = IAMAuth(
                    base_url=config.CONTREE_BASE_URL,
                    token=config.NEBIUS_API_KEY,
                    project_id=config.NEBIUS_PROJECT_ID or "NEBIUS_PROJECT_ID",
                )
                sdk_cfg = ContreeConfig(auth=auth)
                self.client = Contree(config=sdk_cfg)
            except Exception as err:
                logger.warning(
                    "ContreeConfig with IAMAuth initialization failed (%s); falling back to direct Contree init.",
                    err,
                )
                self.client = Contree(
                    base_url=config.CONTREE_BASE_URL,
                    token=config.NEBIUS_API_KEY,
                )

        self._image_ref = image_ref or config.SHIPCHECK_PROBE_IMAGE_UUID
        if isinstance(image_ref, ContreeImage):
            self._image: Optional[ContreeImage] = image_ref
        else:
            self._image: Optional[ContreeImage] = None

    async def _get_image(self) -> ContreeImage:
        """Resolve the image asynchronously (contree-sdk images.use is an async coroutine)."""
        if self._image is None:
            ref = self._image_ref or config.SHIPCHECK_PROBE_IMAGE_UUID
            if isinstance(ref, str):
                self._image = await self.client.images.use(ref)
            else:
                self._image = ref
        return self._image

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
        """Run a command in the microVM.

        Process memory is not preserved across runs, so chained shell scripts are used
        (PRD Gotcha #3).
        """
        img = await self._get_image()
        start_time = time.monotonic()
        logger.info("Executing in Contree sandbox (disposable=%s): %s", disposable, shell or command)

        result_img: ContreeImage = await img.run(
            command=command,
            shell=shell,
            env=env,
            cwd=cwd,
            timeout=timeout,
            disposable=disposable,
            files=files,
        )

        duration = time.monotonic() - start_time
        stdout = result_img.stdout or ""
        stderr = result_img.stderr or ""
        exit_code = result_img.exit_code if result_img.exit_code is not None else -1

        # If non-disposable checkpoint requested, advance our image pointer to branch
        checkpoint_id = None
        if not disposable and hasattr(result_img, "uuid") and result_img.uuid:
            self._image = result_img
            checkpoint_id = str(result_img.uuid)

        return SandboxResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            checkpoint_id=checkpoint_id,
        )

    async def fork(self) -> "ContreeBackend":
        """Fork from the current image reference into a separate branch."""
        img = await self._get_image()
        return ContreeBackend(image_ref=img, client=self.client)

    async def checkpoint(self, tag: Optional[str] = None) -> str:
        """Tag current state as an immutable checkpoint."""
        img = await self._get_image()
        if tag:
            await img.tag_as(tag)
        return str(getattr(img, "uuid", tag or "unknown"))

    async def read_file(self, remote_path: str) -> bytes:
        """Read artifact bytes from sandbox."""
        img = await self._get_image()
        return await img.read(remote_path)

    async def download_file(self, remote_path: str, local_path: Union[str, Path]) -> Path:
        """Download artifact from sandbox to local filesystem."""
        img = await self._get_image()
        target = Path(local_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        return await img.download(remote_path, target)

    async def apply_files(self, files: Dict[str, Union[str, bytes, Path]]) -> None:
        """Upload or update files inside the sandbox image."""
        img = await self._get_image()
        await img.apply_files(files)
