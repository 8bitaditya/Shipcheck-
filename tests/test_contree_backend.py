"""ContreeBackend against a fake ConTree image (no network).

The fake mirrors contree-sdk's real semantics: images are immutable,
apply_files() returns a NEW image, and a str file source is a LOCAL PATH.
"""

from pathlib import Path

import pytest

pytest.importorskip("contree_sdk")

from shipcheck.sandbox.contree_backend import ContreeBackend  # noqa: E402


class FakeResult:
    def __init__(self, stdout="", exit_code=0):
        self.stdout, self.stderr, self.exit_code, self.uuid = stdout, "", exit_code, None


class FakeImage:
    def __init__(self, files=None):
        self.files = dict(files or {})
        self.runs = []

    async def apply_files(self, files):
        new = dict(self.files)
        for dest, src in files.items():
            assert not isinstance(src, str), "str sources are local paths to the SDK"
            new[dest] = src.read_bytes() if isinstance(src, Path) else src
        return FakeImage(new)

    async def run(self, **kwargs):
        self.runs.append(kwargs)
        return FakeResult(stdout="ok")

    async def read(self, path):
        return self.files[path]


def _backend(img):
    b = ContreeBackend(image_ref="test-image")
    b._image = img
    return b


async def test_apply_files_keeps_the_new_image_and_encodes_text():
    base = FakeImage()
    sb = _backend(base)
    await sb.apply_files({"app.py": "print('hi')\n", "/etc/x.conf": b"raw"})

    assert sb._image is not base  # moved to the image with the files
    assert await sb.read_file("app.py") == b"print('hi')\n"
    assert await sb.read_file("/workspace/app.py") == b"print('hi')\n"
    assert await sb.read_file("/etc/x.conf") == b"raw"


async def test_fork_sees_parent_files_and_child_changes_stay_in_child():
    sb = _backend(FakeImage())
    await sb.apply_files({"app.py": "v1"})
    child = await sb.fork()
    await child.apply_files({"app.py": "v2"})
    assert await child.read_file("app.py") == b"v2"
    assert await sb.read_file("app.py") == b"v1"


async def test_run_defaults_to_workspace_and_resolves_relative_cwd():
    img = FakeImage()
    sb = _backend(img)
    await sb.run(shell="ls")
    await sb.run(shell="ls", cwd="sub")
    assert img.runs[0]["cwd"] == "/workspace"
    assert img.runs[1]["cwd"] == "/workspace/sub"
    assert sb.default_workdir == "/workspace"
