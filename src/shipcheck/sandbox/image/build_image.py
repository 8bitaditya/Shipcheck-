"""Script to build, tag, and register the shipcheck-probe base image in Contree."""

import argparse
import asyncio
import os
import subprocess
import sys
from pathlib import Path

IMAGE_TAG = "shipcheck-probe:latest"
DOCKERFILE_PATH = Path(__file__).parent / "Dockerfile.probe"


def build_local_image(tag: str = IMAGE_TAG):
    """Build the probe image locally using docker if available."""
    print(f"Building {tag} from {DOCKERFILE_PATH}...")
    cmd = [
        "docker", "build",
        "-t", tag,
        "-f", str(DOCKERFILE_PATH),
        str(DOCKERFILE_PATH.parent)
    ]
    try:
        subprocess.run(cmd, check=True)
        print(f"Successfully built {tag}")
    except FileNotFoundError:
        print("Docker not found locally. If using Nebius Token Factory directly, import via Contree SDK.")
    except subprocess.CalledProcessError as err:
        print(f"Build failed with exit code {err.returncode}")
        sys.exit(err.returncode)


async def register_with_contree(image_ref: str, tag: str = "shipcheck-probe:latest"):
    """Register/import the image into Nebius Token Factory Sandboxes via contree-sdk."""
    print(f"Importing {image_ref} into Contree as tag '{tag}'...")
    try:
        from contree_sdk import Contree
        from contree_sdk.config import ContreeConfig, IAMAuth
        from shipcheck import config

        auth = IAMAuth(
            base_url=config.CONTREE_BASE_URL,
            token=config.NEBIUS_API_KEY,
            project_id=config.NEBIUS_PROJECT_ID,
        )
        client = Contree(config=ContreeConfig(auth=auth))
        img = await client.images.import_from(image_ref, tag=tag)
        print(f"Successfully imported image into Contree. UUID: {getattr(img, 'uuid', 'unknown')}")
    except ImportError:
        print("contree-sdk not installed. Install with 'pip install contree-sdk==0.3.6'")
    except Exception as exc:
        print(f"Failed to import image into Contree: {exc}")


def main():
    parser = argparse.ArgumentParser(description="Build and register ShipCheck probe image")
    parser.add_argument("--tag", default=IMAGE_TAG, help="Local Docker tag")
    parser.add_argument("--register-contree", metavar="OCI_REF", help="Import remote OCI image into Contree")
    args = parser.parse_args()

    if args.register_contree:
        asyncio.run(register_with_contree(args.register_contree, tag=args.tag))
    else:
        build_local_image(tag=args.tag)


if __name__ == "__main__":
    main()
