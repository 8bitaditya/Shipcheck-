"""Configuration module for ShipCheck."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from root of project if present
BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

# --- Nebius & Token Factory Credentials ---
NEBIUS_API_KEY: str = os.getenv("NEBIUS_API_KEY", "")
NEBIUS_PROJECT_ID: str = os.getenv("NEBIUS_PROJECT_ID", "")

# Base URLs (OpenAI-compatible)
TOKEN_FACTORY_BASE_URL: str = os.getenv(
    "TOKEN_FACTORY_BASE_URL", "https://api.tokenfactory.nebius.com/v1/"
)
TOKEN_FACTORY_FALLBACK_URL: str = (
    "https://api.tokenfactory.us-central1.nebius.com/v1/"
)

# ConTree Sandboxes endpoint
CONTREE_BASE_URL: str = os.getenv(
    "CONTREE_BASE_URL", "https://api.tokenfactory.nebius.com/sandboxes"
)

# Pre-baked probe container image UUID (checkpointed once)
SHIPCHECK_PROBE_IMAGE_UUID: str = os.getenv(
    "SHIPCHECK_PROBE_IMAGE_UUID", "shipcheck-probe-base:latest"
)

# --- NVIDIA Nemotron 3 Model IDs (Case-sensitive - PRD Section 6) ---
NEMOTRON_ULTRA_MODEL_ID: str = os.getenv(
    "NEMOTRON_ULTRA_MODEL_ID", "nvidia/Nemotron-3-Ultra-550b-a55b"
)
NEMOTRON_SUPER_MODEL_ID: str = os.getenv(
    "NEMOTRON_SUPER_MODEL_ID", "nvidia/nemotron-3-super-120b-a12b"
)
NEMOTRON_NANO_MODEL_ID: str = os.getenv(
    "NEMOTRON_NANO_MODEL_ID", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
)
NEMOTRON_LIGHTNING_MODEL_ID: str = os.getenv(
    "NEMOTRON_LIGHTNING_MODEL_ID", "nvidia/Nemotron-3_5-Lightning"
)

# --- Tavily Grounding ---
TAVILY_API_KEY: str = os.getenv("TAVILY_API_KEY", "")

# --- GitHub Integration ---
GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPOSITORY: str = os.getenv("GITHUB_REPOSITORY", "")

# --- Runtime & Semaphore Limits ---
# Token Factory Beta limit is 50 concurrent operations; ShipCheck caps at 40
MAX_CONCURRENT_OPS: int = int(os.getenv("MAX_CONCURRENT_OPS", "40"))
PROBE_TIMEOUT_SECONDS: int = int(os.getenv("PROBE_TIMEOUT_SECONDS", "45"))
OVERALL_SCAN_BUDGET_OPS: int = int(os.getenv("OVERALL_SCAN_BUDGET_OPS", "50"))

# Backend selectors: 'contree', 'docker', 'mock'
SANDBOX_BACKEND: str = os.getenv("SANDBOX_BACKEND", "mock").lower()

# 'docker' backend: one container per sandbox from the probe image
# (build: docker build --platform linux/amd64 -t shipcheck-probe:latest -f
#  src/shipcheck/sandbox/image/Dockerfile.probe src/shipcheck/sandbox/image)
SHIPCHECK_DOCKER_IMAGE: str = os.getenv("SHIPCHECK_DOCKER_IMAGE", "shipcheck-probe:latest")
SHIPCHECK_DOCKER_PLATFORM: str = os.getenv("SHIPCHECK_DOCKER_PLATFORM", "")
LLM_BACKEND: str = os.getenv("LLM_BACKEND", "mock").lower()
