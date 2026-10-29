"""Record the golden demo run: one real end-to-end scan of fixtures/vulnshop.

Runs real triage (semgrep, gitleaks, osv-scanner, pip-audit), Nemotron Ultra
attack planning, live probes, Tavily grounding and Nemotron Super fixes with the
"No PASS, No PR" gate, then writes the redacted ScanResult that GET /api/demo
replays. Needs NEBIUS_API_KEY (+ TAVILY_API_KEY) and the scanners on PATH.

    python scripts/record_golden.py                    # scan + write golden/
    python scripts/record_golden.py --backend docker   # same, inside probe-image containers
    python scripts/record_golden.py --from result.json # just redact + write
    python scripts/record_golden.py --pr <finding_id or vuln class> --pr-url URL --pr-number N
"""

import argparse
import asyncio
import json
import logging
import shlex
import socket
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from shipcheck.golden import GOLDEN_PATH, redact_local_details  # noqa: E402

APP_DIR = "fixtures/vulnshop"


async def scan(backend: str = "mock") -> str:
    from shipcheck.orchestrator import ShipCheckScanner
    from shipcheck.probes.harness import ProbeHarness
    from shipcheck.rectify.fixer import RectificationEngine
    from shipcheck.sandbox.client import SandboxClient

    sandbox = SandboxClient(backend_type=backend).create_sandbox()
    src = REPO / APP_DIR
    files = {
        f"{APP_DIR}/{p.relative_to(src)}": p.read_text()
        for p in src.rglob("*")
        if p.is_file() and not {"__pycache__", ".pytest_cache"} & set(p.parts)
    }
    await sandbox.apply_files(files)

    if backend == "docker":
        # Each sandbox is its own container: own loopback, own Python.
        port, py, concurrency = 5000, "python", 4
    else:
        # Local sandboxes share the host's network and ports: one at a time.
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        py, concurrency = shlex.quote(sys.executable), 1
    harness = ProbeHarness(port=port)
    scanner = ShipCheckScanner(
        harness=harness,
        rectifier=RectificationEngine(harness=harness),
        max_concurrent=concurrency,
    )
    app_py = files[f"{APP_DIR}/app.py"]
    diff = (
        f"diff --git a/{APP_DIR}/app.py b/{APP_DIR}/app.py\nnew file mode 100644\n"
        f"--- /dev/null\n+++ b/{APP_DIR}/app.py\n"
        + "".join("+" + line + "\n" for line in app_py.splitlines())
    )
    t = time.monotonic()
    result = await scanner.scan(
        sandbox, diff, commit_sha="vulnshop-golden",
        app_cmd=f"PORT={port} {py} app.py",
        target_dir=f"{sandbox.default_workdir}/{APP_DIR}",
        test_cmd=f"cd {APP_DIR} && {py} -m pytest -q test_app.py",
    )
    print(f"[{backend}] scan took {time.monotonic() - t:.1f}s: {result.findings_count} findings, "
          f"{result.confirmed_count} confirmed, {result.fixed_count} fixed")
    for f in sorted(result.findings, key=lambda f: -f.score):
        print(f"  {f.vuln_class.value:9} {f.target.file}:{f.target.line} {f.target.endpoint or '-':10} "
              f"score={f.score:5} fix={f.fix.status.value if f.fix else '-'}")
    sandbox.cleanup()
    return result.model_dump_json()


def attach_pr(data: dict, which: str, url: str, number: int) -> None:
    """Record a real draft PR (opened separately) against one finding."""
    finding = next(
        (f for f in data["findings"] if f["finding_id"] == which or f["vuln_class"] == which), None
    )
    if finding is None:
        raise SystemExit(f"no finding matches {which!r}")
    data["pull_requests"] = [p for p in data.get("pull_requests", []) if p["finding_id"] != finding["finding_id"]]
    data["pull_requests"].append({"finding_id": finding["finding_id"], "number": number, "url": url})


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="src", type=Path, help="existing ScanResult JSON to redact instead of scanning")
    ap.add_argument("--out", type=Path, default=GOLDEN_PATH)
    ap.add_argument("--backend", default="mock", choices=["mock", "docker", "contree"],
                    help="sandbox backend (docker = probe-image containers)")
    ap.add_argument("--pr", help="finding_id or vuln class the PR fixes")
    ap.add_argument("--pr-url")
    ap.add_argument("--pr-number", type=int)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    for noisy in ("httpx", "httpx2", "openai", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    raw = args.src.read_text() if args.src else asyncio.run(scan(args.backend))
    data = json.loads(redact_local_details(raw))
    if args.pr:
        attach_pr(data, args.pr, args.pr_url, args.pr_number)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(data, indent=2) + "\n")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
