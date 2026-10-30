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
    from shipcheck.demo import run_vulnshop_scan

    result, seconds = await run_vulnshop_scan(backend, commit_sha="vulnshop-golden")
    print(f"[{backend}] scan took {seconds:.1f}s: {result.findings_count} findings, "
          f"{result.confirmed_count} confirmed, {result.fixed_count} fixed")
    for f in sorted(result.findings, key=lambda f: -f.score):
        print(f"  {f.vuln_class.value:9} {f.target.file}:{f.target.line} {f.target.endpoint or '-':10} "
              f"score={f.score:5} fix={f.fix.status.value if f.fix else '-'}")
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
