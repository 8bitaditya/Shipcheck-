# Golden run

`vulnshop_scan.json` is a recorded **real** ShipCheck scan of `fixtures/vulnshop`. `GET /api/demo` replays it, so the dashboard demo never depends on a live model, sandbox or network call. The response header `X-ShipCheck-Demo-Source: golden` says the recording was served. If this file is missing or invalid, the API falls back to a hand-built sample and sends `sample` instead.

## How it was recorded

- **Date:** 2026-10-29
- **Command:** `python scripts/record_golden.py --backend docker` (one scan, then redaction)
- **Triage:** real scanners — semgrep 1.182.1 (`p/owasp-top-ten` plus ShipCheck's path-traversal rule), gitleaks 8.30.1, osv-scanner 2.7.0, pip-audit 2.10.1
- **Planning:** `nvidia/Nemotron-3-Ultra-550b-a55b`; all 4 plans came from the model, none from templates
- **Fixes:** `nvidia/nemotron-3-super-120b-a12b`
- **Grounding:** live Tavily search
- **Sandbox:** the **Docker** backend: every sandbox and fork is an isolated `linux/amd64` container of the probe image (`sandbox/image/Dockerfile.probe`), the same image ConTree is meant to run. Not ConTree itself: Sandboxes access is still pending.

## Result

5 findings: 4 confirmed (SQLi, command injection, path traversal, reflected XSS on `/search`) and 4 fixed. Every fix passed the "No PASS, No PR" gate: the re-attack no longer finds the marker and vulnshop's tests pass.

The fifth finding is an XSS on `/export`, where ping's error output is echoed unescaped. Ultra wrote no plan for it, so it stays unconfirmed with a score of 2.0.

The SQLi fix was opened as a real draft PR: [8bitaditya/Shipcheck-#1](https://github.com/8bitaditya/Shipcheck-/pull/1).

The probe image used for this recording had no `ping`, so `/export` printed `ping: not found` before the injected `id` ran. The exploit is unaffected. `iputils-ping` has since been added to `Dockerfile.probe`.

## Redactions

The command-injection probe runs `id`. Inside the container that is `root`, which is left as is; only the group list is replaced with `groups=<redacted>`. On the local backend the recorder also replaces the real username, home directory and temp paths. Nothing else was edited: payloads, markers, scores, fixes and the Tavily sources are as recorded. `scripts/record_golden.py --from <result.json>` applies the same redaction to any saved run.
