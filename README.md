# ShipCheck 🚢🛡️

> **Adversarial verification gate for AI-generated code.**
> Don't trust AI-generated code. Test it. ShipCheck proves a vulnerability is real inside an isolated sandbox, fixes it, proves the fix works, and hands a human a draft PR.

Built for the **Nebius x NVIDIA Global AI Hackathon** (Coding and Agentic Engineering Track).

> **Status (2026-10-28, `draft` branch):** every functional requirement FR-1…FR-8 is built and tested — contracts, triage, planning, probing, scoring, the fix/re-verify engine (FR-6), the end-to-end orchestrator, the draft-PR bot (FR-7) and the FastAPI dashboard/API (FR-8) — and the `vulnshop` demo fixture is exploited live by the real probe harness. The golden-run replay and a real-services end-to-end run are **not built yet**. See [Current status](#-current-status) before running anything.

---

## 📌 The Problem

Static analysis tools produce a lot of false positives. A developer sees dozens of vague warnings, ignores them, and merges anyway. Published studies put the vulnerability rate of AI-generated code at 25–45%, and AI-written PRs often come with tests that turn CI green without checking any security boundary.

ShipCheck answers one question:

> **"Can this change actually be exploited, right now, with a real request?"**

- **If yes:** it records deterministic proof (the request sent, a response excerpt, the matched marker), generates a surgical `{file, search, replace}` patch, re-runs the same attack against the patched code in a clean sandbox, and opens a **draft** PR with the evidence.
- **If no:** it suppresses the alert so developers aren't interrupted.
- **A human always merges.** ShipCheck never auto-merges.

---

## 🔄 How the Pipeline Works

```
GitHub PR diff
      │
      ▼
1. Ingest   – fetch the PR diff, copy changed files into a disposable sandbox
      │
      ▼
2. Triage   – fast static scanners: gitleaks → pip-audit / osv-scanner → semgrep
      │         (SARIF normalized into Finding objects, deduplicated, scoped to the diff)
      ▼
3. Plan     – Nemotron Ultra turns findings + diff into an AttackPlanBatch,
      │         grounded by Tavily research (falls back to canonical templates)
      ▼
4. Probe    – start the target app and send the request in the SAME sandbox run
      │         (localhost only, no egress), capture the raw response
      ▼
5. Verdict  – deterministic marker check (string/regex, never an LLM)
      │         + 0–100 risk score
      ▼
6. Rectify  – Nemotron Super writes a search/replace patch, the probe is re-run
      │         (must now fail), and the repo's tests must still pass
      ▼
7. Draft PR – opened with a least-privilege token, for a human to review
```

**Key rule:** LLMs *plan* attacks and *write* fixes. They never decide whether an attack worked. That is a boolean marker check in code, so the verdict can't be hallucinated.

### Architecture

```
┌────────────────────────────────────────┐
│  Dashboard + API (FastAPI, stateless)  │  ← planned: Nebius Serverless endpoint
└───────────────────┬────────────────────┘
      ┌─────────────┼──────────────┐
      ▼             ▼              ▼
┌───────────┐ ┌───────────┐ ┌─────────────┐
│ Nemotron  │ │  Sandbox  │ │   Tavily    │
│  Client   │ │  Client   │ │  Grounding  │
└─────┬─────┘ └─────┬─────┘ └──────┬──────┘
      └─────────────┼──────────────┘
                    ▼   asyncio, capped at 40 concurrent ops
┌────────────────────────────────────────┐
│   Parallel disposable probe sandboxes  │  ← ConTree microVMs (or local fallback)
└───────────────────┬────────────────────┘
                    ▼  marker confirmed
┌────────────────────────────────────────┐
│  Rectification: patch + child re-probe │
└───────────────────┬────────────────────┘
                    ▼
┌────────────────────────────────────────┐
│  Draft GitHub PR (never auto-merged)   │
└────────────────────────────────────────┘
```

---

## ✅ Current Status

What is in the `draft` branch today, and what still needs building.

| Stage | Module | Status |
| :--- | :--- | :--- |
| Data contracts | `contracts/` | ✅ Built. 26 unit tests |
| Diff ingest | `ingest/diff.py`, `ingest/github_ingest.py` | ✅ Built (diff parser, PR diff fetch, repo clone). No tests yet |
| Triage | `triage/` | ✅ Built and run for real on `vulnshop`: gitleaks, pip-audit (`-r requirements.txt`), osv-scanner and semgrep (`p/owasp-top-ten` + a ShipCheck path-traversal taint rule) → SARIF → `Finding`. Reports come back on stdout from the same sandbox run; overlapping rules on nearby lines are merged into one finding. 7 tests |
| Attack planning | `planning/planner.py`, `planning/tavily_client.py` | ✅ Built. Nemotron Ultra returns canonical `AttackPlanBatch` JSON; each plan is validated on its own, gaps are filled from the matching finding, and any finding the model skipped gets a template plan. Uses the mock LLM and offline grounding when no keys are set. 5 tests |
| Probe harness | `probes/harness.py`, `probes/markers.py` | ✅ Built for 4 classes: SQLi, command injection, path traversal, reflected XSS. Payloads are shell-quoted and URL-encoded, so quoted SQLi like `' OR 1=1--` is delivered intact (14 tests in `test_probe_harness.py`) |
| Risk scoring | `contracts/verdict.py`, `scoring/reachability.py` | ✅ Built (`compute_risk_score`, reachability heuristic) |
| Advisory grounding (FR-5) | `planning/tavily_client.py`, `contracts/grounding.py` | ✅ Built. Every confirmed finding gets Tavily-grounded CVE/GHSA/CWE IDs, affected versions (dependency findings) and the canonical fix, shown on the dashboard and in the PR body. Without a key it uses a built-in CWE/OWASP reference and labels it as offline. 6 tests |
| Sandboxes | `sandbox/` | ✅ Built. Three backends: **docker** (one container per sandbox from the probe image; `fork()` = `docker commit` snapshot), local temp-dir, and **ConTree**. The golden run was recorded on docker. ConTree: uploads, paths and image tracking fixed and tested against a fake image, but **not run live** — Sandboxes is in beta and this key's `/v1/whoami` shows every permission `false` until Nebius grants access. 9 + 3 + 4 (opt-in Docker) tests |
| LLM client | `llm/nemotron_client.py`, `llm/mock_llm.py`, `llm/json_extract.py` | ✅ Built (tiered models, retries, offline mock) |
| Prompts | `llm/prompts/*.md` | ✅ Drafted (planner, fixer, PoC generator, summarizer) |
| Fix engine (FR-6) | `rectify/fixer.py` | ✅ Built. Generates a fix from the exploit evidence, applies it, re-probes in a forked child sandbox (marker must be gone) and runs the repo tests (must pass) — the "No PASS, No PR" gate. If a patch doesn't apply, Super is asked again (up to 2 more times), told why and shown the closest real text. 14 tests |
| End-to-end orchestrator | `orchestrator.py` | ✅ Built. `ShipCheckScanner.scan()` chains triage → plan → probe → verdict → ground → rectify, probes fan out one forked sandbox per plan behind a semaphore, and (opt-in `open_prs=True`) opens a draft PR per verified fix. Returns a `ScanResult`. 10 tests |
| Demo fixture | `fixtures/vulnshop/` | ✅ Built. A Flask app with one real bug per class (SQLi, CMDi, traversal, XSS); the probe harness exploits it live (see the live test) |
| PR bot (FR-7) | `pr/github_bot.py` | ✅ Built and used for real ([8bitaditya/Shipcheck-#1](https://github.com/8bitaditya/Shipcheck-/pull/1)). Opens a **draft** PR with an evidence body on a `shipcheck/fix-*` branch, only for a `VERIFIED_PASSED` fix, never merges. A re-scan refreshes the same PR: one fast-forward commit making the branch equal base + the newest fix, skipped if a human has pushed to the branch. 7 tests |
| Golden-run replay | `golden/`, `golden.py`, `scripts/record_golden.py` | ✅ Built. A recorded real scan of `vulnshop` in probe-image containers (4 of 4 confirmed and fixed, real triage, Ultra plans, Super fixes, live Tavily), redacted, replayed by `GET /api/demo` (header `X-ShipCheck-Demo-Source: golden`). See [golden/README.md](golden/README.md) |
| API + dashboard (FR-8) | `api/main.py`, `api/dashboard.py` | ✅ Built. FastAPI app: `POST /scan`, `GET /api/demo`, `GET /health`, and a lean single-page dashboard (risk-ranked verdicts, evidence timeline, fix diff, gate state, PR link). 6 tests |

**Vulnerability classes:** the contracts define 10 (`sqli`, `cmdi`, `traversal`, `xss`, `ssrf`, `ssti`, `idor`, `deserialization`, `secrets`, `deps`, plus `other`). The probe harness can currently execute **4** of them (SQLi, CMDi, traversal, XSS) — the same four `vulnshop` demonstrates. The other classes have templates in `CANONICAL_ATTACK_TEMPLATES` but no probe yet.

### Docker and CI (interim setup)

- **`Dockerfile`** builds the package and serves the dashboard/API with `uvicorn` on port 8000 (`docker run -p 8000:8000 shipcheck`). The image includes `golden/`, so the demo works with no keys or network.
- **`.github/workflows/tests.yml`** runs the contract, sandbox, rectification, orchestrator and PR-bot test files on Python 3.11 and 3.12 (the opt-in live tests are not run in CI). It only triggers on pushes and PRs to `main`, so it won't run on `draft` until `draft` is merged or a PR into `main` is opened. Add new test files to the workflow as they're written.

---

## 🚀 Quickstart (what works today)

Requires **Python 3.11+** and `git`. Docker is **not** needed for local development: the default sandbox runs commands in a temporary directory on your machine.

### 1. Install

```bash
git clone -b draft https://github.com/8bitaditya/Shipcheck-.git
cd Shipcheck-
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### 2. Run the test suite

```bash
python -m pytest
```

Expected: **123 passed, 10 skipped** (26 contract + 9 sandbox + 3 ConTree-backend + 22 probe-harness + 7 triage + 7 planner + 6 grounding + 19 rectification + 11 orchestrator + 7 PR-bot + 6 API tests; the 6 live vulnshop tests and 4 Docker tests skip unless opted in). Run it with the venv **activated**. Some sandbox tests shell out to a bare `python` command, and on macOS that only exists inside the venv.

### Run the dashboard

```bash
uvicorn shipcheck.api.main:app --port 8000
```

Open [http://localhost:8000](http://localhost:8000) and click **Load demo** to replay the recorded real scan of `vulnshop` from `golden/` — the risk-ranked verdict, the evidence timeline (exploit lands → fix → attack fails), the fix diff, the "No PASS, No PR" gate and the draft-PR link. Or build the container: `docker build -t shipcheck . && docker run -p 8000:8000 shipcheck`.

### Run the live exploit demo

The deterministic suite uses stubs. To watch the real harness exploit the real `vulnshop` app:

```bash
pip install 'flask>=3.0,<4.0'
SHIPCHECK_LIVE=1 pytest tests/test_vulnshop_live.py -v
```

This starts `vulnshop` in a local sandbox and fires live SQLi (`' OR 1=1--` login bypass), XSS, command-injection and path-traversal exploits, asserting each marker appears in the real HTTP response.

It also runs the real fix loop: a correct SQLi patch is applied in a forked sandbox, re-attacked and regression-tested with `vulnshop`'s own tests, and must reach `VERIFIED_PASSED`; a no-op patch must fail the gate.

### 3. Configure (optional)

Everything runs offline with mocks by default. To use real services:

```bash
cp .env.example .env
```

| Variable | Purpose | Default when unset |
| :--- | :--- | :--- |
| `NEBIUS_API_KEY`, `NEBIUS_PROJECT_ID` | Nemotron models + ConTree sandboxes | Mock LLM; local sandbox |
| `TAVILY_API_KEY` | Exploit research for the planner + CVE/advisory grounding of confirmed findings | Offline fallback text / built-in CWE/OWASP reference (labelled offline) |
| `GITHUB_TOKEN`, `GITHUB_REPOSITORY` | Fetch PR diffs / open draft PRs | — |
| `LLM_BACKEND` | `nemotron` or `mock` | `mock` |
| `SANDBOX_BACKEND` | `contree`, `docker` or `mock` | `mock` |
| `MAX_CONCURRENT_OPS` | Cap on parallel sandbox ops (Token Factory beta limit is 50) | `40` |

Notes on how the fallbacks behave:
- `docker` and `mock` both use the **local** backend (`LocalDockerBackend`, a temp-directory subprocess sandbox). Only `contree` uses Nebius microVMs, and it falls back to local if the key is missing or the backend fails to start.
- The planner uses the mock LLM whenever `LLM_BACKEND=mock` **or** `NEBIUS_API_KEY` is empty. In mock mode it returns a fixed set of 4 sample plans (one per probe class), whatever findings you pass in. If the LLM's JSON can't be parsed, the planner builds plans from `CANONICAL_ATTACK_TEMPLATES` instead.

**Scanners for real triage on the local backend.** On ConTree they come from the probe image. Locally, install them yourself (without them, triage simply finds nothing):

```bash
pip install semgrep pip-audit
brew install gitleaks osv-scanner
```

**Docker sandboxes (closest to ConTree today).** Build the probe image once (≈1.6 GB, `linux/amd64`; slow under emulation on Apple Silicon), then select the backend:

```bash
docker build --platform linux/amd64 -t shipcheck-probe:latest -f src/shipcheck/sandbox/image/Dockerfile.probe src/shipcheck/sandbox/image
SANDBOX_BACKEND=docker uvicorn shipcheck.api.main:app --port 8000
SHIPCHECK_DOCKER=1 pytest tests/test_docker_backend.py -v
```

**Re-record the golden run** after changing the pipeline (needs the keys; `--backend docker` needs the probe image, the default local backend needs the scanners above):

```bash
python scripts/record_golden.py --backend docker
```

### 4. Use the stages from Python

There's no CLI or API yet, so for now you call the stages directly:

```python
import asyncio
from shipcheck.contracts import (
    Finding, FindingTarget, VulnClass, SeverityLevel,
    ReachabilityLevel, ExposureLevel, compute_risk_score,
)
from shipcheck.planning.planner import AttackPlanner

finding = Finding(
    vuln_class=VulnClass.SQLI,
    title="User input concatenated into SQL query",
    target=FindingTarget(file="app.py", line=42, endpoint="/login"),
    tool="semgrep",
    rule_id="python.sqli",
)

# Offline: uses the mock LLM + offline Tavily grounding
batch = asyncio.run(AttackPlanner().plan_attacks("<diff text>", [finding]))
for plan in batch.plans:
    print(plan.vuln_class.value, plan.route, plan.expected_marker)

# Deterministic 0–100 risk score
score = compute_risk_score(
    severity=SeverityLevel.HIGH,
    is_confirmed=True,
    reachability=ReachabilityLevel.DIRECT,
    exposure=ExposureLevel.PUBLIC,
)
print(score.final_score, score.explanation)
```

---

## 🧱 Core Contracts

The contracts in `src/shipcheck/contracts/` (Pydantic v2) are the **frozen interfaces** every stage uses, so team members can build independently. Design rationale: [`CONTRACTS_DECISIONS.md`](CONTRACTS_DECISIONS.md) and [`docs/contracts_design_decisions.md`](docs/contracts_design_decisions.md).

| Contract | File | What it holds |
| :--- | :--- | :--- |
| `Finding`, `FindingTarget` | `finding.py` | One suspect, carried through every stage: `{target, probe, evidence, verdict, fix}` + scanner metadata. `fingerprint()` for dedup |
| `AttackPlan`, `AttackPlanBatch` | `attack_plan.py` | One probe: `{vuln_class, target_file, sink, payload_strategy, expected_marker}` + route/method/parameter. `VulnClass` (with alias normalization) and `CANONICAL_ATTACK_TEMPLATES` |
| `Evidence`, `ProbeVerdict` | `evidence.py` | Captured sandbox result: request, status, response excerpt, `marker_found`. `Evidence.capture()` decides the verdict by string match only |
| `DiffHunk`, `FixPatch`, `FixStatus` | `fix.py` | Surgical `{file, search, replace}` hunks. `search` must match exactly once, and full-file rewrites are rejected |
| `VerdictCard`, `compute_risk_score` | `verdict.py` | Deterministic score and gate decision |

### Risk score

```
score = severity_base × confirmed_factor × reachability_factor × exposure_factor
```

| Factor | Values |
| :--- | :--- |
| Severity base | CRITICAL 100 · HIGH 80 · MEDIUM 50 · LOW 20 · INFO 5 |
| Confirmed | 1.0 if the sandbox probe confirmed it · **0.05 if unconfirmed** |
| Reachability | DIRECT 1.0 · CONDITIONAL 0.7 · UNKNOWN 0.5 · UNREACHABLE 0.05 |
| Exposure | PUBLIC 1.0 · AUTHENTICATED 0.75 · INTERNAL 0.5 · LOCAL 0.25 |

A confirmed critical finding on a public, directly reachable endpoint scores 100. An unconfirmed scanner alert scores near 0, so proven issues rise to the top.

---

## 🔎 Where Tavily Is Used

Tavily is called in two places, both in `planning/tavily_client.py` (`POST https://api.tavily.com/search`, `include_answer=True`, key sent as a Bearer header):

1. **Attack planning:** `AttackPlanner` asks Tavily for current exploit write-ups for the detected vulnerability class and puts the answer and sources into the Nemotron Ultra planning prompt.
2. **Advisory grounding (FR-5):** after the verdict, `ShipCheckScanner.scan()` grounds every **confirmed** finding in parallel with `ground_finding()`. The result (`AdvisoryGrounding`) holds:
   - CVE / GHSA / CWE IDs pulled from the Tavily answer and results,
   - affected version ranges (only for dependency findings; for first-party code the CVEs Tavily returns are related advisories, not this bug),
   - the canonical fix (Tavily's answer),
   - the cited source links (only plain `http(s)` URLs are kept).

   It is shown on the dashboard card and as section 2 of the draft-PR body. Tavily titles and text are treated as untrusted and escaped there.

If `TAVILY_API_KEY` is unset or Tavily errors, the finding gets a built-in CWE/OWASP reference instead, with `provider: "static"` and a note saying why. The report and PR body label it as offline, never as a Tavily result. A grounding failure never stops the scan. Queries are currently built deterministically from the CWE, class and sink; Nano-written queries are not wired yet. The `/api/demo` sample shows the offline reference.

---

## 🤖 Model Tiers (NVIDIA Nemotron 3)

| Tier | Model ID | Context | Role |
| :--- | :--- | :--- | :--- |
| **Ultra** | `nvidia/Nemotron-3-Ultra-550b-a55b` | 1M | Attack planning over the full diff + findings; hard patches |
| **Super** | `nvidia/nemotron-3-super-120b-a12b` | 256K | Orchestration, PoC generation, patch review |
| **Nano** | `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | 262K | Log compaction, pass/fail parsing, summaries, Tavily queries |
| **Lightning** | `nvidia/Nemotron-3_5-Lightning` | 1M | High-throughput JSON extraction |

Ultra is reserved for planning and hard fixes. Super and Nano handle everyday calls to stay within the credit budget.

---

## 📁 Repository Structure

```
Shipcheck-/
├── src/shipcheck/
│   ├── config.py                 # env-driven settings + backend selectors
│   ├── contracts/                # frozen Pydantic interfaces (see above)
│   ├── ingest/                   # unified-diff parser, GitHub PR fetch/clone
│   ├── triage/                   # gitleaks, deps, semgrep, SARIF parser, runner
│   ├── planning/                 # AttackPlanner (Nemotron Ultra) + Tavily client
│   ├── probes/                   # probe harness, deterministic markers, per-class probes
│   ├── scoring/                  # reachability heuristic
│   ├── rectify/                  # FR-6 fix engine: generate → apply → re-verify
│   ├── pr/                       # FR-7 PR bot: body renderer + draft-PR GitHub client
│   ├── sandbox/                  # SandboxClient, ConTree + local backends, probe image
│   ├── llm/                      # Nemotron client, mock LLM, JSON extraction, prompts/
│   ├── api/                      # FR-8 FastAPI app (main.py) + dashboard (dashboard.py)
│   └── orchestrator.py           # ShipCheckScanner.scan() — chains the whole pipeline
├── fixtures/vulnshop/            # intentionally vulnerable Flask demo app (4 classes)
├── tests/
│   ├── test_contracts.py         # 26 tests
│   ├── test_sandbox.py           # 9 tests
│   ├── test_probe_harness.py     # 22 tests (payload quoting, workdir, traversal depth)
│   ├── test_planner.py           # 5 tests (Ultra plan parsing)
│   ├── test_grounding.py         # 6 tests (FR-5 Tavily grounding)
│   ├── test_rectify.py           # 14 tests (FR-6 fix loop)
│   ├── test_orchestrator.py      # 10 tests (end-to-end chaining)
│   ├── test_pr_bot.py            # 5 tests (FR-7 draft PR)
│   ├── test_api.py               # 6 tests (FR-8 dashboard/API, golden replay)
│   └── test_vulnshop_live.py     # 6 live tests: 4 exploits + real fix loop (opt-in: SHIPCHECK_LIVE=1)
├── docs/
│   ├── PRD.pdf, BUILD_PLAN.pdf   # product requirements + day-by-day plan
│   ├── contracts_design_decisions.md
│   └── ATTACK_PLAN_README.md     # original attack-plan branch README
├── ProjectExplain.md             # plain-language walkthrough of the whole system
├── CONTRACTS_DECISIONS.md        # architectural decision records
├── PRoject.txt                   # build notes
├── Dockerfile                    # serves the dashboard/API (uvicorn on :8000)
├── .github/workflows/tests.yml   # CI: all deterministic test files on 3.11 / 3.12
├── requirements.txt, pyproject.toml, .env.example
└── LICENSE
```

---

## 🧭 Next Steps

All eight functional requirements are built. What remains is hardening and the demo:

1. **Run on ConTree:** blocked on access. Sandboxes is in beta; request access at [tokenfactory.nebius.com/sandboxes/about](https://tokenfactory.nebius.com/sandboxes/about) (or contree@nebius.com). Until then `GET /v1/whoami` lists every permission as `false`. Once granted: import the probe image, set `SHIPCHECK_PROBE_IMAGE_UUID` and `SANDBOX_BACKEND=contree`, then `python scripts/record_golden.py --backend contree`.
2. **Deploy** the dashboard/API to a Nebius Serverless Endpoint and warm it before judging.
3. Tests for the probe markers; Semgrep-taint reachability; the Nano tier.

The real end-to-end run is done on the local sandbox. Real triage finds the bugs itself, Ultra plans all 4, every fix passes the gate, and the SQLi fix was opened as a real draft PR ([8bitaditya/Shipcheck-#1](https://github.com/8bitaditya/Shipcheck-/pull/1)). That run is recorded as the golden run.

> **Done:** ✅ FR-6 fix engine · ✅ scan orchestrator (opens draft PRs when `open_prs=True`) · ✅ `vulnshop` fixture (exploited live — SQLi, XSS, CMDi, traversal) · ✅ FR-5 Tavily advisory grounding · ✅ FR-7 draft-PR bot · ✅ FR-8 dashboard/API · ✅ golden-run replay.

---

## 🛡️ Guarantees

1. **Deterministic verification:** LLMs plan and fix; code decides whether an attack worked.
2. **Surgical fixes:** a patch only applies if its `search` text matches the source exactly once.
3. **Double verification:** every fix is re-attacked with the same probe and regression-tested before a PR is opened.
4. **Isolation:** probes run against the app on localhost inside a disposable sandbox, never against real systems.
5. **Human authority:** a person always makes the merge decision.

---

## 👥 Team

| Branch | Contributor | Contribution |
| :--- | :--- | :--- |
| `UI/Ai` | Aditya Dhavale | Pipeline implementation: sandboxes, triage, planner, probes, LLM client, Docker/CI setup |
| `attack-plan` | Prem PawanKumar Dubay | Frozen core contracts, attack templates, design decisions, project explainer |
| `draft` | Parth | Integration of both branches onto the canonical contracts; AI/model work |

---

## 📄 License

Apache-2.0. See [LICENSE](LICENSE).
