# ShipCheck 🚢🛡️

> **Adversarial verification gate for AI-generated code.**
> Don't trust AI-generated code. Test it. ShipCheck proves a vulnerability is real inside an isolated sandbox, fixes it, proves the fix works, and hands a human a draft PR.

Built for the **Nebius x NVIDIA Global AI Hackathon** (Coding and Agentic Engineering Track).

> **Status (2026-10-28, `draft` branch):** the data contracts, every pipeline stage (triage, planning, probing, scoring, sandboxes, LLM client), the fix/re-verify engine (FR-6), the end-to-end orchestrator and the draft-PR bot (FR-7) are built and tested, and the `vulnshop` demo fixture is exploited live by the real probe harness. The dashboard/API and the golden-run replay are **not built yet**. See [Current status](#-current-status) before running anything.

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
| Triage | `triage/` | ✅ Built (gitleaks, pip-audit, osv-scanner, semgrep → SARIF → `Finding`, dedup). No tests yet |
| Attack planning | `planning/planner.py`, `planning/tavily_client.py` | ✅ Built. Uses the mock LLM and offline grounding when no keys are set. No tests yet |
| Probe harness | `probes/harness.py`, `probes/markers.py` | ✅ Built for 4 classes: SQLi, command injection, path traversal, reflected XSS. No tests yet |
| Risk scoring | `contracts/verdict.py`, `scoring/reachability.py` | ✅ Built (`compute_risk_score`, reachability heuristic) |
| Sandboxes | `sandbox/` | ✅ Built. ConTree backend + local fallback. 9 tests |
| LLM client | `llm/nemotron_client.py`, `llm/mock_llm.py`, `llm/json_extract.py` | ✅ Built (tiered models, retries, offline mock) |
| Prompts | `llm/prompts/*.md` | ✅ Drafted (planner, fixer, PoC generator, summarizer) |
| Fix engine (FR-6) | `rectify/fixer.py` | ✅ Built. Generates a fix from the exploit evidence, applies it, re-probes in a forked child sandbox (marker must be gone) and runs the repo tests (must pass) — the "No PASS, No PR" gate. 6 tests |
| End-to-end orchestrator | `orchestrator.py` | ✅ Built. `ShipCheckScanner.scan()` chains triage → plan → probe → verdict → rectify, probes fan out one forked sandbox per plan behind a semaphore, and (opt-in `open_prs=True`) opens a draft PR per verified fix. Returns a `ScanResult`. 7 tests |
| Demo fixture | `fixtures/vulnshop/` | ✅ Built. A Flask app with one real bug per class (SQLi, CMDi, traversal, XSS); the probe harness exploits it live (see the live test) |
| PR bot (FR-7) | `pr/github_bot.py` | ✅ Built. Opens a **draft** PR with an evidence body on a `shipcheck/fix-*` branch, only for a `VERIFIED_PASSED` fix, dedupes by head ref, never merges. 5 tests |
| **Golden-run replay** | `golden/` | ❌ Not built |
| **API + dashboard** | `shipcheck.api.main` | ❌ Not built |

**Vulnerability classes:** the contracts define 10 (`sqli`, `cmdi`, `traversal`, `xss`, `ssrf`, `ssti`, `idor`, `deserialization`, `secrets`, `deps`, plus `other`). The probe harness can currently execute **4** of them (SQLi, CMDi, traversal, XSS) — the same four `vulnshop` demonstrates. The other classes have templates in `CANONICAL_ATTACK_TEMPLATES` but no probe yet.

### Docker and CI (interim setup)

- **`Dockerfile`** builds the package and, by default, runs the test suite. When `shipcheck.api.main` exists, switch the `CMD` back to `uvicorn` (the line is commented in the file) and re-add `COPY` lines for `fixtures/` and `golden/` once those exist.
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

Expected: **53 passed, 3 skipped** (26 contract + 9 sandbox + 6 rectification + 7 orchestrator + 5 PR-bot tests; the 3 live tests skip unless opted in). Run it with the venv **activated**. Some sandbox tests shell out to a bare `python` command, and on macOS that only exists inside the venv.

### Run the live exploit demo

The deterministic suite uses stubs. To watch the real harness exploit the real `vulnshop` app:

```bash
pip install 'flask>=3.0,<4.0'
SHIPCHECK_LIVE=1 pytest tests/test_vulnshop_live.py -v
```

This starts `vulnshop` in a local sandbox and fires live XSS, command-injection and path-traversal exploits, asserting each marker appears in the real HTTP response.

### 3. Configure (optional)

Everything runs offline with mocks by default. To use real services:

```bash
cp .env.example .env
```

| Variable | Purpose | Default when unset |
| :--- | :--- | :--- |
| `NEBIUS_API_KEY`, `NEBIUS_PROJECT_ID` | Nemotron models + ConTree sandboxes | Mock LLM; local sandbox |
| `TAVILY_API_KEY` | Exploit research grounding | Offline fallback text |
| `GITHUB_TOKEN`, `GITHUB_REPOSITORY` | Fetch PR diffs / open draft PRs | — |
| `LLM_BACKEND` | `nemotron` or `mock` | `mock` |
| `SANDBOX_BACKEND` | `contree`, `docker` or `mock` | `mock` |
| `MAX_CONCURRENT_OPS` | Cap on parallel sandbox ops (Token Factory beta limit is 50) | `40` |

Notes on how the fallbacks behave:
- `docker` and `mock` both use the **local** backend (`LocalDockerBackend`, a temp-directory subprocess sandbox). Only `contree` uses Nebius microVMs, and it falls back to local if the key is missing or the backend fails to start.
- The planner uses the mock LLM whenever `LLM_BACKEND=mock` **or** `NEBIUS_API_KEY` is empty. In mock mode it returns a fixed set of 4 sample plans (one per probe class), whatever findings you pass in. If the LLM's JSON can't be parsed, the planner builds plans from `CANONICAL_ATTACK_TEMPLATES` instead.

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
│   └── orchestrator.py           # ShipCheckScanner.scan() — chains the whole pipeline
├── fixtures/vulnshop/            # intentionally vulnerable Flask demo app (4 classes)
├── tests/
│   ├── test_contracts.py         # 26 tests
│   ├── test_sandbox.py           # 9 tests
│   ├── test_rectify.py           # 6 tests (FR-6 fix loop)
│   ├── test_orchestrator.py      # 4 tests (end-to-end chaining)
│   ├── test_pr_bot.py            # 5 tests (FR-7 draft PR)
│   └── test_vulnshop_live.py     # 3 live exploit tests (opt-in: SHIPCHECK_LIVE=1)
├── docs/
│   ├── PRD.pdf, BUILD_PLAN.pdf   # product requirements + day-by-day plan
│   ├── contracts_design_decisions.md
│   └── ATTACK_PLAN_README.md     # original attack-plan branch README
├── ProjectExplain.md             # plain-language walkthrough of the whole system
├── CONTRACTS_DECISIONS.md        # architectural decision records
├── PRoject.txt                   # build notes
├── Dockerfile                    # builds the package; runs tests until the API exists
├── .github/workflows/tests.yml   # CI: contract + sandbox + rectify tests on 3.11 / 3.12
├── requirements.txt, pyproject.toml, .env.example
└── LICENSE
```

---

## 🧭 Next Steps

1. **API + dashboard (FR-8):** FastAPI app at `shipcheck.api.main` with `POST /scan` and the verdict/evidence views.
2. **Golden-run replay:** record a full scan's evidence under `golden/` so the demo never depends on a live model/sandbox; then point the `Dockerfile` at the API.
3. **Real end-to-end run:** wire the live Nemotron client + a real scanner so `ShipCheckScanner.scan()` runs against `vulnshop` with no stubs.
4. Tests for triage, planner and markers.

> **Done:** ✅ FR-6 fix engine, ✅ the scan orchestrator (now opens draft PRs for verified fixes when `open_prs=True`), ✅ the `vulnshop` demo fixture (exploited live by the real harness — XSS, CMDi and traversal markers all fire), and ✅ FR-7 draft-PR bot.

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
