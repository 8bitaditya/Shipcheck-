# ShipCheck 🚢🛡️

> **Adversarial verification gate for AI-generated code.**
> *"Don’t trust AI-generated code — attack it. ShipCheck proves vulnerabilities with working exploits in isolated sandboxes, fixes them, proves the fix, and hands you the PR."*

Built for the **Nebius x NVIDIA Global AI Hackathon** (Coding and Agentic Engineering Track).

---

## 🎯 The Core Thesis

Published studies reveal that AI coding assistants generate code with vulnerability rates between **25% and 45%**. Furthermore, AI-generated pull requests often carry synthetic tests designed to make CI turn green without validating genuine security boundaries.

**ShipCheck** operates an offensive-as-a-service verification and rectification loop:
1. **Ingests** a pull request diff or repository URL.
2. **Triages** via fast static analyzers (`gitleaks`, `pip-audit`, `osv-scanner`, `semgrep`).
3. **Plans Attacks** with NVIDIA **Nemotron-3-Ultra** (leveraging its 1M context window) grounded by **Tavily** exploit writeups.
4. **Executes Parallel Probes** inside disposable **Nebius Token Factory Sandboxes** (`contree-sdk`) against 4 deterministic vulnerability classes.
5. **Proves Exploits** using objective boolean markers (never LLM guesswork).
6. **Rectifies & Re-verifies**: NVIDIA **Nemotron-3-Super** synthesizes diff-hunk JSON patches, re-runs the exploit in a child sandbox branch (proving the exploit is closed), verifies existing test suites remain green, and opens a draft GitHub PR for a human.

**ShipCheck never auto-merges — a human reviewer makes the final call.**

---

## 🏗️ Architecture & Component Map

```
┌────────────────────────────────────────┐
│  Dashboard + API (FastAPI Stateless)   │  <-- Nebius Serverless Endpoint
│  POST /scan  -->  Live Stream / Verdict │
└───────────────────┬────────────────────┘
                    │
      ┌─────────────┼──────────────┐
      ▼             ▼              ▼
┌───────────┐ ┌───────────┐ ┌─────────────┐
│ Nemotron  │ │  Sandbox  │ │   Tavily    │
│  Client   │ │  Client   │ │  Grounding  │
└─────┬─────┘ └─────┬─────┘ └──────┬──────┘
      │             │              │
      │   asyncio.gather (sem=40)  │
      ▼             ▼              ▼
┌────────────────────────────────────────┐
│   Parallel MicroVM Disposable Probes   │  <-- Contree Sandboxes (localhost only)
│  SQLi | CMDi | Traversal | Reflected XSS│
└───────────────────┬────────────────────┘
                    │ (Confirmed Marker Fired)
                    ▼
┌────────────────────────────────────────┐
│  Rectification: Patch + Child Re-probe │  <-- Re-run probe (fails) + Tests pass
└───────────────────┬────────────────────┘
                    ▼
┌────────────────────────────────────────┐
│  Draft GitHub PR (Never Auto-Merged)   │  <-- Least-privilege PAT with evidence
└────────────────────────────────────────┘
```

---

## 🤖 Model Tier Mapping (NVIDIA Nemotron 3)

| Tier | Model ID | Context | Role in ShipCheck |
| :--- | :--- | :--- | :--- |
| **Ultra** | `nvidia/Nemotron-3-Ultra-550b-a55b` | 1M | Attack planning over full PR diff + triage findings; complex patch synthesis. |
| **Super** | `nvidia/nemotron-3-super-120b-a12b` | 256K | Orchestrator/supervisor; PoC script generation; patch review & validation. |
| **Nano** | `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | 262K | Log compaction, pass/fail parsing, evidence summarization, Tavily query formulation. |
| **Lightning** | `nvidia/Nemotron-3_5-Lightning` | 1M | High-throughput JSON extraction and parsing loops. |

---

## 🛠️ Sandbox & Infrastructure Stack

- **Nebius Token Factory Sandboxes (`contree-sdk==0.3.6`)**: Isolated Firecracker microVMs for deterministic exploit execution.
- **Localhost Isolation**: App and probe attack harness run within the same microVM network namespace, eliminating egress dependencies.
- **Tavily Search API**: Grounds every finding with real CVE IDs, affected library versions, and canonical security advisories.
- **Nebius Serverless Endpoint**: Hosts the public FastAPI + Dashboard container.
- **Golden Run Replay Engine**: Guarantees instant, reliable evaluation for hackathon judges without cloud API downtime.

---

## 🚀 Quickstart

### 1. Installation
```bash
git clone https://github.com/your-org/shipcheck.git
cd shipcheck
python -m venv .venv
source .venv/bin/activate  # Or on Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### 2. Environment Setup
```bash
cp .env.example .env
# Edit .env with your NEBIUS_API_KEY, NEBIUS_PROJECT_ID, and TAVILY_API_KEY
```

### 3. Run Offline Smoke Tests & Mock Pipeline
```bash
# Marker verification
pytest tests/test_markers.py -v

# E2E scan on the included fixture
python scripts/run_scan.py --target fixtures/vulnshop
```

### 4. Start Dashboard
```bash
uvicorn shipcheck.api.main:app --reload --port 8000
```
Open [http://localhost:8000](http://localhost:8000) in your browser.

---

## 📄 License

Licensed under the [Apache-2.0 License](LICENSE).
