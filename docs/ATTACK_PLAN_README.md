# ShipCheck 🛡️⚡

> **Autonomous security testing engine that proves vulnerabilities before alerting developers.**  
> *Ingests PR diffs → Triages static suspects → Generates attack plans → Probes in disposable sandboxes → Deterministically verifies exploits → Synthesizes surgical fixes → Opens draft pull requests.*

---

## 📌 Overview

Traditional static application security testing (SAST) tools generate overwhelming false positives. Developers ignore dozens of vague warnings and merge vulnerabilities anyway.

**ShipCheck** solves this by asking one question:
> **"Can this code actually be exploited with a real payload right now?"**

- **If YES:** ShipCheck extracts deterministic proof (raw payload, output excerpt, matched marker), generates a surgical patch (`{file, search, replace}`), verifies the fix inside a clean sandbox, and opens a draft pull request with complete evidence.
- **If NO:** It suppresses false alarms so engineering velocity is never interrupted.
- **Human in the Loop:** A human always reviews and merges. ShipCheck never automatically merges code into production.

---

## 🔄 End-to-End Pipeline

```
GitHub PR Diff 
      │
      ▼
1. Triage (Fast static scanners: Semgrep, Gitleaks, pip-audit)
      │
      ▼
2. Plan (Nemotron Ultra model generates structured attack plans)
      │
      ▼
3. Probe (Executes exploit in isolated container / throwaway sandbox)
      │
      ▼
4. Verdict (Deterministic marker matching + 0–100 risk scoring)
      │
      ▼
5. Rectify (Nemotron Super outputs surgical search-and-replace patches)
      │
      ▼
6. Verify & Draft PR (Re-runs attack probe; opens PR only if exploit is dead)
```

---

## 🚀 What Has Been Done (P2 Core Contracts Milestone)

In this phase, we completed the **core contracts architecture** (`src/shipcheck/contracts/`), establishing the frozen interfaces that unify the triage scanners, LLM planners, sandbox probe harness, fixer engine, and reporting bot:

### 1. Unified Finding Contract ([`finding.py`](file:///c:/ShipCheck/src/shipcheck/contracts/finding.py))
- Standardized data representation for suspects flowing from triage scanners through the probe execution and verdict stages.
- Supported vulnerability taxonomy: `SQLI`, `CMDI`, `TRAVERSAL`, `SSRF`, `SSTI`, `XSS`, `IDOR`, `SECRETS`, `INSECURE_DESERIALIZATION`, `AUTH_BYPASS`, and `OTHER`.
- Normalizes scanner inputs from Semgrep, Gitleaks, and dependency audits.

### 2. Attack Plan Contract ([`attack_plan.py`](file:///c:/ShipCheck/src/shipcheck/contracts/attack_plan.py))
- Structured instructions emitted by LLM planners (Nemotron Ultra) for the probe execution harness.
- Specifies payload strategy, target file/sink, execution protocol (`HTTP`, `CLI_STDIN`, `CLI_ARG`, `FUNCTION_CALL`), expected deterministic marker (e.g. `uid=`, `root:`, `ami-id`), and strict timeout / resource constraints.
- Includes pre-built templates and validation for major vulnerability classes.

### 3. Probe Evidence Contract ([`evidence.py`](file:///c:/ShipCheck/src/shipcheck/contracts/evidence.py))
- Records immutable, concrete evidence from sandbox execution: payload sent, status code, raw execution output, and execution logs.
- **Deterministic Exploit Verification:** Pure string and regex checks (`marker_found: bool`) determine confirmation—**no LLM hallucination is permitted in exploit confirmation**.

### 4. Surgical Fix Contract ([`fix.py`](file:///c:/ShipCheck/src/shipcheck/contracts/fix.py))
- Enforces atomic search-and-replace diff-hunks: `{file, search, replace}`.
- Rejects full-file rewrites to prevent silent regressions and hallucinations.
- Validates that `search` strings exist and are uniquely matched within the source file before applying.

### 5. Verdict & Risk Scoring ([`verdict.py`](file:///c:/ShipCheck/src/shipcheck/contracts/verdict.py))
- Implements the deterministic **0–100 risk scoring algorithm**:
  $$\text{Score} = \text{SeverityBase} \times \text{ConfirmedFactor} \times \text{ReachabilityFactor} \times \text{ExposureFactor}$$
- Heavily discounts unconfirmed scanner alerts (0.05× multiplier) so real, verified exploits float to the top of developer reports.
- Generates markdown card summaries for GitHub PR comments.

### 6. Full Test Suite & Documentation
- **26 comprehensive unit tests** in [`tests/test_contracts.py`](file:///c:/ShipCheck/tests/test_contracts.py) covering schema validation, serialization round-tripping, patch application, and edge cases.
- In-depth architectural decisions document in [`CONTRACTS_DECISIONS.md`](file:///c:/ShipCheck/CONTRACTS_DECISIONS.md) and [`docs/contracts_design_decisions.md`](file:///c:/ShipCheck/docs/contracts_design_decisions.md).

---

## 📁 Repository Structure

```
ShipCheck/
├── docs/
│   └── contracts_design_decisions.md # Detailed P2 design specifications
├── src/
│   └── shipcheck/
│       ├── __init__.py
│       └── contracts/               # Core frozen interfaces (Pydantic V2)
│           ├── __init__.py          # Clean module exports
│           ├── attack_plan.py       # Probe attack specifications
│           ├── evidence.py          # Sandbox execution evidence
│           ├── finding.py           # Unified finding model & enums
│           ├── fix.py               # Surgical diff-hunk patch contracts
│           └── verdict.py           # Risk scoring & finding verdicts
├── tests/
│   └── test_contracts.py            # Complete test suite (26 passing tests)
├── .gitignore                       # Git exclusions
├── CONTRACTS_DECISIONS.md           # Architectural decision records
├── ProjectExplain.md                # Complete project & pipeline walkthrough
├── pyproject.toml                   # Project configuration & dependencies
└── README.md                        # Project documentation
```

---

## 🛠️ Getting Started

### Prerequisites
- Python 3.10+
- `pip` or `poetry` / `hatchling`

### Installation
Clone the repository and install the development dependencies:

```bash
git clone -b attack-plan https://github.com/8bitaditya/Shipcheck-.git
cd Shipcheck-
pip install -e .
pip install pytest pydantic
```

### Running Tests
Execute the contract test suite:

```bash
pytest
```

Expected output:
```text
tests/test_contracts.py .......................... [100%]
26 passed
```

---

## 🛡️ Key Guarantees

1. **Deterministic Verification:** LLMs plan the attacks and craft the fixes; deterministic string assertions judge whether the attack worked.
2. **Surgical Fixes:** Fixes must match existing source code context uniquely before being applied.
3. **Double Verification:** Any proposed fix is deployed back into a disposable sandbox, attacked with the exact same exploit payload, and regression tested before a PR is opened.
4. **Human Authority:** A human engineer always makes the final merge decision.
