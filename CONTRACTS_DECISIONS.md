# ShipCheck Contracts: Architectural Decisions & Attack Specifications

> **Module:** `src/shipcheck/contracts/`  
> **Role:** P2 Frozen Core Interfaces (Week 1 Milestone)  
> **Target Files:**
> - [`finding.py`](file:///c:/ShipCheck/src/shipcheck/contracts/finding.py) — Unified Triage & Pipeline Output `{probe, target, verdict, evidence}`
> - [`attack_plan.py`](file:///c:/ShipCheck/src/shipcheck/contracts/attack_plan.py) — Exploit Probe Specification `{vuln_class, target_file, sink, payload_strategy, expected_marker}`
> - [`evidence.py`](file:///c:/ShipCheck/src/shipcheck/contracts/evidence.py) — Sandbox Probe Evidence `{payload, request, response_status, response_excerpt, verdict, marker_found}`
> - [`fix.py`](file:///c:/ShipCheck/src/shipcheck/contracts/fix.py) — Structured Diff-Hunk JSON `{file, search, replace}`
> - [`verdict.py`](file:///c:/ShipCheck/src/shipcheck/contracts/verdict.py) — Per-Finding Card & Deterministic 0–100 Risk Score

---

## 1. Executive Summary & The "Freeze the Interfaces Early" Principle

In the ShipCheck development plan, the project is split across three engineers (`P1`, `P2`, `P3`). Week 1 prioritizes **freezing the shared data contracts**.

Without frozen contracts:
- `P1` (building triage scanners, Contree/Docker sandboxes, and probe execution harness) wouldn't know what payload structure to dispatch or what evidence format to emit.
- `P2` (building Nemotron Ultra planners, Nemotron Super fixers, and risk scoring) would risk outputting unstructured text that other modules cannot parse.
- `P3` (building FastAPI endpoints, the report generator, and the GitHub PR bot) wouldn't have stable JSON schemas for rendering cards and pull request bodies.

By defining strict, validated contracts with explicit JSON representations early, all three engineers can develop, mock, and test their components in parallel with zero blockers.

---

## 2. Important Architectural Decisions & Why They Were Chosen

### Decision 1: Pydantic V2 Over Raw Dictionaries or Standard Dataclasses
* **Decision:** All contracts are built using Pydantic V2 (`BaseModel`, `Field`, `field_validator`).
* **Why this was chosen:**
  1. **Strict Runtime Schema Validation:** LLMs (even Nemotron Ultra/Super) can occasionally return malformed types (e.g., string integers or slightly misspelled enum keys). Pydantic automatically validates, coerces, and rejects invalid structures.
  2. **JSON-in-Prompt & Tool Calling Compatibility:** Pydantic provides `.model_json_schema()`, which can be injected directly into system prompts for Nemotron Ultra and Nemotron Super to constrain their outputs to pure JSON mode.
  3. **Lossless Serialization:** Standard `.model_dump()` and `.model_dump_json()` methods guarantee 100% round-trip fidelity between API endpoints, disk artifacts (`reports/`), and child sandbox commands.
  4. **Robust Value Normalization:** Input aliases (e.g. `"sql-injection"` -> `VulnClass.SQLI`, `"path_traversal"` -> `VulnClass.TRAVERSAL`) are normalized automatically via field validators.

---

### Decision 2: Pure Deterministic Marker Verification (No LLM Exploit Judging)
* **Decision:** Exploitation confirmation is determined exclusively by deterministic substring and pattern checks (`marker_found: bool`) against the sandbox output. LLMs are never asked: *"Did this exploit succeed?"*
* **Why this was chosen:**
  1. **Elimination of Hallucinations:** As emphasized in `PRoject.txt`:  
     > *"No LLM decides this. LLMs hallucinate; a string match doesn't. A string match on `uid=` is a fact."*
  2. **Auditability:** Security engineers and PR reviewers require deterministic proof. A response containing `uid=0(root)` or `root:x:0:0:` is undeniable ground truth.
  3. **Speed & Zero Cost:** In-memory string matching runs in microseconds and consumes zero API tokens, saving Token Factory credits.

---

### Decision 3: Atomic Search-and-Replace Diff-Hunks (`{file, search, replace}`)
* **Decision:** `fix.py` enforces a diff-hunk model `{file, search, replace}` that mechanically validates search text uniqueness and applies surgical edits.
* **Why this was chosen:**
  1. **Guarding Against Unintended Code Mutations:** Allowing an LLM to rewrite entire files frequently leads to silent regressions, deleted comments, altered imports, or modified business logic outside the vulnerable function.
  2. **Strict Rejection on Absence (`REJECTED_SEARCH_NOT_FOUND`):** If the `search` block does not exist in the source file, the patch is rejected immediately rather than guessing line offsets.
  3. **Strict Rejection on Ambiguity (`REJECTED_AMBIGUOUS_MATCH`):** If `search` occurs multiple times (e.g., a generic `return True`), replacing only one or all of them might corrupt application logic. ShipCheck requires the model to provide enough surrounding context lines to make the match unique.

---

### Decision 4: Deterministic 0–100 Risk Score Formula
* **Decision:** Risk scoring in `verdict.py` is calculated via:
  $$\text{Score} = \text{SeverityBase} \times \text{ConfirmedFactor} \times \text{ReachabilityFactor} \times \text{ExposureFactor}$$
* **Why this was chosen:**
  1. **"Unconfirmed Findings Score Near Zero":** Static scanners (Semgrep, Gitleaks, etc.) generate numerous false positives or unexploitable suspects. When a probe fails to confirm the marker, `confirmed_factor = 0.05`. Even a "Critical" base (100) drops to $\le 5.0$, immediately shifting attention to verified vulnerabilities.
  2. **Four-Factor Modulation:**
     - **Severity Base:** Critical (100), High (80), Medium (50), Low (20), Info (5).
     - **Confirmed Factor:** Confirmed (1.0) vs. Unconfirmed (0.05).
     - **Reachability:** Direct (1.0), Conditional (0.7), Unknown (0.5), Unreachable (0.05).
     - **Exposure:** Public Internet (1.0), Authenticated (0.75), Internal (0.5), Local CLI (0.25).
  3. **Transparent Explanations:** Every calculated score includes an audit sentence explaining exactly how each factor modulated the final score.

---

### Decision 5: The "No PASS, No PR" Strict Rectification Gate
* **Decision:** In `fix.py` and `verdict.py`, a proposed patch cannot trigger a draft PR unless it passes the strict verification gate:
  1. **Re-Attack in Child Sandbox:** The exact exploit payload is dispatched against the patched code. The marker **must be absent** (`recheck_attack_marker_absent = True`).
  2. **Regression Test Pass:** The target repository's existing test suite must still pass (`repo_tests_passed = True`).
* **Why this was chosen:**
  - AI fix generators often "fix" vulnerabilities by simply returning an error, removing the route, or breaking legitimate functionality. Running both the exploit re-check and the unit tests prevents broken fixes from ever being submitted to developers.

---

### Decision 6: Token Budget Preservation & Excerpt Windowing
* **Decision:** `Evidence.capture()` automatically extracts a focused excerpt (default max 2048 characters) centered around the matched marker rather than dumping megabytes of application logs.
* **Why this was chosen:**
  - Database queries or path traversals can dump megabytes of text. Feeding raw megabyte outputs into the LLM fixer would exceed token limits, trigger HTTP 429 rate limits, and exhaust the $50 Token Factory budget on Day 1.

---

## 3. Explanations of Included Attacks

The contract suite natively models and includes canonical attack strategies, payload structures, sinks, and expected markers for the four primary vulnerability classes specified in `PRoject.txt` (plus static triage categories).

### 1. SQL Injection (`sqli`)
* **Vulnerable Pattern:** Direct string concatenation or f-string interpolation of untrusted input into SQL queries.
  ```python
  # Vulnerable
  db.execute(f"SELECT * FROM users WHERE name='{name}' AND pw='{pw}'")
  ```
* **Payload Strategy:** Boolean authentication bypass / tautology injection.
* **Default / Canonical Payload:** `' OR 1=1--`
* **Expected Marker:** `"admin"` or `"multiple rows"` (indicating authentication bypass or unauthorized record leakage).
* **Fix Pattern:** Parameterized queries with prepared statements.
  ```python
  # Fixed
  db.execute("SELECT * FROM users WHERE name=? AND pw=?", (name, pw))
  ```

---

### 2. OS Command Injection (`cmdi`)
* **Vulnerable Pattern:** Passing user-controlled strings directly to the shell interpreter via `os.system` or `subprocess(..., shell=True)`.
  ```python
  # Vulnerable
  os.system("ping -c 1 " + host)
  ```
* **Payload Strategy:** Shell command chaining using semicolon, pipe, or subshell expansion.
* **Default / Canonical Payload:** `8.8.8.8; id`
* **Expected Marker:** `uid=` (POSIX `id` command output demonstrating execution within the sandbox container).
* **Fix Pattern:** Disabling shell interpolation and passing arguments as an explicit array to `subprocess.run(..., shell=False)`.
  ```python
  # Fixed
  subprocess.run(["ping", "-c", "1", host], shell=False)
  ```

---

### 3. Path / Directory Traversal (`traversal`)
* **Vulnerable Pattern:** Combining user-supplied filenames using `os.path.join(BASE_DIR, filename)` without prefix or canonical validation.
  ```python
  # Vulnerable
  open(os.path.join(BASE_DIR, filename))
  ```
* **Payload Strategy:** Dot-dot-slash sequence escaping the intended directory root.
* **Default / Canonical Payload:** `../../etc/passwd`
* **Expected Marker:** `root:` (or `root:x:0:0:` verifying leakage of system configuration files).
* **Fix Pattern:** Resolving canonical path with `os.path.realpath` and enforcing that the resolved path starts with the base directory path plus path separator.
  ```python
  # Fixed
  p = os.path.realpath(os.path.join(BASE_DIR, filename))
  if not p.startswith(os.path.realpath(BASE_DIR) + os.sep):
      abort(400)
  ```

---

### 4. Reflected Cross-Site Scripting (`xss`)
* **Vulnerable Pattern:** Echoing untrusted user input directly into raw HTML responses without sanitization or HTML entity encoding.
  ```python
  # Vulnerable
  return f"<h1>Results for {q}</h1>"
  ```
* **Payload Strategy:** Unencoded script tag injection or HTML attribute breakout.
* **Default / Canonical Payload:** `<script>alert(1)</script>`
* **Expected Marker:** `<script>alert(1)</script>` (verbatim unencoded presence in the HTML body).
* **Fix Pattern:** HTML entity encoding with `html.escape()` or template engine autoescaping.
  ```python
  # Fixed
  return f"<h1>Results for {html.escape(q)}</h1>"
  ```

---

### 5. Server-Side Request Forgery (`ssrf`)
* **Vulnerable Pattern:** Directly fetching user-supplied target URLs via HTTP libraries (`requests.get`, `urllib.request`) without destination IP or scheme validation.
  ```python
  # Vulnerable
  resp = requests.get(request.args.get("url"))
  ```
* **Payload Strategy:** Targeting internal cloud metadata endpoints (`169.254.169.254`) or loopback services (`127.0.0.1`).
* **Default / Canonical Payload:** `http://169.254.169.254/latest/meta-data/`
* **Expected Marker:** `ami-id` or `instance-id` (proving exfiltration of cloud metadata).
* **Fix Pattern:** Strict scheme validation (http/https only) and DNS resolution checking to reject private, loopback, and link-local IP addresses.
  ```python
  # Fixed
  ip = ipaddress.ip_address(socket.gethostbyname(urlparse(url).hostname))
  if ip.is_private or ip.is_loopback or ip.is_link_local:
      abort(400)
  ```

---

### 6. Server-Side Template Injection (`ssti`)
* **Vulnerable Pattern:** Dynamic string concatenation into template engine definitions (`jinja2.Template(f"Hello {name}")`) instead of supplying data via template context.
  ```python
  # Vulnerable
  return jinja2.Template(f"Hello {name}").render()
  ```
* **Payload Strategy:** Mathematical expression evaluation canary (`{{7*7}}`) or sandbox escape payload.
* **Default / Canonical Payload:** `{{7*7}}`
* **Expected Marker:** `49` (verifying code execution inside the template engine).
* **Fix Pattern:** Passing user input safely as context variables into static template definitions.
  ```python
  # Fixed
  return jinja2.Template("Hello {{ name }}").render(name=name)
  ```

---

### 7. Insecure Direct Object Reference / BOLA (`idor`)
* **Vulnerable Pattern:** Querying database records directly by a client-provided ID without validating session ownership or tenant permissions.
  ```python
  # Vulnerable
  order = Order.query.filter_by(id=order_id).first()
  ```
* **Payload Strategy:** Horizontal parameter tampering with a foreign tenant / user identifier.
* **Default / Canonical Payload:** `102`
* **Expected Marker:** `owner_id: 102` (verifying leakage of foreign user records).
* **Fix Pattern:** Enforcing object-level tenant scoping directly in the database query.
  ```python
  # Fixed
  order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
  ```

---

### 8. Insecure Deserialization (`deserialization`)
* **Vulnerable Pattern:** Passing untrusted byte streams or serialized strings to unsafe native deserializers (`pickle.loads`, `yaml.unsafe_load`).
  ```python
  # Vulnerable
  obj = pickle.loads(base64.b64decode(user_payload))
  ```
* **Payload Strategy:** Object reduction gadget chain triggering arbitrary system command execution.
* **Default / Canonical Payload:** `cos\nsystem\n(S'id'\ntR.`
* **Expected Marker:** `uid=` (POSIX id command execution during object unpickling).
* **Fix Pattern:** Migrating from unsafe binary serialization to safe structured formats (`json.loads`) with cryptographic signature verification.
  ```python
  # Fixed
  data = signer.unsign(token)
  obj = json.loads(data)
  ```

---

### Static Triage Classes (Included for Completeness)
* **Hardcoded Secrets (`secrets`):** Scanned by Gitleaks (e.g. AWS access keys, private keys, API tokens).
* **Vulnerable Dependencies (`deps`):** Scanned by pip-audit and osv-scanner against published CVE advisories.

---

## 4. Contract Schema Reference

### `attack_plan.py`
```json
{
  "plan_id": "plan-a1b2c3d4",
  "vuln_class": "sqli",
  "target_file": "app.py",
  "sink": "login()",
  "payload_strategy": "boolean bypass",
  "expected_marker": "admin",
  "route": "/login",
  "http_method": "POST",
  "parameter_name": "username",
  "suggested_payload": "' OR 1=1--"
}
```

### `evidence.py`
```json
{
  "evidence_id": "ev-e5f6g7h8",
  "payload": "' OR 1=1--",
  "request": "POST /login HTTP/1.1\r\nHost: localhost:5000\r\n\r\nusername=' OR 1=1--",
  "response_status": 200,
  "response_excerpt": "Welcome admin! User ID: 1, Role: administrator",
  "verdict": "CONFIRMED",
  "marker_found": true,
  "target_marker": "admin"
}
```

### `fix.py`
```json
{
  "file": "app.py",
  "search": "db.execute(f\"SELECT * FROM users WHERE name='{name}' AND pw='{pw}'\")",
  "replace": "db.execute(\"SELECT * FROM users WHERE name=? AND pw=?\", (name, pw))"
}
```

### `verdict.py`
```json
{
  "finding_id": "find-sqli-001",
  "status": "CONFIRMED",
  "score": 80.0,
  "score_breakdown": {
    "severity": "HIGH",
    "severity_base_score": 80.0,
    "confirmed_factor": 1.0,
    "reachability": "DIRECT",
    "reachability_factor": 1.0,
    "exposure": "PUBLIC",
    "exposure_factor": 1.0,
    "final_score": 80.0,
    "explanation": "HIGH base score (80) modulated by: confirmed by live sandbox exploit (1.0x), direct reachability (1.0x), and public exposure (1.0x) -> Final Score: 80.0/100."
  },
  "summary": "CONFIRMED vulnerability (80.0/100): Marker 'admin' verified in sandbox response.",
  "marker_verified": true,
  "gate_verdict": "NO_PASS"
}
```

### `finding.py`
```json
{
  "finding_id": "find-sqli-001",
  "vuln_class": "sqli",
  "title": "Unsanitized user input in SQL query",
  "target": {
    "file": "app.py",
    "line": 42,
    "sink": "db.execute()",
    "endpoint": "/login",
    "code_snippet": "db.execute(f\"SELECT * FROM users WHERE name='{name}' AND pw='{pw}'\")"
  },
  "probe": { ... AttackPlan ... },
  "evidence": { ... Evidence ... },
  "verdict": { ... VerdictCard ... },
  "fix": { ... FixPatch ... }
}
```

---

## 5. Automated Verification Results

All 5 contracts and their validation, serialization, search-and-replace mechanics, and mathematical score calculations are verified through unit tests in [`tests/test_contracts.py`](file:///c:/ShipCheck/tests/test_contracts.py):

* `test_attack_plan_fields_and_shape`: Passed
* `test_vuln_class_normalization`: Passed
* `test_canonical_attack_templates_exist`: Passed
* `test_evidence_fields_and_shape`: Passed
* `test_evidence_deterministic_capture_confirmed`: Passed
* `test_evidence_deterministic_capture_unconfirmed`: Passed
* `test_diff_hunk_apply_success`: Passed
* `test_diff_hunk_search_not_found_rejection`: Passed
* `test_diff_hunk_ambiguous_match_rejection`: Passed
* `test_fix_verification_gate`: Passed
* `test_unconfirmed_findings_score_near_zero`: Passed
* `test_verdict_card_from_probe`: Passed
* `test_unified_finding_lifecycle`: Passed

**Test Suite Execution:** 13 passed in 0.70s.
