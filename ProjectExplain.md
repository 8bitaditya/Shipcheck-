# ShipCheck — What This Project Does

## The One-Liner

ShipCheck is an **autonomous security testing engine** that takes a GitHub pull request, attacks the changed code inside a throwaway sandbox, proves whether vulnerabilities are real, generates a fix, proves the fix works, and opens a draft PR for a human to review.

No human writes the exploit. No human writes the patch. But a human always merges.

---

## The Problem It Solves

AI-generated code is flooding pull requests. GitHub Copilot, ChatGPT, and similar tools write code fast — but they also write **SQL injection, command injection, path traversal, XSS, SSRF, SSTI, and IDOR bugs** fast. Traditional static analysis tools (like Semgrep) can flag suspicious patterns, but they produce mountains of false positives. A developer sees 47 warnings, ignores all of them, and merges anyway.

ShipCheck fixes this by answering one question definitively:

> **"Can I actually exploit this code, right now, with a real payload?"**

If yes → here's the proof, here's the fix, here's proof the fix works.  
If no → stop wasting the developer's time.

---

## How It Works (The Pipeline)

ShipCheck runs a 6-stage pipeline on every PR diff:

```
PR Diff → Triage → Plan → Probe → Verdict → Rectify → Draft PR
```

### Stage 1: Ingest
The changed files from a GitHub PR are copied into a **disposable sandbox** — an isolated container (or microVM) that already has Python, Node.js, Semgrep, gitleaks, and other scanning tools pre-installed. Nothing runs on your real machine.

### Stage 2: Triage
Cheap, fast static analysis scanners run first:
- **Semgrep** — pattern-matches code for known dangerous constructs (e.g., "user input flows into a SQL string")
- **gitleaks** — detects hardcoded secrets, API keys, and tokens
- **pip-audit / osv-scanner** — checks dependencies against known CVE databases

These scanners produce **suspects** — things that *look* dangerous but might not actually be exploitable.

### Stage 3: Plan
The suspects and the PR diff are sent to a large language model (Nemotron Ultra). The model reads the code and produces a structured **attack plan** for each suspect:

```json
{
  "vuln_class": "sqli",
  "target_file": "app.py",
  "sink": "login()",
  "payload_strategy": "boolean bypass",
  "expected_marker": "admin"
}
```

This plan says: *"The login route concatenates user input into a SQL query. Send `' OR 1=1--` as the username. If the word `admin` appears in the response, the exploit worked."*

The LLM **plans** the attack. It does **not** judge whether the attack succeeded — that's the next stage's job.

### Stage 4: Probe
For each attack plan, ShipCheck forks the sandbox into an independent branch, starts the target application, sends the exploit payload, and captures the raw response. This all happens inside the sandbox — no real systems are touched.

The critical decision is made by a **deterministic string match**, not by an LLM:

```python
marker_found = "uid=" in raw_output   # True or False. No hallucination possible.
```

If the expected marker (`uid=`, `root:`, `admin`, `<script>alert(1)</script>`, `ami-id`, `49`, `owner_id:`) appears in the output, the vulnerability is **CONFIRMED**. If it doesn't appear, it's **UNCONFIRMED**.

> *"No LLM decides this. LLMs hallucinate; a string match doesn't."*

### Stage 5: Verdict
Each finding gets a deterministic **0–100 risk score** calculated by:

```
Score = Severity × Confirmed × Reachability × Exposure
```

- A **confirmed** Critical finding on a public endpoint scores **100/100**
- An **unconfirmed** Critical finding scores only **5/100** (0.05× dampener)

This means scanner false positives automatically sink to the bottom of the report, while proven exploits rise to the top.

### Stage 6: Rectify
For each confirmed finding:

1. The fixer model receives the **exploit evidence** — not just the code, but the actual payload and what it leaked. This makes the bug obvious even to the model.
2. It outputs a structured patch as `{file, search, replace}` — a surgical search-and-replace, not a full file rewrite. If the `search` text doesn't exist in the file, the patch is **rejected** (prevents hallucinated fixes).
3. The patched code is deployed to a **child sandbox branch**, and the **exact same attack** is re-run. The marker must be gone.
4. The repository's own test suite runs. Tests must still pass.
5. **Both pass?** → Push a branch, open a draft PR with the proof-of-concept, root cause analysis, diff, and re-verification results.  
   **Either fails?** → Report "fix failed verification" honestly. No PR.
6. **A human always merges.** ShipCheck never calls the merge endpoint.

---

## The Vulnerability Classes & Attack Vectors

ShipCheck targets eight of the most critical and pervasive vulnerabilities in modern web applications, APIs, and cloud services. Each vulnerability class is paired with a concrete attack strategy, a disposable sandbox probe, and an objective deterministic marker.

---

### 1. SQL Injection (SQLi)
- **CWE:** CWE-89
- **Mechanism:** User-controlled input is directly concatenated into a dynamic SQL query string instead of being passed through parameterized database drivers. An attacker injects SQL syntax to alter the query logic and bypass authentication or dump tables.
- **Why Probing Matters:** Linters flag string formatting even when input is an internal integer, but miss complex multi-tier sanitization bugs. Running the probe proves whether authentication bypass actually happens.

```python
# Vulnerable: user input concatenated into SQL
db.execute(f"SELECT * FROM users WHERE name='{name}' AND pw='{pw}'")

# Attack payload: ' OR 1=1--
# Expected marker: "admin" (returns all users including admin)

# Fixed: parameterized query
db.execute("SELECT * FROM users WHERE name=? AND pw=?", (name, pw))
```

---

### 2. OS Command Injection (CMDi)
- **CWE:** CWE-78
- **Mechanism:** User input flows into system shell invocation functions (`os.system`, `subprocess.Popen(..., shell=True)`). Attackers use shell metacharacters (`;`, `&`, `|`, `` ` ``) to execute arbitrary commands under the application's process context.
- **Why Probing Matters:** Proving command execution requires observing output from the injected command (`uid=0(root)`), confirming shell execution without false positives.

```python
# Vulnerable: user input passed to shell
os.system("ping -c 1 " + host)

# Attack payload: 8.8.8.8; id
# Expected marker: "uid=" (proves arbitrary command execution)

# Fixed: no shell, argument list
subprocess.run(["ping", "-c", "1", host], shell=False)
```

---

### 3. Path Traversal (Directory Traversal / LFI)
- **CWE:** CWE-22
- **Mechanism:** User-supplied filename or file path parameters are joined to a base directory without canonical path resolution and boundary checks. Attackers use dot-dot-slash (`../`) sequences to escape the web root and read sensitive system or application files.
- **Why Probing Matters:** Path resolution behavior depends on OS filesystem semantics; the sandbox probe verifies whether the file actually leaks.

```python
# Vulnerable: user-supplied filename without validation
open(os.path.join(BASE_DIR, filename))

# Attack payload: ../../etc/passwd
# Expected marker: "root:" (proves filesystem escape)

# Fixed: resolve canonical path, enforce prefix
p = os.path.realpath(os.path.join(BASE_DIR, filename))
if not p.startswith(os.path.realpath(BASE_DIR) + os.sep):
    abort(400)
```

---

### 4. Reflected Cross-Site Scripting (XSS)
- **CWE:** CWE-79
- **Mechanism:** User input received in an HTTP request is included in an immediate web response without contextual HTML entity encoding. When rendered in a browser, attacker-supplied scripts execute within the victim's session context.
- **Why Probing Matters:** The probe checks whether the raw `<script>` tag is returned unencoded in the HTTP response body.

```python
# Vulnerable: user input echoed into HTML without encoding
return f"<h1>Results for {q}</h1>"

# Attack payload: <script>alert(1)</script>
# Expected marker: <script>alert(1)</script> (unencoded in response)

# Fixed: HTML entity encoding
return f"<h1>Results for {html.escape(q)}</h1>"
```

---

### 5. Server-Side Request Forgery (SSRF)
- **CWE:** CWE-918
- **Mechanism:** The backend application accepts a user-provided URL (e.g. webhook endpoints, profile image avatars, PDF generators, link previews) and performs an outbound HTTP request without restricting the target destination. In cloud environments (AWS, GCP, Azure), attackers point the URL to the link-local instance metadata service (`http://169.254.169.254/latest/meta-data/`) to extract IAM session credentials, or to internal microservices (`http://localhost:8080/admin`).
- **Why Probing Matters:** Static scanners cannot tell whether firewall rules, network policies, or DNS filters exist. ShipCheck's probe sends an actual request to a mock metadata/internal listener inside the sandbox and checks if the metadata marker is returned.

```python
# Vulnerable: fetches arbitrary user-supplied URL without restrictions
@app.route("/api/preview")
def preview():
    target_url = request.args.get("url")
    resp = requests.get(target_url, timeout=5)
    return resp.text

# Attack payload: http://169.254.169.254/latest/meta-data/
# Expected marker: "ami-id" (or "instance-id", proving access to internal metadata)

# Fixed: scheme validation, IP resolution & private CIDR filtering
import ipaddress
import socket
from urllib.parse import urlparse

def is_safe_url(target_url: str) -> bool:
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname or ""
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        # Block loopback, link-local (169.254.x.x), and private RFC 1918 CIDRs
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return False
    except (socket.gaierror, ValueError):
        return False
    return True

@app.route("/api/preview")
def preview():
    target_url = request.args.get("url")
    if not is_safe_url(target_url):
        abort(400, "Forbidden target address")
    resp = requests.get(target_url, timeout=5, allow_redirects=False)
    return resp.text
```

---

### 6. Server-Side Template Injection (SSTI)
- **CWE:** CWE-1336 / CWE-94
- **Mechanism:** Applications using template engines (Jinja2, Mako, Twig, EJS) dynamically concatenate untrusted user input directly into the template string before compiling it, rather than passing data as variables into the template render context. Attackers inject template syntax directives that break out of the template sandbox and execute arbitrary Python code.
- **Why Probing Matters:** The probe uses a deterministic mathematical evaluation canary (`{{7*7}}`). If the string `49` appears in the rendered output instead of literal `{{7*7}}`, template execution is objectively confirmed without guessing.

```python
# Vulnerable: user input concatenated directly into template string
@app.route("/greet")
def greet():
    name = request.args.get("name", "Guest")
    template_str = f"Hello {name}! Welcome to ShipCheck."
    return jinja2.Template(template_str).render()

# Attack payload: {{7*7}}
# Expected marker: "49" (evaluates expression inside template engine)

# Fixed: pass user input safely via template context variables
@app.route("/greet")
def greet():
    name = request.args.get("name", "Guest")
    template_str = "Hello {{ name }}! Welcome to ShipCheck."
    return jinja2.Template(template_str).render(name=name)
```

---

### 7. Insecure Direct Object Reference (IDOR / BOLA)
- **CWE:** CWE-639 / CWE-284 (OWASP API1:2023)
- **Mechanism:** The application exposes internal database object keys (e.g. `order_id`, `invoice_id`, `account_number`) in request parameters or API routes and retrieves records without verifying that the currently authenticated user/session actually possesses authorization to access that specific record. Attackers increment or swap IDs to access foreign tenant data (horizontal privilege escalation).
- **Why Probing Matters:** Static analysis tools almost never detect IDOR because `SELECT * WHERE id = :id` looks completely legitimate. Only an active probe with a foreign test account identifier can determine if cross-tenant leakage actually occurs.

```python
# Vulnerable: queries record by parameter ID without session ownership check
@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    order = db.session.query(Order).filter_by(id=order_id).first()
    if not order:
        abort(404)
    return jsonify(order.to_dict())

# Attack payload: /api/orders/102 (belonging to another tenant/user)
# Expected marker: "owner_id: 102" (or foreign user's private data returned)

# Fixed: scope database query to current_user.id
@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    order = db.session.query(Order).filter_by(
        id=order_id,
        user_id=current_user.id  # Enforce ownership boundary
    ).first()
    if not order:
        abort(404)
    return jsonify(order.to_dict())
```

---

### 8. Insecure Deserialization
- **CWE:** CWE-502
- **Mechanism:** Untrusted serialized data (such as pickled objects, unsafe YAML documents, or Java serialized streams) from cookies, request bodies, or query parameters is passed directly to native deserializers (`pickle.loads`, `yaml.unsafe_load`). Attackers construct crafted byte streams with object reduction methods (`__reduce__`) that execute arbitrary OS commands during object unpickling.
- **Why Probing Matters:** The probe sends a serialized payload containing a benign proof canary (e.g. executing `id` or logging a unique probe token). If the canary marker `uid=` appears, arbitrary code execution is proven.

```python
# Vulnerable: unpickling untrusted session cookies or client payloads
@app.route("/api/profile")
def profile():
    user_data = request.cookies.get("session_token")
    profile_obj = pickle.loads(base64.b64decode(user_data))
    return f"Welcome {profile_obj.get('username')}"

# Attack payload: base64(cos\nsystem\n(S'id'\ntR.)
# Expected marker: "uid=" (confirms arbitrary code execution during deserialization)

# Fixed: use secure data serialization (JSON or signed cryptographic tokens)
import base64
import json
import itsdangerous

signer = itsdangerous.TimestampSigner(SECRET_KEY)

@app.route("/api/profile")
def profile():
    raw_cookie = request.cookies.get("session_token")
    try:
        unsigned_data = signer.unsign(raw_cookie, max_age=86400)
        profile_obj = json.loads(unsigned_data.decode("utf-8"))
    except (itsdangerous.BadSignature, json.JSONDecodeError):
        abort(401, "Invalid session token")
    return f"Welcome {profile_obj.get('username')}"
```

---

## Canonical Attack Matrix Summary

| Vulnerability Class | VulnClass Enum | Attack Strategy | Canonical Payload | Expected Marker | Primary CWE |
|---|---|---|---|---|---|
| **SQL Injection** | `sqli` | Boolean authentication bypass | `' OR 1=1--` | `admin` | CWE-89 |
| **Command Injection** | `cmdi` | Shell separator command chaining | `8.8.8.8; id` | `uid=` | CWE-78 |
| **Path Traversal** | `traversal` | Dot-dot-slash directory traversal | `../../etc/passwd` | `root:` | CWE-22 |
| **Reflected XSS** | `xss` | Unencoded script tag injection | `<script>alert(1)</script>` | `<script>alert(1)</script>` | CWE-79 |
| **SSRF** | `ssrf` | Cloud metadata service probe | `http://169.254.169.254/latest/meta-data/` | `ami-id` | CWE-918 |
| **SSTI** | `ssti` | Mathematical expression evaluation | `{{7*7}}` | `49` | CWE-1336 |
| **IDOR / BOLA** | `idor` | Cross-tenant parameter tampering | `102` | `owner_id: 102` | CWE-639 |
| **Insecure Deserialization** | `deserialization` | Pickle reduction command execution | `cos\nsystem\n(S'id'\ntR.` | `uid=` | CWE-502 |

---

## Why This Architecture

### Why sandbox everything?
ShipCheck **runs real exploits**. Without isolation, you'd be SQL-injecting your own database or running `id` on your own server.

### Why not let the LLM judge if an exploit worked?
LLMs hallucinate. They'll confidently say "the exploit succeeded" when it didn't, or miss a real exploit. A string match on `uid=` is an objective fact. This is the core design principle of the entire project.

### Why `{file, search, replace}` instead of full file rewrites?
If you let an LLM rewrite an entire file, it will silently delete comments, change imports, alter business logic, or introduce new bugs. A surgical search-and-replace can only change the exact text you specify. If the search string isn't found (because the LLM hallucinated the code), the patch is rejected.

### Why "No PASS, No PR"?
AI-generated fixes often "fix" vulnerabilities by breaking the feature — returning an error for all inputs, removing the route entirely, or crashing. The re-verification gate catches this: the exploit must fail AND the existing tests must pass. If either check fails, no PR is opened.

### Why a draft PR instead of auto-merging?
Trust but verify. The system provides the proof; a human makes the final call.

---

## The Technology Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| **LLM (Planning & Fixing)** | Nemotron Ultra/Super/Nano via Token Factory | Ultra reasons about code; Super generates patches; Nano summarizes logs. Tiered to control cost. |
| **Sandbox** | Contree SDK (microVMs) + Docker fallback | Isolated execution with checkpoint/branching for parallel probes and clean before/after states |
| **Static Analysis** | Semgrep, gitleaks, pip-audit, osv-scanner | Free, open-source first-pass scanning to reduce LLM token waste |
| **Exploit Grounding** | Tavily Search API | Pulls real CVE writeups and advisory IDs so the report cites real references, not hallucinated ones |
| **API** | FastAPI | Exposes `POST /scan` and serves the dashboard |
| **PR Integration** | GitHub REST API + fine-grained PAT | Pushes fix branches and opens draft PRs with minimal permissions |
| **Deployment** | Docker + Nebius Serverless Endpoint | Public URL for judges/users to access |
| **Contracts** | Pydantic V2 | Strict schema validation for all data flowing between pipeline stages |

---

## Project Structure Overview

```
shipcheck/
├── src/shipcheck/
│   ├── contracts/        # Frozen data schemas (attack plans, evidence, fixes, verdicts)
│   ├── llm/              # Nemotron client, mock LLM, JSON extraction, prompt templates
│   ├── sandbox/          # Sandbox adapter (Contree SDK + Docker fallback)
│   ├── ingest/           # GitHub PR diff ingestion
│   ├── triage/           # Static scanner runners (Semgrep, gitleaks, etc.)
│   ├── planning/         # LLM attack planner + Tavily grounding
│   ├── probes/           # Exploit execution harness + deterministic marker checks
│   ├── scoring/          # Risk score computation + reachability analysis
│   ├── rectify/          # Fix generation, patching, and re-verification
│   ├── github/           # PR bot (push branch, open draft PR, never merge)
│   ├── report/           # JSON → Markdown report rendering
│   ├── pipeline/         # Orchestrator gluing all stages together
│   ├── replay/           # Golden-run recorder/player for demo stability
│   └── api/              # FastAPI endpoints + dashboard
├── fixtures/vulnshop/    # Intentionally vulnerable demo app for testing
├── tests/                # Unit tests + end-to-end SQLi test
└── docs/                 # Architecture notes, verification checklists
```

---

## What Makes This Different

1. **Proof, not opinion.** Every confirmed vulnerability comes with the exact payload, the exact response, and the exact string that proves it worked.
2. **Proof the fix works.** Every proposed fix comes with evidence that the same attack no longer succeeds.
3. **Deterministic verdicts.** No LLM decides if something is vulnerable. A string match does.
4. **Minimal, auditable patches.** Search-and-replace hunks that can't silently modify unrelated code.
5. **Human in the loop.** The system opens draft PRs. Humans merge.
