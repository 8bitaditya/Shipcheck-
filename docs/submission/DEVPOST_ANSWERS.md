# Devpost: field-by-field answers

Paste these into the matching fields. Anything marked **[your call]** is an opinion or a personal detail — read it and change it if you disagree. Everything else is factual and checked against what we actually built.

---

## 1. Project overview

**Project name**
```
ShipCheck
```
(Currently "Ship Check". One word matches the repo, the dashboard and the video.)

**Elevator pitch** (200 characters max — this is 183)
```
Don't flag it, prove it. ShipCheck attacks AI-generated code in a sandbox, proves each bug with a real exploit, fixes it, re-attacks the fix, then opens a draft PR. It never auto-merges.
```

**Thumbnail:** use `media/01-dashboard.png` (3:2, as Devpost asks).

---

## 2. Project details

### About the project

Paste this whole block into **About the project**. It uses the headings Devpost pre-filled.

```markdown
## Inspiration

AI assistants now write a large share of production code, and that code passes tests. The tools meant to catch its security bugs only ever *suspect*: scanners and LLM reviewers produce findings that are often wrong, so teams learn to scroll past them. We wanted a gate that never asks you to take its word for it. If ShipCheck says your PR is exploitable, it shows you the exploit working. If it says the fix is good, it shows you the same exploit failing.

## What it does

For every pull request, ShipCheck runs a five-stage loop:

1. **Triage** — semgrep (OWASP Top 10, plus a path-traversal taint rule we wrote because no registry pack caught ours), gitleaks, osv-scanner and pip-audit flag suspects in the diff. Overlapping rules on the same sink are merged into one finding.
2. **Plan** — **NVIDIA Nemotron 3 Ultra** on **Nebius Token Factory** reads the diff, the triage findings and the *full source* of every affected file, and writes one falsifiable attack plan per finding: route, HTTP method, parameter, payload, and a deterministic success marker. **Tavily** supplies current exploit write-ups.
3. **Attack** — each plan fires as a real HTTP request against the running app inside its own forked, disposable sandbox. A finding is **confirmed** only when the marker appears in the response: the admin's email for SQL injection, `uid=` for command injection, `root:` for path traversal. No LLM casts a vote. Confirmed findings get a deterministic 0–100 risk score (severity × confirmed × reachability × exposure) and **Tavily CVE/CWE grounding** with the canonical fix.
4. **Fix** — **Nemotron 3 Super** writes a patch from the exploit evidence. ShipCheck applies it in a forked sandbox, **re-runs the exact same attack** (the marker must be gone) and **runs the repo's own tests** (they must pass). If either check fails, Super gets the failure output and tries again. No PASS, No PR.
5. **Hand-off** — a **draft** pull request containing the exploit evidence, the advisories, the root cause, the diff, the re-verification result and a reviewer checklist. ShipCheck never merges. A human decides.

On our `vulnshop` demo app, a real run confirms **4 of 4** planted vulnerabilities, fixes all four, re-verifies them and opens a real draft PR — in about 39 seconds.

## How we built it

- **Python 3.11**, Pydantic v2 contracts frozen in week one so three people could build in parallel, FastAPI and a dependency-free dashboard.
- **Nebius Token Factory** through its OpenAI-compatible API: `nvidia/Nemotron-3-Ultra-550b-a55b` plans the attacks, `nvidia/nemotron-3-super-120b-a12b` writes the fixes.
- **Tavily** for exploit research and per-finding advisory grounding.
- **Sandboxes behind one interface, three implementations:** a Nebius Token Factory Sandboxes (ConTree) backend, a Docker backend (one container per sandbox, forked with `docker commit`) and a local temp-dir backend.
- **GitHub REST API** for draft PRs. A re-scan refreshes the same PR with a fast-forward commit and never touches a branch a human has pushed to.
- **A golden-run replay**, so the public demo never depends on a live call: a recorded real scan, redacted, served from the dashboard.
- **135 tests**, plus live exploit tests and Docker tests. CI runs on Python 3.11 and 3.12 and includes live exploits against the demo app.

## Challenges we ran into

- **Nebius Sandboxes access.** Our key worked for inference, but every Sandboxes call returned 403; `/v1/whoami` showed every permission as `false`, because the beta had not been enabled for our project. We built a Docker backend with the same probe image and the same fork semantics, so the pipeline still runs fully isolated. **The recorded demo run used Docker sandboxes, not Nebius Sandboxes.**
- **Making model output safe to act on.** Ultra followed our first prompt's outdated schema exactly, so every plan failed validation and we silently fell back to templates. Super sometimes appended a stray character to a JSON string. Given only a diff, the planner guessed routes and invented markers. The fixes: canonical-schema prompts with per-plan validation, feeding the planner whole files, exact-match patching with a narrow repair, and feeding gate failures back to the model.
- **Our own re-attack hit unpatched code.** The first real run "fixed" nothing, because the re-attack ran against the parent sandbox instead of the patched fork. A verification gate that cannot verify itself is worthless, and this is exactly the class of bug it exists to catch.

## Accomplishments that we're proud of

- **An honest gate.** Every confirmed finding has a real exploit in the transcript, and every accepted fix has a real failed re-attack plus green tests behind it.
- **Real end to end:** real scanners, real models, real HTTP attacks, a real draft PR opened on our repo.
- **It caught our own bugs.** The verification loop found three defects in ShipCheck itself during development.

## What we learned

- **Deterministic markers beat model judgement** for deciding "is this exploitable". A string match cannot hallucinate.
- **Give the planner the whole file.** Long context is not a luxury for security planning; with only a diff, the model guesses.
- **Feed failures back into the loop.** The verification gate turned out to be the best teacher the fixer model had.

## What's next for ShipCheck

- Run on Nebius Sandboxes as soon as access is granted, and re-record the demo there.
- More vulnerability classes: SSRF, SSTI, IDOR and deserialization, which already have templates.
- Semgrep taint-based reachability instead of the current heuristic.
- A GitHub App that runs on every pull request.
```

### Built with (tags)

```
python, fastapi, pydantic, nebius, nebius-token-factory, nvidia, nemotron, tavily, semgrep, gitleaks, osv-scanner, pip-audit, docker, github-api, httpx, pytest, uvicorn, flask
```

### "Try it out" links

```
https://parthdevai-shipcheck.static.hf.space
https://github.com/8bitaditya/Shipcheck-
https://github.com/8bitaditya/Shipcheck-/pull/1
```

### Project Media

See the **Project Media** section at the bottom of this file.

---

## 3. Additional info

| Field | Answer |
|---|---|
| **Submitter Type** | Team **[your call]** — pick Team if offered, since there are three of you |
| **Organization Name** | `N/A` |
| **Submitter Country of Residence** | India **[your call]** |
| **Canada province** | `N/A` |
| **Which track** | Coding and Agentic Engineering |
| **New or existing prior to Aug 26, 2026?** | New |
| **Public code repository URL** | `https://github.com/8bitaditya/Shipcheck-` |
| **Working demo URL** | `https://parthdevai-shipcheck.static.hf.space` |
| **Did you use Tavily?** | **Yes** — we make functional runtime calls to the Tavily search API (see below) |
| **Builders & Brews city** | Leave unselected unless you attended one |
| **Both checkboxes** | Tick them |
| **Level of learning** | **[your call]** — "Significant" or the highest honest option |
| **Did you gain AI value for your career?** | **[your call]** — Yes |

### Which model(s) did you use, and why that size/variant?

```
Two, matched to the job:

nvidia/Nemotron-3-Ultra-550b-a55b — attack planning. This is the one step where context size is load-bearing: the planner reads the full PR diff, every triage finding AND the complete source of each affected file in a single call, so it can take real routes, parameter names and success markers from the code instead of guessing. We proved this mattered: given only a small diff, it aimed a SQL injection at the wrong route, used the wrong parameter and invented a marker, and nothing was confirmed. Given the full files, all four plans were correct. A wrong plan wastes an entire sandbox run, so we spend the big model here.

nvidia/nemotron-3-super-120b-a12b — fix generation. Called once per confirmed finding and up to three times when a patch fails verification, so latency and cost matter more than raw capability. Super is good enough because we never trust its output: every patch must survive the same exploit being re-fired and the repo's own test suite before it can reach a human.

nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B — configured for log compaction and search-query synthesis, but we ran out of time and it is not wired into the final pipeline.
```

### How would you rate Nemotron's output quality? (1–10)

**8** **[your call]**

```
8.

Worked well: schema compliance is excellent — given a JSON schema in the system prompt, Ultra returns exactly that shape, which is what let us validate plans mechanically. The security reasoning was genuinely good: Super produced correct, minimal fixes from exploit evidence (parameterized queries, subprocess without a shell, a base-directory check, HTML escaping), and Ultra chose sensible payloads and markers from real code.

Fell short: (1) some responses return empty `content` with the text in `reasoning_content`, so we fall back to it and pass `chat_template_kwargs: {enable_thinking: false}`. (2) There is no server-side JSON guarantee, so we prompt for a fenced block and parse the last one. (3) Super repeatedly appended a stray `>` or `,` to one JSON string, even after being shown the exact line — we added a narrow, gated repair. (4) It once used `html.escape` without importing `html`; our test gate caught it and it fixed itself when we fed the failing test output back.

The literal schema compliance cuts both ways: our first prompt contained an outdated schema, and Ultra followed it exactly, so every plan failed validation and we silently fell back to templates until we noticed.
```

### Did you fine-tune, prompt-engineer, or use Nemotron out of the box?

```
Out of the box, with heavy prompt engineering and a verification loop around it. No fine-tuning.

What we did instead:
- A canonical JSON schema in the system prompt, with one example per field, and per-plan validation so one malformed plan cannot discard the whole batch.
- Full source files in the planning context, not just the diff.
- Failure-driven retries: when a patch does not apply, the model is told the rejection reason and shown the closest real text in the file; when a patch applies but fails the gate, it gets the failing re-attack output or the failing test output.
- Deterministic scaffolding everywhere the model does not need to decide: payload templates, marker checks and the risk score are plain code, so model error can never turn an unproven finding into a confirmed one.
```

### How did Nemotron's performance compare to other models for similar tasks?

```
We built the pipeline on Nemotron rather than benchmarking models side by side, so this is a qualitative comparison with our general experience of using LLMs for structured code tasks.

Where it stood out: instruction and schema following. Ultra reproduced our requested JSON shape literally and consistently, which is exactly what you want when the output is fed to a validator rather than a human. Latency on Token Factory was 0.5–2 s for small calls across Nano, Super and Ultra, and a complete scan — one Ultra planning call plus up to three Super fix calls per finding, with live exploits in between — finishes in about 39 seconds.

Where it behaved like most models we have used: no guaranteed structured output, and small recurring formatting quirks in long literal strings. Our answer was not a better model but a stricter gate: nothing the model writes is accepted until an exploit and a test suite agree.
```

### Which Nebius platform capabilities were most valuable to your project, and how?

```
Token Factory inference was the backbone. Three things mattered:

1. The OpenAI-compatible endpoint (https://api.tokenfactory.nebius.com/v1/). We pointed the stock `openai` Python client at it and changed only the base URL and the key — integration was minutes, not an afternoon.
2. GET /v1/models returned all 30 models with exact, case-sensitive IDs, which let us verify every hard-coded Nemotron ID in one call.
3. The tiered Nemotron line-up on one endpoint, so routing planning to Ultra and fixes to Super was a parameter change rather than a second integration.

Token Factory Sandboxes (ConTree) is the capability our architecture is designed around — forking an immutable image per exploit is exactly the primitive an attack-then-verify loop needs — but access is a gated beta and ours was not granted in time, so the recorded run uses an equivalent Docker backend. The ConTree backend is written and unit-tested and switches on with one environment variable.
```

### How likely are you to recommend running Nemotron on Nebius? (1–10)

**8** **[your call]**

```
8. The inference side is genuinely easy to recommend: OpenAI-compatible, fast, with the whole Nemotron tier list behind one key, and pricing visible per project. The point taken off is onboarding beyond inference — Sandboxes is a gated beta whose 403s do not say so, and Token Factory and AI Cloud are separate accounts and projects, which cost us hours during a hackathon.
```

### How would you rate running Nemotron inference on Nebius vs previous environments? (1–10)

**8** **[your call]**

```
8. Compared with self-hosting a model, this was not close: no GPU provisioning, no weights to download, and a drop-in OpenAI client. Compared with other hosted APIs we have used, it is equivalent in ergonomics and noticeably good on model selection and latency. What kept it from a 9 or 10 was the thinking/`reasoning_content` behaviour and the absence of a server-side JSON mode, both of which we had to handle in application code.
```

### What additional features or improvements would have made the experience more effective?

```
1. Server-side structured output — a JSON schema or response_format for Nemotron. Half our hardening exists because we cannot guarantee a parseable response.
2. Actionable permission errors. Sandboxes returns "403 Insufficient permissions" with no hint that it is a gated beta; GET /v1/whoami already returns a permissions map, so pointing to it (or saying "request access here") in the error body would have saved us most of a day.
3. Self-serve or fast-tracked Sandboxes access for hackathon participants, since the event promotes it.
4. One story for Token Factory and AI Cloud. Separate consoles, CLIs, project IDs and billing for what feels like one product is the single most confusing thing we hit.
5. Two documentation notes for contree-sdk 0.3.6 that cost us real time: apply_files() returns a NEW image rather than mutating, and a str value in the files dict is treated as a local path, not as file content.
6. A documented way to disable thinking output per request, rather than chat_template_kwargs plus a reasoning_content fallback.
```

### What do you most hope to see from the Nemotron team next?

```
Guaranteed structured output — JSON schema enforcement or function calling with the same quality the models already show at following a schema by prompt. For agentic pipelines like ours, "the model usually returns valid JSON" is the difference between a tool you can ship and one that needs a parser full of fallbacks.

Second: a fast, cheap model tuned for exact code edits. Our fixer does not need 120B of reasoning; it needs to reproduce a block of source byte-for-byte and change three lines. That specific failure mode — a stray character in a long literal — was our most common retry cause.
```

### Which AI tools have you leveraged while working on this project?

```
Claude Code (Anthropic) as a pair programmer for implementation, debugging and test writing.
NVIDIA Nemotron 3 (Ultra and Super) via Nebius Token Factory — inside the product itself, for attack planning and fix generation.
Tavily Search API — inside the product, for exploit research and CVE/advisory grounding.
```
**[your call]** — add Cursor, ChatGPT or anything else you used.

---

## 4. Project Media — what to upload

Devpost wants a **3:2 ratio**, up to 15 images. Six is plenty. Order matters: the first image is the one most judges actually look at.

| # | Shot | Why it earns its place | Status |
|---|---|---|---|
| 1 | **Dashboard, top of page** — headline, stat row (100 top risk, 5 findings, 4 confirmed, 4 fixed, 1 draft PR) and the first finding's timeline | The whole pitch in one frame: found, proven, fixed, handed over | ✅ `media/01-dashboard.jpg` |
| 2 | **The SQL-injection card in full** — timeline, payload `admin'--`, observed marker `admin@vulnshop.local`, the Tavily advisory block with CWE-89 and CVE IDs, and the fix diff | The proof *and* the Tavily grounding in one image. This is the strongest frame you have, and the Tavily prize is judged on exactly this | ✅ `media/02-evidence-and-tavily.jpg` |
| 3 | **The draft PR on GitHub** — scroll to the body: exploit evidence, advisory grounding, root cause, diff, "ShipCheck never auto-merges" | Shows the hand-off is real, not a mock-up | ⬜ yours: open [PR #1](https://github.com/8bitaditya/Shipcheck-/pull/1), Cmd+Shift+4 |
| 4 | **Terminal mid-scan** — the output of `python scripts/record_golden.py --backend docker` with the 39 s summary | Proves the scan is real and reproducible, not a canned JSON | ⬜ yours |
| 5 | **Green CI** — GitHub Actions showing 3.11 and 3.12 passing | Quiet credibility: it is tested | ⬜ yours |

I generated 1 and 2 from the live demo at 3:2. For the rest, press **Cmd+Shift+4** then **Space** to capture a clean window.

**Video link:** paste your YouTube URL into the "Video Demo Link" field under Project Media. Devpost requires it to be public, not unlisted.

---

## 5. Submit

Tick the Terms & conditions box and press **Submit project**. You can keep editing until the deadline, so submit early rather than perfecting first.
