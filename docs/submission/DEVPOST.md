# Devpost entry: ShipCheck

Copy each section into the matching Devpost field. Fill in the demo URL and video link once you have them.

**Name:** ShipCheck

**Tagline:** Don't flag it, prove it. ShipCheck attacks AI-generated code in a sandbox, fixes what it breaks, re-attacks the fix, and hands a human a draft PR. It never auto-merges.

**Links**
- Repo: https://github.com/8bitaditya/Shipcheck- (Apache-2.0)
- Demo: https://parthdevai-shipcheck.static.hf.space (replays a recorded real scan; live scans are disabled on the public URL) — Space page: https://huggingface.co/spaces/ParthDevAI/shipcheck
- Video: `<YOUTUBE_URL>`
- Example draft PR opened by ShipCheck: https://github.com/8bitaditya/Shipcheck-/pull/1

**Track:** Coding and Agentic Engineering

---

## Inspiration

AI assistants write a growing share of production code, and it passes tests. Scanners and LLM reviewers flag *suspects*, and they're wrong often enough that teams ignore them. We wanted a gate that doesn't guess: if ShipCheck says a PR is exploitable, it shows you the exploit working. If it says the fix works, it shows you the same exploit failing.

## What it does

For each PR, ShipCheck runs a five-stage loop:

1. **Triage:** semgrep (OWASP Top 10 plus our own path-traversal taint rule), gitleaks, osv-scanner and pip-audit flag suspects in the diff.
2. **Plan:** **NVIDIA Nemotron 3 Ultra** on **Nebius Token Factory** reads the diff, the findings and the full source of the affected files. It writes one falsifiable attack plan per finding: route, method, parameter, payload, and a deterministic success marker. **Tavily** supplies current exploit write-ups.
3. **Attack:** every plan fires as a real HTTP request against the app in its own forked, disposable sandbox. A finding is **confirmed** only if the marker appears in the response, for example the admin's email for SQLi, `uid=` for command injection, or `root:` for traversal. No LLM decides this. Confirmed findings get a deterministic 0–100 risk score (severity × confirmed × reachability × exposure) and **Tavily CVE/CWE grounding**.
4. **Fix:** **Nemotron 3 Super** writes a patch from the exploit evidence. ShipCheck applies it in a forked sandbox, **re-runs the exact attack** (the marker must be gone) and **runs the repo's tests** (they must pass). If either check fails, Super gets the failure output and tries again. No PASS, No PR.
5. **Hand-off:** a **draft** PR with the evidence, advisories, root cause, diff, re-verification and a reviewer checklist. ShipCheck never merges.

On our `vulnshop` demo app, a real run confirms **4 of 4** planted bugs (SQLi, command injection, path traversal, reflected XSS), fixes all four, re-verifies them, and opened a real draft PR, in about 40 seconds.

## How we built it

- **Python 3.11, Pydantic v2 contracts, FastAPI** with a single-page dashboard.
- **Nebius Token Factory** through its OpenAI-compatible API:
  - `nvidia/Nemotron-3-Ultra-550b-a55b` for planning, using the 1M context to read the diff, the findings and the full files.
  - `nvidia/nemotron-3-super-120b-a12b` for fixes.
- **Tavily** for exploit research and per-finding advisory grounding.
- **Sandboxes:** a backend interface with three implementations. The **Nebius Token Factory Sandboxes (ConTree)** backend is built and unit-tested. The other two are a **Docker** backend (a container per sandbox from our probe image, forked with `docker commit`) and a local temp-dir backend.
- **GitHub REST API** for draft PRs. A re-scan refreshes the same PR with a fast-forward commit, and never touches a branch a human has pushed to.
- **A golden-run replay**, so the demo never depends on a live call: a recorded real scan, redacted, served by `/api/demo`.
- **Tests:** 127 tests, plus live exploit tests and Docker tests. CI runs on Python 3.11 and 3.12, including live exploits against vulnshop.

## Challenges we ran into

- **Nebius Sandboxes access.** Our key worked for inference, but every Sandboxes call returned 403; `/v1/whoami` showed all permissions `false` because the beta hadn't been enabled for our project. We built a Docker backend with the same probe image and the same fork semantics, so the pipeline runs fully isolated today. **The recorded demo run used Docker sandboxes, not Nebius Sandboxes.**
- **Making LLM output safe to act on.** Ultra followed our first prompt's outdated schema exactly, Super sometimes adds a stray `>` to search strings, and with only a diff the planner guesses. The fixes:
  - canonical-schema prompts with per-plan validation;
  - feeding the planner the full source;
  - strict exact-match patching with a narrow, gated repair;
  - feeding gate failures back to Super.
- **The re-attack hit unpatched code.** Our first real run "fixed" nothing, because the re-attack ran against the parent sandbox instead of the patched fork. That's exactly the kind of bug a verification gate exists to catch, in ourselves too.

## Accomplishments that we're proud of

- **An honest gate.** Every confirmed finding has a real exploit in the transcript, and every fix has a real failed re-attack plus green tests.
- **Real end to end:** real scanners, real models, real HTTP attacks, a real draft PR.

## What we learned

- **Deterministic markers beat LLM judgment** for deciding "is this exploitable".
- **Give the planner the whole file.** Long context isn't a luxury for security planning.
- **Feed failures back into the loop.** The verification loop is also the best teacher for the fixer model.

## What's next for ShipCheck

- Run on Nebius Sandboxes as soon as access is granted, and re-record the demo there.
- More vulnerability classes: SSRF, SSTI, IDOR and deserialization, for which templates already exist.
- Semgrep taint-based reachability.
- A GitHub App that runs on every PR.

## Built with

python, fastapi, pydantic, nebius-token-factory, nvidia-nemotron, tavily, semgrep, gitleaks, osv-scanner, pip-audit, docker, github-api, httpx, pytest
