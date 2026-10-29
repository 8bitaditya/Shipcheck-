# ShipCheck: 3-minute demo video

This follows the PRD §10 beats. The audio must cover Token Factory and Nemotron (a submission requirement). Total length is 2:55. Record the screen at 1080p and upload the video to YouTube as **Public**.

**Before recording:**
- Open the dashboard at the demo URL, or at `http://localhost:8000`, with **Load demo** ready.
- Open [PR #1](https://github.com/8bitaditya/Shipcheck-/pull/1) in a second tab.
- Open `fixtures/vulnshop/app.py` in the editor, scrolled to `login()`.
- Optional live beat: a terminal ready to run `python scripts/record_golden.py --backend docker`, which runs a real scan in about 40 s.

| Time | Screen | Voice-over |
|---|---|---|
| **0:00–0:25** | Editor: `login()` in `fixtures/vulnshop/app.py`, with the `%`-formatted SQL highlighted. Then a terminal showing `pytest` green. | "An AI assistant wrote this login handler. The tests pass and CI is green. But scanners and LLM reviewers only *suspect* bugs, and they're wrong often enough that teams ignore them. ShipCheck doesn't guess. It attacks the code and proves it." |
| **0:25–0:50** | Dashboard: click **Load demo**. Point at the stats: 5 findings, 4 confirmed, 4 fixed. | "This is a real ShipCheck run. Semgrep, gitleaks, osv-scanner and pip-audit flag suspects. Then **NVIDIA Nemotron 3 Ultra, served by Nebius Token Factory**, reads the diff, the findings and the full source, and writes one concrete attack plan per finding. **Tavily** adds current exploit write-ups." |
| **0:50–1:20** | Expand the **SQLi** card: payload `admin'--`, marker `admin@vulnshop.local`, verdict CONFIRMED, score **100/100**, and the score breakdown. | "Each plan runs as a real HTTP attack in its own disposable sandbox. Here the SQL injection logs in as admin, and the admin's email shows up in the response. That marker is the proof. No LLM decides this: a string match does. Confirmed, critical, publicly reachable: risk score 100." |
| **1:20–1:35** | Scroll the Advisory grounding block: CWE-89, the CVE IDs and the source links. | "Tavily grounds every confirmed finding with CWE and CVE advisories and the canonical fix, so the reviewer sees the context, not just the alert." |
| **1:35–2:05** | The fix diff (parameterized query), then the timeline: *Exploit landed → patched & re-attacked: marker gone → repo tests pass*, and the **PASS** gate. | "Now the fix. **Nemotron 3 Super** writes a patch from the exploit evidence. ShipCheck applies it in a *forked* sandbox and fires the *exact same attack* again. The marker is gone. Then the repo's own tests run, and they pass. Both checks or nothing: No PASS, No PR." |
| **2:05–2:15** | Quick cut to the command-injection and traversal cards (`uid=`, `root:`), both PASS. | "Command injection, path traversal and XSS: all four confirmed, fixed and re-verified in under a minute." |
| **2:15–2:40** | The GitHub tab: draft PR #1, scrolling the body (evidence, advisories, root cause, diff, re-verification, reviewer checklist). | "Only then does ShipCheck open a **draft** pull request with the evidence, the advisories, the diff and the re-run result. ShipCheck never merges. A human makes the call." |
| **2:40–2:55** | Slide or README: the stack. | "Built on **Nebius Token Factory** with **NVIDIA Nemotron 3**: Ultra plans the attacks, Super writes the fixes. Grounding comes from **Tavily**. It runs in isolated sandboxes, Docker today, with Nebius Sandboxes access pending. ShipCheck: prove it, fix it, hand it to a human." |

## Notes
- **Keep the facts as stated.** Nano isn't used, and the recorded run used Docker sandboxes because the Nebius Sandboxes beta has not been granted yet. If access arrives and the golden run is re-recorded on ConTree, change the last line to "runs in Nebius Token Factory Sandboxes".
- **If you show the optional live run**, cut the waiting; a real scan takes about 40 s.
- **Speak at about 150 words per minute.** The voice-over above is about 430 words.
