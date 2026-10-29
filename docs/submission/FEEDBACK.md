# Feedback: Nebius Token Factory, AI Cloud and NVIDIA tooling

This is written from building ShipCheck, an adversarial verification gate for AI-generated code, during the Nebius × NVIDIA hackathon. Everything below comes from what we actually ran.

## Nebius Token Factory (inference)

**What worked well**
- **The OpenAI-compatible endpoint** (`https://api.tokenfactory.nebius.com/v1/`) worked with the stock `openai` Python client. We changed only the base URL and the key.
- **`GET /v1/models`** returned all 30 models, with exact, case-sensitive IDs. It made checking our config trivial: every Nemotron ID we hard-coded was confirmed in one call.
- **Latency** for small calls was 0.5–2 s across Nano, Super and Ultra. A full scan, with one Ultra planning call and up to three Super fix attempts per finding, finishes in 40–60 s end to end.
- **The billing and usage pages** are clear, and the usage view per project is helpful.

**What tripped us up**
- **Thinking output.** Some responses put the useful text in `reasoning_content` and leave `content` empty, so we fall back to `reasoning_content`. We also pass `chat_template_kwargs: {enable_thinking: false}`. A documented, model-independent way to get "final answer only" would help.
- **No JSON mode.** We have no server-side structured-output guarantee, so we prompt for a fenced JSON block and parse the last one. A real JSON-schema or `response_format` option for Nemotron would remove a whole class of failures; see the model notes below.

## Nebius Token Factory Sandboxes (ConTree)

This was our biggest blocker, so the details are worth spelling out.
- **Unclear 403s.** With a valid inference key and the `Project` header, every Sandboxes call returned `403 Insufficient permissions: list` (and `import`, and so on). The message doesn't say that Sandboxes is a gated beta.
- **The answer was in `/v1/whoami`.** It returns a permissions map, and ours was all `false`. That endpoint is excellent; the 403 body could point to it, or say "Sandboxes access not granted — request at …".
- **Hard to find the access request.** The overview page mentions it, but someone reading the API reference or using the SDK won't see it. We requested access on hackathon day and fell back to Docker containers built from the same probe image.
- **SDK footguns in `contree-sdk 0.3.6`.** Both of these were silent:
  - `apply_files()` returns a *new* image and leaves the old one untouched. This is correct for immutable images, but it's easy to drop the result. A docstring warning or an in-place helper would help.
  - In `apply_files({...})`, a `str` value is treated as a **local file path**, not as file content. Passing source code as a string fails in a confusing way. Accepting `bytes` *or* clearly rejecting `str` would help.
- **Good design.** The fork-by-image model, where every run can branch from an immutable image, is a great fit for exploit-then-re-verify workflows. It's exactly what we needed.

## Nebius AI Cloud (Serverless endpoints)

- **Two separate setups.** Token Factory and AI Cloud are separate consoles, CLIs and project IDs. The Token Factory project ID (`aiproject-…`) isn't the AI Cloud project. For a hackathon that asks for a "Nebius Serverless Endpoint" demo URL, one page explaining how the two relate (which account, which credits, which CLI) would save teams time.
- **Public demo auth.** `nebius ai endpoint create` defaults to token auth. For a public demo URL that judges open in a browser, the docs should show the no-auth option clearly, together with the cost of keeping a CPU endpoint up through judging.

## NVIDIA Nemotron 3

**Ultra (`nvidia/Nemotron-3-Ultra-550b-a55b`) for attack planning**
- **Good plans with full context.** Given the diff, the triage findings *and the full source of the affected files*, it wrote correct, falsifiable plans for all four vulnerability classes: real routes, HTTP methods, parameter names and markers that the app really returns.
- **It followed our prompt's schema exactly**, including an outdated schema in our first prompt. That's great for compliance, but it means a wrong prompt fails silently.
- **It guesses with only a diff.** Given just a one-line diff, it guessed the route and parameter, and invented a marker (`admin@example.com`). Supplying the full file fixed this; the 1M context makes that cheap.

**Super (`nvidia/nemotron-3-super-120b-a12b`) for fix generation**
- **Good fixes.** It produced correct, minimal fixes from the exploit evidence: a parameterized query, `subprocess` without a shell, a path check, `html.escape`.
- **A recurring formatting quirk.** In JSON `search`/`replace` strings that end in an HTML-ish literal (`"</h1>"`), it often appended a stray `>` or `,` (`"</h1>">`), even after being shown the exact line. We added a narrow repair, and every patch still has to pass our re-attack and the repo's tests.
- **Imports.** It once used `html.escape` without `import html`. Our test gate caught it, and feeding the failing test output back fixed it on the next attempt.

**Nano and Lightning:** configured but not used in the final pipeline. We ran out of time to wire Nano in for log compaction.

## Tavily

`include_answer=True` plus up to 5 results gave usable CWE and CVE IDs and canonical-fix text for every confirmed finding. The Bearer-header auth was straightforward.
