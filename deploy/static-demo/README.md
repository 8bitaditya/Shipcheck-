---
title: ShipCheck
emoji: 🛡️
colorFrom: blue
colorTo: gray
sdk: static
app_file: index.html
pinned: false
license: apache-2.0
short_description: Proves the exploit, fixes it, then re-attacks the fix
---

# ShipCheck — adversarial verification gate for AI-generated code

ShipCheck attacks AI-written code in a sandbox, proves each vulnerability with a real exploit, fixes it, re-attacks the fix, and opens a **draft** PR for a human. It never auto-merges.

This page replays a **recorded real scan** of the `vulnshop` demo app: real scanners (semgrep, gitleaks, osv-scanner, pip-audit), attack plans from NVIDIA Nemotron 3 Ultra on Nebius Token Factory, live HTTP exploits in isolated sandboxes, Tavily CVE grounding, and fixes from Nemotron 3 Super. 4 of 4 planted bugs (SQL injection, command injection, path traversal, reflected XSS) were confirmed, fixed and re-verified.

It is the dashboard's own page with that recording baked in (`scripts/build_static_demo.py`), so it renders exactly what the running app renders. Live scanning is disabled here, because a scan executes submitted code and spends model credits — run ShipCheck locally to scan your own code.

- Source: https://github.com/8bitaditya/Shipcheck- (Apache-2.0)
- Example draft PR opened by ShipCheck: https://github.com/8bitaditya/Shipcheck-/pull/1
