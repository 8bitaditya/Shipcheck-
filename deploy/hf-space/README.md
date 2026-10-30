---
title: ShipCheck
emoji: 🛡️
colorFrom: blue
colorTo: gray
sdk: docker
app_port: 8000
pinned: false
license: apache-2.0
---

# ShipCheck — adversarial verification gate for AI-generated code

ShipCheck attacks AI-written code in a sandbox, proves each vulnerability with a real exploit, fixes it, re-attacks the fix, and opens a **draft** PR for a human. It never auto-merges.

This Space replays a **recorded real scan** of the `vulnshop` demo app: 4 of 4 planted bugs (SQL injection, command injection, path traversal, reflected XSS) confirmed by live exploits, fixed, and re-verified. Live scans are disabled here, because they execute submitted code and spend model credits.

- Source: https://github.com/8bitaditya/Shipcheck- (Apache-2.0)
- Example draft PR opened by ShipCheck: https://github.com/8bitaditya/Shipcheck-/pull/1

Built on Nebius Token Factory with NVIDIA Nemotron 3 (Ultra plans the attacks, Super writes the fixes) and Tavily CVE grounding.
