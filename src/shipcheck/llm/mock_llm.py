"""Mock LLM implementation (Sandforge pattern) for offline development and testing."""

import json
from typing import Any, Dict, List, Optional, Union


class MockNemotronClient:
    """Deterministic offline mock mimicking Nemotron responses for test fixtures."""

    def __init__(self, *args, **kwargs):
        pass

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        tier: str = "super",
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> str:
        """Return deterministic mock text based on prompt keywords."""
        lower_prompt = prompt.lower()
        if "attack plan" in lower_prompt or "planner" in lower_prompt:
            return json.dumps(
                {
                    "plan_id": "mock-plan-1",
                    "commit_sha": "mock-sha",
                    "summary": "Mock attack plan targeting 4 vulnerability classes",
                    "steps": [
                        {
                            "step_id": "step-sqli",
                            "finding_id": "finding-sqli",
                            "vuln_class": "SQLi",
                            "target_file": "app.py",
                            "target_endpoint": "/login",
                            "http_method": "POST",
                            "payload_strategy": "Tautology authentication bypass",
                            "expected_marker": "admin@vulnshop.local",
                            "suggested_payloads": ["admin' OR 1=1--"],
                        },
                        {
                            "step_id": "step-cmdi",
                            "finding_id": "finding-cmdi",
                            "vuln_class": "Command Injection",
                            "target_file": "app.py",
                            "target_endpoint": "/export",
                            "http_method": "GET",
                            "payload_strategy": "Command separator injection",
                            "expected_marker": "uid=",
                            "suggested_payloads": ["8.8.8.8; id"],
                        },
                        {
                            "step_id": "step-traversal",
                            "finding_id": "finding-traversal",
                            "vuln_class": "Path Traversal",
                            "target_file": "app.py",
                            "target_endpoint": "/download",
                            "http_method": "GET",
                            "payload_strategy": "Directory traversal sequence",
                            "expected_marker": "root:",
                            "suggested_payloads": ["../../etc/passwd"],
                        },
                        {
                            "step_id": "step-xss",
                            "finding_id": "finding-xss",
                            "vuln_class": "Reflected XSS",
                            "target_file": "app.py",
                            "target_endpoint": "/search",
                            "http_method": "GET",
                            "payload_strategy": "Script tag reflection",
                            "expected_marker": "<script>alert(1)</script>",
                            "suggested_payloads": ["<script>alert(1)</script>"],
                        },
                    ],
                }
            )

        if "fix" in lower_prompt or "patch" in lower_prompt:
            return json.dumps(
                {
                    "hunks": [
                        {
                            "file_path": "app.py",
                            "search_block": "query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"",
                            "replace_block": "query = \"SELECT * FROM users WHERE username = ? AND password = ?\"\n    cursor.execute(query, (username, password))",
                            "rationale": "Parameterized SQLite query eliminates SQL injection",
                        }
                    ]
                }
            )

        return "Mock response for query"

    async def complete_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        tier: str = "super",
        max_tokens: int = 4096,
    ) -> Optional[Union[Dict[str, Any], List[Any]]]:
        """Return parsed mock JSON."""
        text = await self.complete(prompt, system_prompt, tier, max_tokens)
        return json.loads(text)
