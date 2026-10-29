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
                    "batch_id": "mock-batch-1",
                    "diff_ref": "mock-sha",
                    "plans": [
                        {
                            "vuln_class": "sqli",
                            "target_file": "app.py",
                            "sink": "db.execute()",
                            "payload_strategy": "Tautology authentication bypass",
                            "expected_marker": "admin@vulnshop.local",
                            "route": "/login",
                            "http_method": "POST",
                            "parameter_name": "username",
                            "suggested_payload": "admin' OR 1=1--",
                        },
                        {
                            "vuln_class": "cmdi",
                            "target_file": "app.py",
                            "sink": "os.system()",
                            "payload_strategy": "Command separator injection",
                            "expected_marker": "uid=",
                            "route": "/export",
                            "http_method": "GET",
                            "parameter_name": "ip",
                            "suggested_payload": "8.8.8.8; id",
                        },
                        {
                            "vuln_class": "traversal",
                            "target_file": "app.py",
                            "sink": "open()",
                            "payload_strategy": "Directory traversal sequence",
                            "expected_marker": "root:",
                            "route": "/download",
                            "http_method": "GET",
                            "parameter_name": "file",
                            "suggested_payload": "../../../../../../../../../../../../etc/passwd",
                        },
                        {
                            "vuln_class": "xss",
                            "target_file": "app.py",
                            "sink": "render_template_string()",
                            "payload_strategy": "Script tag reflection",
                            "expected_marker": "<script>alert(1)</script>",
                            "route": "/search",
                            "http_method": "GET",
                            "parameter_name": "q",
                            "suggested_payload": "<script>alert(1)</script>",
                        },
                    ],
                }
            )

        if "fix" in lower_prompt or "patch" in lower_prompt:
            return json.dumps(
                {
                    "hunks": [
                        {
                            "file": "app.py",
                            "search": "query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"",
                            "replace": "query = \"SELECT * FROM users WHERE username = ? AND password = ?\"\n    cursor.execute(query, (username, password))",
                        }
                    ],
                    "root_cause": "Unparameterized SQL string interpolation",
                    "explanation": "Parameterized SQLite query eliminates SQL injection",
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
