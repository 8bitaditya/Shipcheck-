"""Robust JSON block extractor from model responses (PRD Gotcha #1)."""

import json
import re
from typing import Any, Dict, List, Optional, Union


def extract_last_json(text: str) -> Optional[Union[Dict[str, Any], List[Any]]]:
    """Find and parse the last valid JSON block (dict or list) in LLM output.

    Handles markdown fences ```json ... ``` and raw JSON structures.
    """
    if not text:
        return None

    # 1. Search for fenced markdown code blocks first
    fence_matches = list(re.finditer(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE))
    if fence_matches:
        # Check from last fence backward
        for match in reversed(fence_matches):
            snippet = match.group(1).strip()
            try:
                return json.loads(snippet)
            except json.JSONDecodeError:
                continue

    # 2. Search for the outermost JSON brackets from end of string
    # Find last occurrence of closing } or ]
    last_brace = text.rfind("}")
    last_bracket = text.rfind("]")

    if last_brace == -1 and last_bracket == -1:
        return None

    end_idx = max(last_brace, last_bracket)
    open_char = "{" if end_idx == last_brace else "["

    # Scan backward for matching open bracket
    bracket_depth = 0
    start_idx = -1
    for i in range(end_idx, -1, -1):
        char = text[i]
        if char in "}]":
            bracket_depth += 1
        elif char in "{[":
            bracket_depth -= 1
            if bracket_depth == 0:
                start_idx = i
                break

    if start_idx != -1:
        candidate = text[start_idx : end_idx + 1].strip()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    return None
