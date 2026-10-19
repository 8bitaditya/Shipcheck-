"""Tavily search client for CVE grounding, exploit writeups, and canonical fix advisories."""

import logging
from typing import Dict, List, Optional
import httpx

from shipcheck import config

logger = logging.getLogger(__name__)


class TavilyGroundingClient:
    """Grounds vulnerability findings with live CVE advisories and exploit techniques."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or config.TAVILY_API_KEY

    async def search_exploit_context(self, query: str) -> Dict[str, str]:
        """Search Tavily for exploit techniques and canonical fixes for a vulnerability."""
        if not self.api_key:
            logger.info("TAVILY_API_KEY not set. Returning offline fallback grounding.")
            return {
                "answer": f"Standard vulnerability pattern for {query}. Recommended mitigation: input sanitization and parameterized bindings.",
                "sources": "https://cve.mitre.org",
            }

        url = "https://api.tavily.com/search"
        payload = {
            "api_key": self.api_key,
            "query": f"{query} exploit proof of concept remediation",
            "search_depth": "advanced",
            "include_answer": True,
            "max_results": 3,
        }

        try:
            async with httpx.AsyncClient() as client:
                res = await client.post(url, json=payload, timeout=15.0)
                res.raise_for_status()
                data = res.json()
                answer = data.get("answer", "")
                sources = ", ".join(
                    [r.get("url", "") for r in data.get("results", [])]
                )
                return {"answer": answer, "sources": sources}
        except Exception as err:
            logger.warning("Tavily search error: %s. Using default grounding.", err)
            return {
                "answer": f"Security guidance for {query}.",
                "sources": "https://nvd.nist.gov",
            }
