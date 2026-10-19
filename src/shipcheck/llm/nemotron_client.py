"""Nemotron 3 client with tiered model presets, reasoning content fallback, and retry logic."""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Union
from openai import AsyncOpenAI, APIConnectionError, RateLimitError

from shipcheck import config
from shipcheck.llm.json_extract import extract_last_json

logger = logging.getLogger(__name__)


class NemotronClient:
    """Unified client for NVIDIA Nemotron-3 models hosted on Nebius Token Factory."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        self.api_key = api_key or config.NEBIUS_API_KEY
        self.base_url = base_url or config.TOKEN_FACTORY_BASE_URL
        self.client = AsyncOpenAI(
            api_key=self.api_key or "mock-key",
            base_url=self.base_url,
        )

        # Tier presets as defined in PRD Section 6
        self.tiers = {
            "ultra": config.NEMOTRON_ULTRA_MODEL_ID,
            "super": config.NEMOTRON_SUPER_MODEL_ID,
            "nano": config.NEMOTRON_NANO_MODEL_ID,
            "lightning": config.NEMOTRON_LIGHTNING_MODEL_ID,
        }

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        tier: str = "super",
        max_tokens: int = 4096,
        temperature: float = 0.2,
        retries: int = 3,
    ) -> str:
        """Call Nemotron model with reasoning_content fallback and chat_template_kwargs."""
        model_id = self.tiers.get(tier.lower(), self.tiers["super"])

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        # PRD Gotcha #1: Force non-empty content and disable reasoning divergence if needed
        extra_body = {
            "chat_template_kwargs": {
                "enable_thinking": False,
                "force_nonempty_content": True,
            }
        }

        delay = 1.0
        last_exception = None

        for attempt in range(1, retries + 1):
            try:
                response = await self.client.chat.completions.create(
                    model=model_id,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    extra_body=extra_body,
                )

                choice = response.choices[0]
                content = choice.message.content or ""

                # Fallback to reasoning_content if content is empty (documented Nebius behavior)
                if not content.strip() and hasattr(choice.message, "reasoning_content"):
                    reasoning = getattr(choice.message, "reasoning_content", None)
                    if reasoning:
                        content = reasoning

                return content
            except (RateLimitError, APIConnectionError) as err:
                last_exception = err
                logger.warning(
                    "Nemotron API attempt %d failed: %s. Backing off for %.1fs...",
                    attempt,
                    err,
                    delay,
                )
                await asyncio.sleep(delay)
                delay *= 2
            except Exception as exc:
                logger.error("Nemotron call failed with error: %s", exc)
                raise exc

        raise RuntimeError(
            f"Nemotron complete failed after {retries} attempts: {last_exception}"
        )

    async def complete_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        tier: str = "super",
        max_tokens: int = 4096,
    ) -> Optional[Union[Dict[str, Any], List[Any]]]:
        """Request structured JSON from Nemotron and extract the last JSON block."""
        formatted_prompt = (
            f"{prompt}\n\nIMPORTANT: Respond ONLY with a valid JSON block enclosed in ```json ... ```."
        )
        raw_text = await self.complete(
            prompt=formatted_prompt,
            system_prompt=system_prompt,
            tier=tier,
            max_tokens=max_tokens,
        )
        return extract_last_json(raw_text)
