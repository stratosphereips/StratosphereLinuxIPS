# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""OpenAI-compatible backend mixin for the shared LLM module."""

from typing import Any

from modules.llm.llm_backend import LLMBackend
from modules.llm.llm_errors import LLMRequestError


class MixinOpenAIBackend(LLMBackend):
    """Generate responses through an OpenAI-compatible chat backend."""

    def generate(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Send a normalized request to an OpenAI-compatible chat endpoint.

        Parameters:
            request: Normalized LLM request payload.

        Returns:
            Shared LLM result with text, usage, provider, and model.
        """
        url = self._build_url("/chat/completions")
        payload = {
            "model": request.get("model") or self.config.model,
            "messages": request["messages"],
        }
        if request.get("temperature") is not None:
            payload["temperature"] = request["temperature"]
        if request.get("max_tokens") is not None:
            payload["max_tokens"] = request["max_tokens"]

        response = self._request_json(
            "POST",
            url,
            payload,
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
        )

        choices = response.get("choices") or []
        if not choices:
            raise LLMRequestError(
                f"Backend {self.config.alias} returned no choices."
            )

        message = choices[0].get("message", {})
        return {
            "text": self._join_text_blocks(message.get("content", "")),
            "usage": self._normalize_usage(response.get("usage")),
            "provider": self.config.provider,
            "model": response.get("model") or payload["model"],
        }
