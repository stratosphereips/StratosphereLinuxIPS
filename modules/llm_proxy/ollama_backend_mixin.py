# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Ollama backend mixin for the shared LLM module."""

from typing import Any

from modules.llm_proxy.llm_backend import LLMBackend


class MixinOllamaBackend(LLMBackend):
    """Generate responses through the Ollama chat API."""

    def generate(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Send a normalized request to the Ollama chat endpoint.

        Parameters:
            request: Normalized LLM request payload.

        Returns:
            Shared LLM result with text, usage, provider, and model.
        """
        url = self._build_url("/api/chat")
        payload = {
            "model": request.get("model") or self.config.model,
            "messages": request["messages"],
            "stream": False,
        }
        options = {}
        if request.get("temperature") is not None:
            options["temperature"] = request["temperature"]
        if request.get("max_tokens") is not None:
            options["num_predict"] = request["max_tokens"]
        if options:
            payload["options"] = options

        response = self._request_json("POST", url, payload)
        message = response.get("message", {})
        usage = {
            "prompt_tokens": response.get("prompt_eval_count"),
            "completion_tokens": response.get("eval_count"),
            "total_tokens": None,
        }
        if (
            usage["prompt_tokens"] is not None
            and usage["completion_tokens"] is not None
        ):
            usage["total_tokens"] = (
                usage["prompt_tokens"] + usage["completion_tokens"]
            )
        return {
            "text": self._join_text_blocks(message.get("content", "")),
            "usage": self._normalize_usage(usage),
            "provider": self.config.provider,
            "model": response.get("model") or payload["model"],
        }
