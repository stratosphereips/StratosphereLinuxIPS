# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Anthropic backend mixin for the shared LLM module."""

from typing import Any

from modules.llm_proxy.llm_backend import LLMBackend


class MixinAnthropicBackend(LLMBackend):
    """Generate responses through the Anthropic messages API."""

    def generate(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Send a normalized request to the Anthropic messages endpoint.

        Parameters:
            request: Normalized LLM request payload.

        Returns:
            Shared LLM result with text, usage, provider, and model.
        """
        url = self._build_url("/v1/messages")
        system_parts = []
        messages = []
        for message in request["messages"]:
            role = message["role"]
            content = message["content"]
            if role == "system":
                system_parts.append(content)
                continue
            messages.append({"role": role, "content": content})

        payload = {
            "model": request.get("model") or self.config.model,
            "messages": messages,
            "max_tokens": request.get("max_tokens") or 1024,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        if request.get("temperature") is not None:
            payload["temperature"] = request["temperature"]

        response = self._request_json(
            "POST",
            url,
            payload,
            headers={
                "x-api-key": self.config.api_key,
                "anthropic-version": self.config.anthropic_version,
                "Content-Type": "application/json",
            },
        )

        content = response.get("content") or []
        return {
            "text": self._join_text_blocks(content),
            "usage": self._normalize_usage(response.get("usage")),
            "provider": self.config.provider,
            "model": response.get("model") or payload["model"],
        }
