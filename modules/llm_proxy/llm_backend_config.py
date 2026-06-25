# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Configuration object for shared LLM backend connections."""

import os
from dataclasses import dataclass
from typing import Any

from modules.llm_proxy.llm_errors import LLMConfigurationError


@dataclass
class LLMBackendConfig:
    """Validated configuration for one LLM backend alias."""

    alias: str
    provider: str
    model: str
    base_url: str
    timeout: int
    api_key: str | None = None
    anthropic_version: str = "2023-06-01"

    @classmethod
    def from_dict(cls, alias: str, data: dict[str, Any]) -> "LLMBackendConfig":
        """
        Build a backend configuration from raw config data.

        Parameters:
            alias: Backend alias from the Slips configuration.
            data: Raw backend configuration mapping.

        Returns:
            Validated LLM backend configuration.
        """
        if not isinstance(data, dict):
            raise LLMConfigurationError(f"Backend {alias} must be a mapping.")

        provider = str(data.get("provider", "")).strip().lower()
        if provider not in {"ollama", "openai", "anthropic"}:
            raise LLMConfigurationError(
                f"Backend {alias} has unsupported provider {provider!r}."
            )

        model = str(data.get("model", "")).strip()
        if not model:
            raise LLMConfigurationError(f"Backend {alias} is missing a model.")

        timeout = data.get("timeout", 60)
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            timeout = 60
        timeout = max(1, timeout)

        base_url = str(data.get("base_url", "")).strip()
        if not base_url:
            base_url = {
                "ollama": "http://127.0.0.1:11434",
                "openai": "https://api.openai.com/v1",
                "anthropic": "https://api.anthropic.com",
            }[provider]
        base_url = base_url.rstrip("/")

        api_key = cls._resolve_api_key(data)
        if provider in {"openai", "anthropic"} and not api_key:
            raise LLMConfigurationError(
                f"Backend {alias} requires an API key."
            )

        anthropic_version = str(
            data.get("anthropic_version", "2023-06-01")
        ).strip()

        return cls(
            alias=alias,
            provider=provider,
            model=model,
            base_url=base_url,
            timeout=timeout,
            api_key=api_key,
            anthropic_version=anthropic_version,
        )

    @staticmethod
    def _resolve_api_key(data: dict[str, Any]) -> str | None:
        """
        Resolve an API key from inline, environment, or file config.

        Parameters:
            data: Raw backend configuration mapping.

        Returns:
            API key string when one is configured and readable.
        """
        api_key = data.get("api_key")
        if isinstance(api_key, str) and api_key.strip():
            return api_key.strip()

        api_key_env = data.get("api_key_env")
        if isinstance(api_key_env, str) and api_key_env.strip():
            env_value = os.environ.get(api_key_env.strip(), "").strip()
            if env_value:
                return env_value

        api_key_file = data.get("api_key_file")
        if isinstance(api_key_file, str) and api_key_file.strip():
            try:
                with open(api_key_file.strip(), "r", encoding="utf-8") as f:
                    return f.read().strip() or None
            except OSError:
                return None

        return None
