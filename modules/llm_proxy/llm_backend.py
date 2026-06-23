# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Base HTTP backend for shared LLM providers."""

import json
from typing import Any

import certifi
import urllib3

from modules.llm.llm_backend_config import LLMBackendConfig
from modules.llm.llm_errors import LLMRequestError


class LLMBackend:
    """Common HTTP and response helpers for LLM provider implementations."""

    def __init__(
        self,
        config: LLMBackendConfig,
        pool_maxsize: int = 2,
    ) -> None:
        """
        Initialize a backend with a validated config and HTTP pool.

        Parameters:
            config: Validated backend configuration.
            pool_maxsize: Maximum connections kept in the HTTP pool.

        Returns:
            None.
        """
        self.config = config
        self.http = urllib3.PoolManager(
            cert_reqs="CERT_REQUIRED",
            ca_certs=certifi.where(),
            maxsize=max(2, int(pool_maxsize)),
        )

    def generate(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Generate a response for a normalized LLM request.

        Parameters:
            request: Normalized request payload.

        Returns:
            Provider response converted to the shared result shape.
        """
        raise NotImplementedError

    def _request_json(
        self,
        method: str,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """
        Send a JSON request and decode the JSON response.

        Parameters:
            method: HTTP method to use.
            url: Backend URL to call.
            payload: JSON-serializable request body.
            headers: Optional HTTP headers.

        Returns:
            Decoded JSON response body.
        """
        encoded_payload = json.dumps(payload).encode()
        try:
            response = self.http.request(
                method,
                url,
                body=encoded_payload,
                headers=headers or {"Content-Type": "application/json"},
                timeout=urllib3.Timeout(
                    connect=self.config.timeout,
                    read=self.config.timeout,
                ),
            )
        except urllib3.exceptions.HTTPError as exc:
            raise LLMRequestError(
                f"{self.config.alias} request failed: {exc}"
            ) from exc
        except OSError as exc:
            raise LLMRequestError(
                f"{self.config.alias} request failed: {exc}"
            ) from exc

        try:
            decoded = response.data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LLMRequestError(f"Invalid backend response: {exc}") from exc

        if response.status >= 400:
            raise LLMRequestError(
                f"{self.config.alias} returned HTTP {response.status}: "
                f"{decoded[:500]}"
            )

        try:
            return json.loads(decoded)
        except json.JSONDecodeError as exc:
            raise LLMRequestError(
                f"Backend {self.config.alias} returned invalid JSON."
            ) from exc

    def _build_url(self, endpoint: str) -> str:
        """
        Build a provider URL from the configured base URL and endpoint.

        Parameters:
            endpoint: Provider endpoint path.

        Returns:
            Full URL for the backend request.
        """
        base_url = self.config.base_url.rstrip("/")
        if endpoint.startswith("/v1/") and base_url.endswith("/v1"):
            endpoint = endpoint[3:]
        return f"{base_url}{endpoint}"

    @staticmethod
    def _normalize_usage(usage: dict[str, Any] | None) -> dict[str, Any]:
        """
        Convert provider usage counters to the shared token keys.

        Parameters:
            usage: Provider usage payload.

        Returns:
            Normalized usage mapping.
        """
        usage = usage or {}
        return {
            "input_tokens": usage.get("prompt_tokens")
            or usage.get("input_tokens"),
            "output_tokens": usage.get("completion_tokens")
            or usage.get("output_tokens"),
            "total_tokens": usage.get("total_tokens"),
        }

    @staticmethod
    def _join_text_blocks(content: Any) -> str:
        """
        Convert provider text blocks into one text string.

        Parameters:
            content: Provider message content.

        Returns:
            Joined response text.
        """
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            text_parts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    text_parts.append(str(item.get("text", "")))
            return "".join(text_parts)
        return str(content or "")
