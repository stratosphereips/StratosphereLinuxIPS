# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from unittest.mock import Mock

import pytest

from modules.llm_proxy.llm_backend_config import LLMBackendConfig
from modules.llm_proxy.llm_errors import LLMRequestError
from modules.llm_proxy.openai_backend_mixin import MixinOpenAIBackend
from tests.module_factory import ModuleFactory


def test_openai_backend_mixin_parses_chat_completion_response() -> None:
    llm = ModuleFactory().create_llm_obj()
    config = LLMBackendConfig.from_dict(
        "openai_default",
        {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "api_key": "secret",
        },
    )
    backend = MixinOpenAIBackend(config)
    backend._request_json = Mock(
        return_value={
            "model": "gpt-4o-mini",
            "choices": [
                {
                    "message": {
                        "content": "final answer",
                    }
                }
            ],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 7,
                "total_tokens": 19,
            },
        }
    )

    response = backend.generate(
        {
            "messages": [{"role": "user", "content": "Hello"}],
            "model": None,
            "temperature": None,
            "max_tokens": None,
        }
    )

    assert llm.name == "llm_proxy"
    assert response["text"] == "final answer"
    assert response["usage"]["total_tokens"] == 19


def test_openai_backend_mixin_rejects_empty_choices() -> None:
    llm = ModuleFactory().create_llm_obj()
    config = LLMBackendConfig.from_dict(
        "openai_default",
        {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "api_key": "secret",
        },
    )
    backend = MixinOpenAIBackend(config)
    backend._request_json = Mock(
        return_value={"model": "gpt-4o-mini", "choices": []}
    )

    with pytest.raises(LLMRequestError, match="returned no choices"):
        backend.generate(
            {
                "messages": [{"role": "user", "content": "Hello"}],
                "model": None,
                "temperature": None,
                "max_tokens": None,
            }
        )

    assert llm.name == "llm_proxy"
