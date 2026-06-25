# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from unittest.mock import Mock

from modules.llm_proxy.llm_backend_config import LLMBackendConfig
from modules.llm_proxy.ollama_backend_mixin import MixinOllamaBackend
from tests.module_factory import ModuleFactory


def test_ollama_backend_mixin_parses_response() -> None:
    llm = ModuleFactory().create_llm_obj()
    config = LLMBackendConfig.from_dict(
        "local_qwen",
        {
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "base_url": "http://127.0.0.1:11434",
        },
    )
    backend = MixinOllamaBackend(config)
    backend._request_json = Mock(
        return_value={
            "model": "qwen2.5:3b",
            "message": {"content": "ollama answer"},
            "prompt_eval_count": 9,
            "eval_count": 11,
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

    assert llm.name == "LLM"
    assert response["text"] == "ollama answer"
    assert response["usage"]["input_tokens"] == 9
    assert response["usage"]["output_tokens"] == 11
    assert response["usage"]["total_tokens"] == 20
