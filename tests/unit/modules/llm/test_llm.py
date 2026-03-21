# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import json
from unittest.mock import Mock, patch

from modules.llm.llm import (
    AnthropicBackend,
    LLMBackendConfig,
    OllamaBackend,
    OpenAIBackend,
)
from tests.module_factory import ModuleFactory


def test_backend_config_reads_api_key_from_env(mocker):
    mocker.patch.dict("os.environ", {"OPENAI_API_KEY": "secret-key"})

    config = LLMBackendConfig.from_dict(
        "openai_default",
        {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "api_key_env": "OPENAI_API_KEY",
        },
    )

    assert config.api_key == "secret-key"
    assert config.base_url == "https://api.openai.com/v1"


def test_prepare_request_uses_default_backend_and_prompt():
    llm = ModuleFactory().create_llm_obj()

    request = llm._prepare_request(
        {"request_id": "req-1", "prompt": "summarize this"}
    )

    assert request["backend"] == "local_qwen"
    assert request["messages"] == [
        {"role": "user", "content": "summarize this"}
    ]


def test_get_available_backends_registry_has_runtime_ready_backends():
    llm = ModuleFactory().create_llm_obj()

    assert llm._get_available_backends_registry() == {
        "default_backend": "local_qwen",
        "backends": {
            "local_qwen": {
                "provider": "ollama",
                "model": "qwen2.5:3b",
            }
        },
    }


def test_get_available_backends_registry_blanks_invalid_default():
    llm = ModuleFactory().create_llm_obj()
    llm.default_backend = "missing_backend"

    assert llm._get_available_backends_registry() == {
        "default_backend": "",
        "backends": {
            "local_qwen": {
                "provider": "ollama",
                "model": "qwen2.5:3b",
            }
        },
    }


def test_pre_main_publishes_runtime_ready_registry():
    llm = ModuleFactory().create_llm_obj()

    llm.pre_main()

    llm.db.set_available_llm_backends.assert_called_once_with(
        {
            "default_backend": "local_qwen",
            "backends": {
                "local_qwen": {
                    "provider": "ollama",
                    "model": "qwen2.5:3b",
                }
            },
        }
    )


def test_pre_main_publishes_empty_registry_when_disabled():
    llm = ModuleFactory().create_llm_obj()
    llm.enabled = False

    assert llm.pre_main() is True
    llm.db.set_available_llm_backends.assert_called_once_with(
        {
            "default_backend": "",
            "backends": {},
        }
    )


def test_pre_main_publishes_empty_registry_when_no_valid_backends():
    llm = ModuleFactory().create_llm_obj()
    llm.backends = {}

    assert llm.pre_main() is True
    llm.db.set_available_llm_backends.assert_called_once_with(
        {
            "default_backend": "",
            "backends": {},
        }
    )


def test_handle_request_publishes_success_response():
    llm = ModuleFactory().create_llm_obj()
    llm.backends = {
        "local_qwen": Mock(
            generate=Mock(
                return_value={
                    "text": "analysis result",
                    "usage": {
                        "input_tokens": 10,
                        "output_tokens": 5,
                        "total_tokens": 15,
                    },
                    "provider": "ollama",
                    "model": "qwen2.5:3b",
                }
            )
        )
    }

    llm._handle_request(
        {
            "request_id": "req-2",
            "requester": "HTTP Analyzer",
            "prompt": "analyze this flow",
            "metadata": {"uid": "C1"},
        }
    )

    channel, payload = llm.db.publish.call_args.args
    response = json.loads(payload)
    assert channel == "llm_response"
    assert response["success"] is True
    assert response["request_id"] == "req-2"
    assert response["text"] == "analysis result"
    assert response["metadata"] == {"uid": "C1"}


def test_handle_request_publishes_error_for_unknown_backend():
    llm = ModuleFactory().create_llm_obj()

    llm._handle_request(
        {
            "request_id": "req-3",
            "backend": "missing_backend",
            "prompt": "hello",
        }
    )

    channel, payload = llm.db.publish.call_args.args
    response = json.loads(payload)
    assert channel == "llm_response"
    assert response["success"] is False
    assert "Unknown LLM backend" in response["error"]


def test_openai_backend_parses_chat_completion_response():
    config = LLMBackendConfig.from_dict(
        "openai_default",
        {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "api_key": "secret",
        },
    )
    backend = OpenAIBackend(config)
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

    assert response["text"] == "final answer"
    assert response["usage"]["total_tokens"] == 19


def test_anthropic_backend_moves_system_messages():
    config = LLMBackendConfig.from_dict(
        "claude_default",
        {
            "provider": "anthropic",
            "model": "claude-sonnet-4-5",
            "api_key": "secret",
        },
    )
    backend = AnthropicBackend(config)
    with patch.object(backend, "_request_json") as mock_request:
        mock_request.return_value = {
            "model": "claude-sonnet-4-5",
            "content": [{"type": "text", "text": "anthropic answer"}],
            "usage": {"input_tokens": 3, "output_tokens": 4},
        }
        response = backend.generate(
            {
                "messages": [
                    {"role": "system", "content": "be terse"},
                    {"role": "user", "content": "hello"},
                ],
                "model": None,
                "temperature": 0.2,
                "max_tokens": 128,
            }
        )

    sent_payload = mock_request.call_args.args[2]
    assert sent_payload["system"] == "be terse"
    assert sent_payload["messages"] == [{"role": "user", "content": "hello"}]
    assert response["text"] == "anthropic answer"


def test_ollama_backend_parses_response():
    config = LLMBackendConfig.from_dict(
        "local_qwen",
        {
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "base_url": "http://127.0.0.1:11434",
        },
    )
    backend = OllamaBackend(config)
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

    assert response["text"] == "ollama answer"
    assert response["usage"]["input_tokens"] == 9
    assert response["usage"]["output_tokens"] == 11
    assert response["usage"]["total_tokens"] == 20


def test_llm_backend_pool_size_scales_with_worker_threads():
    llm = ModuleFactory().create_llm_obj()
    llm.worker_threads = 3
    config = LLMBackendConfig.from_dict(
        "local_qwen",
        {
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "base_url": "http://127.0.0.1:11434",
        },
    )

    with patch("modules.llm.llm.urllib3.PoolManager") as mock_pool:
        llm._create_backend(config)

    assert mock_pool.call_args.kwargs["maxsize"] == 6
