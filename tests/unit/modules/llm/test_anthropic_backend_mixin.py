# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from unittest.mock import patch

from modules.llm_proxy.anthropic_backend_mixin import MixinAnthropicBackend
from modules.llm_proxy.llm_backend_config import LLMBackendConfig
from tests.module_factory import ModuleFactory


def test_anthropic_backend_mixin_moves_system_messages() -> None:
    llm = ModuleFactory().create_llm_obj()
    config = LLMBackendConfig.from_dict(
        "claude_default",
        {
            "provider": "anthropic",
            "model": "claude-sonnet-4-5",
            "api_key": "secret",
        },
    )
    backend = MixinAnthropicBackend(config)
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
    assert llm.name == "llm_proxy"
    assert sent_payload["system"] == "be terse"
    assert sent_payload["messages"] == [{"role": "user", "content": "hello"}]
    assert response["text"] == "anthropic answer"
