# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from unittest.mock import Mock

import urllib3

from modules.llm_proxy.llm_backend import LLMBackend
from modules.llm_proxy.llm_backend_config import LLMBackendConfig
from tests.module_factory import ModuleFactory


def test_backend_request_json_uses_explicit_connect_and_read_timeouts() -> (
    None
):
    llm = ModuleFactory().create_llm_obj()
    config = LLMBackendConfig.from_dict(
        "local_qwen",
        {
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "base_url": "http://127.0.0.1:11434",
            "timeout": 42,
        },
    )
    backend = LLMBackend(config)
    backend.http = Mock()
    backend.http.request.return_value = Mock(
        status=200,
        data=b'{"message": {"content": "ok"}}',
    )

    backend._request_json("POST", "http://127.0.0.1:11434/api/chat", {})

    timeout = backend.http.request.call_args.kwargs["timeout"]
    assert llm.name == "llm_proxy"
    assert isinstance(timeout, urllib3.Timeout)
    assert timeout.connect_timeout == 42
    assert timeout.read_timeout == 42


def test_backend_build_url_avoids_duplicate_v1_prefix() -> None:
    llm = ModuleFactory().create_llm_obj()
    config = LLMBackendConfig.from_dict(
        "openai_default",
        {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "base_url": "https://api.openai.com/v1",
            "api_key": "secret",
        },
    )
    backend = LLMBackend(config)

    url = backend._build_url("/v1/messages")

    assert llm.name == "llm_proxy"
    assert url == "https://api.openai.com/v1/messages"
