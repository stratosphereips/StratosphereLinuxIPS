# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from typing import Any

import pytest

from modules.llm_proxy.llm_backend_config import LLMBackendConfig
from modules.llm_proxy.llm_errors import LLMConfigurationError
from tests.module_factory import ModuleFactory


def test_backend_config_reads_api_key_from_env(mocker: Any) -> None:
    llm = ModuleFactory().create_llm_obj()
    mocker.patch.dict("os.environ", {"OPENAI_API_KEY": "secret-key"})

    config = LLMBackendConfig.from_dict(
        "openai_default",
        {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "api_key_env": "OPENAI_API_KEY",
        },
    )

    assert llm.name == "llm_proxy"
    assert config.api_key == "secret-key"
    assert config.base_url == "https://api.openai.com/v1"


@pytest.mark.parametrize(
    ("alias", "data", "expected_error"),
    [
        ("bad_backend", [], "must be a mapping"),
        (
            "bad_provider",
            {"provider": "invalid", "model": "model"},
            "unsupported provider",
        ),
        ("missing_model", {"provider": "ollama"}, "missing a model"),
    ],
)
def test_backend_config_rejects_invalid_config(
    alias: str,
    data: Any,
    expected_error: str,
) -> None:
    llm = ModuleFactory().create_llm_obj()

    with pytest.raises(LLMConfigurationError, match=expected_error):
        LLMBackendConfig.from_dict(alias, data)

    assert llm.name == "llm_proxy"
