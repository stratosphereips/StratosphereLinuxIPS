import pytest

from modules.llm_proxy.llm_backend_config import LLMBackendConfig
from modules.llm_proxy.llm_errors import LLMConfigurationError
from tests.module_factory import ModuleFactory


def test_llm_backend_config_builds_defaults_for_ollama() -> None:
    llm_proxy = ModuleFactory().create_llm_obj()
    backend_config = LLMBackendConfig.from_dict(
        "local_qwen",
        {"provider": "ollama", "model": "qwen2.5:3b"},
    )

    assert llm_proxy is not None
    assert backend_config.base_url == "http://127.0.0.1:11434"


def test_llama_cpp_backend_uses_local_endpoint_without_api_key() -> None:
    llm_proxy = ModuleFactory().create_llm_obj()
    backend_config = LLMBackendConfig.from_dict(
        "slips_summary_q4",
        {"provider": "llama_cpp", "model": "slips-summary-q4"},
    )

    assert llm_proxy._create_backend(backend_config).config == backend_config
    assert backend_config.base_url == "http://127.0.0.1:8080/v1"
    assert backend_config.api_key is None


@pytest.mark.parametrize("base_url", [
    "http://example.com:8080/v1",
    "https://127.0.0.1:8080/v1",
    "http://localhost.evil.test:8080/v1",
])
def test_llama_cpp_rejects_nonlocal_endpoint(base_url: str) -> None:
    llm_proxy = ModuleFactory().create_llm_obj()

    assert llm_proxy is not None
    with pytest.raises(LLMConfigurationError):
        LLMBackendConfig.from_dict("summary", {
            "provider": "llama_cpp",
            "model": "slips-summary-q4",
            "base_url": base_url,
        })
