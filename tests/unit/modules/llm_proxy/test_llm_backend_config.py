from modules.llm_proxy.llm_backend_config import LLMBackendConfig
from tests.module_factory import ModuleFactory


def test_llm_backend_config_builds_defaults_for_ollama() -> None:
    llm_proxy = ModuleFactory().create_llm_obj()
    backend_config = LLMBackendConfig.from_dict(
        "local_qwen",
        {"provider": "ollama", "model": "qwen2.5:3b"},
    )

    assert llm_proxy is not None
    assert backend_config.base_url == "http://127.0.0.1:11434"
