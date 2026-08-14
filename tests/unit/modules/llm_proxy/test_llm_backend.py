from modules.llm_proxy.llm_backend import LLMBackend
from modules.llm_proxy.llm_backend_config import LLMBackendConfig
from tests.module_factory import ModuleFactory


def test_llm_backend_initializes_with_valid_config() -> None:
    llm_proxy = ModuleFactory().create_llm_obj()
    backend_config = LLMBackendConfig.from_dict(
        "local_qwen",
        {"provider": "ollama", "model": "qwen2.5:3b"},
    )
    backend = LLMBackend(backend_config)

    assert llm_proxy is not None
    assert backend.config.alias == "local_qwen"
