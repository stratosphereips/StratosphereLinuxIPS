from modules.llm_proxy.ollama_backend_mixin import MixinOllamaBackend
from tests.module_factory import ModuleFactory


def test_ollama_backend_mixin_exposes_generate_method() -> None:
    llm_proxy = ModuleFactory().create_llm_obj()

    assert llm_proxy is not None
    assert hasattr(MixinOllamaBackend, "generate")
