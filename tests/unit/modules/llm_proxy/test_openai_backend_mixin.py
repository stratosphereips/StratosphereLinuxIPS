from modules.llm_proxy.openai_backend_mixin import MixinOpenAIBackend
from tests.module_factory import ModuleFactory


def test_openai_backend_mixin_exposes_generate_method() -> None:
    llm_proxy = ModuleFactory().create_llm_obj()

    assert llm_proxy is not None
    assert hasattr(MixinOpenAIBackend, "generate")
