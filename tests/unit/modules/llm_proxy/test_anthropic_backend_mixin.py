from modules.llm_proxy.anthropic_backend_mixin import MixinAnthropicBackend
from tests.module_factory import ModuleFactory


def test_anthropic_backend_mixin_exposes_generate_method() -> None:
    llm_proxy = ModuleFactory().create_llm_obj()

    assert llm_proxy is not None
    assert hasattr(MixinAnthropicBackend, "generate")
