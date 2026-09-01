from modules.llm_proxy.llm_proxy import LLMProxy
from tests.module_factory import ModuleFactory


def test_llm_proxy_module_instantiates_llm_proxy() -> None:
    llm_proxy = ModuleFactory().create_llm_obj()

    assert isinstance(llm_proxy, LLMProxy)
