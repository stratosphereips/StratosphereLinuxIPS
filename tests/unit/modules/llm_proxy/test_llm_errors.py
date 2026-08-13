from modules.llm_proxy.llm_errors import (
    LLMConfigurationError,
    LLMRequestError,
)
from tests.module_factory import ModuleFactory


def test_llm_error_classes_are_exceptions() -> None:
    llm_proxy = ModuleFactory().create_llm_obj()

    assert llm_proxy is not None
    assert issubclass(LLMConfigurationError, Exception)
    assert issubclass(LLMRequestError, Exception)
