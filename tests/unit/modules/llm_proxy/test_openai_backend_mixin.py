from modules.llm_proxy.openai_backend_mixin import MixinOpenAIBackend
from modules.llm_proxy.llm_backend_config import LLMBackendConfig
from tests.module_factory import ModuleFactory


def test_openai_backend_mixin_exposes_generate_method() -> None:
    llm_proxy = ModuleFactory().create_llm_obj()

    assert llm_proxy is not None
    assert hasattr(MixinOpenAIBackend, "generate")


def test_llama_cpp_request_has_no_authorization_header(mocker) -> None:
    llm_proxy = ModuleFactory().create_llm_obj()
    backend = llm_proxy._create_backend(LLMBackendConfig.from_dict(
        "summary", {"provider": "llama_cpp", "model": "slips-summary-q4"}
    ))
    request = mocker.patch.object(backend, "_request_json", return_value={
        "choices": [{"message": {"content": "Observed a scan."}}],
        "model": "slips-summary-q4",
    })

    assert backend.generate({"messages": [{"role": "user", "content": "test"}]})["text"] == "Observed a scan."
    assert request.call_args.kwargs["headers"] == {"Content-Type": "application/json"}
