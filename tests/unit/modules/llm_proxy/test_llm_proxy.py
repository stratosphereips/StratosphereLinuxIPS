from modules.llm_proxy.llm_proxy import LLMProxy
from tests.module_factory import ModuleFactory
from unittest.mock import Mock
import json


def test_llm_proxy_module_instantiates_llm_proxy() -> None:
    llm_proxy = ModuleFactory().create_llm_obj()

    assert isinstance(llm_proxy, LLMProxy)


def test_web_explanation_response_expires_and_clears_pending() -> None:
    """Persist only web explanation replies with a bounded TTL."""
    llm_proxy = ModuleFactory().create_llm_obj()
    llm_proxy.db = Mock()
    llm_proxy._log_operation = Mock()
    digest = "a" * 64
    llm_proxy._publish_response({
        "requester": "web_explain", "request_id": "request-1",
        "metadata": {"cache_key": digest}, "success": True,
        "text": "Observed a connection.", "backend": "local",
    })
    args = llm_proxy.db.rdb.r.setex.call_args.args
    assert args[:2] == (f"web:explain:result:{digest}", 7 * 86400)
    assert json.loads(args[2])["text"] == "Observed a connection."
    llm_proxy.db.rdb.r.delete.assert_called_once_with(
        f"web:explain:pending:{digest}")
    llm_proxy.db.publish.assert_called_once()
