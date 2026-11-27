from modules.llm_proxy.llm_proxy import LLMProxy
from tests.module_factory import ModuleFactory
from unittest.mock import Mock
import json
from pathlib import Path

from modules.llm_proxy.response_cache import LLMResponseCache, response_cache_path


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


def test_identical_opt_in_requests_reuse_persistent_response(
    tmp_path: Path,
) -> None:
    """Skip model inference for an identical prompt, including after cache reopen.

    Parameters:
        tmp_path: Isolated permanent directory.
    """
    llm_proxy = ModuleFactory().create_llm_obj()
    llm_proxy.response_cache = LLMResponseCache(response_cache_path(tmp_path))
    llm_proxy._log_operation = Mock()
    llm_proxy._publish_response = Mock()
    backend = llm_proxy.backends["local_qwen"]
    backend.generate = Mock(return_value={
        "provider": "ollama", "model": "qwen2.5:3b",
        "text": "One observed event.", "usage": {"total_tokens": 10},
    })
    payload = {
        "request_id": "first", "requester": "web_explain",
        "backend": "local_qwen", "cache": True,
        "messages": [{"role": "user", "content": "Observed event"}],
        "metadata": {"cache_key": "a" * 64},
    }
    llm_proxy._handle_request(payload)
    llm_proxy.response_cache = LLMResponseCache(
        response_cache_path(tmp_path), create=False
    )
    llm_proxy._handle_request({**payload, "request_id": "second"})

    backend.generate.assert_called_once()
    reply = llm_proxy._publish_response.call_args.args[0]
    assert reply["request_id"] == "second"
    assert reply["cached"] is True
    assert reply["usage"] == {}
    assert reply["text"] == "One observed event."


def test_uncached_requests_still_generate_new_responses(tmp_path: Path) -> None:
    """Keep regex and other non-opt-in requests fresh.

    Parameters:
        tmp_path: Isolated permanent directory.
    """
    llm_proxy = ModuleFactory().create_llm_obj()
    llm_proxy.response_cache = LLMResponseCache(response_cache_path(tmp_path))
    llm_proxy._log_operation = Mock()
    llm_proxy._publish_response = Mock()
    backend = llm_proxy.backends["local_qwen"]
    backend.generate = Mock(return_value={
        "provider": "ollama", "model": "qwen2.5:3b",
        "text": "Pattern", "usage": {},
    })
    payload = {
        "request_id": "first", "requester": "regex_generator",
        "backend": "local_qwen", "messages": [
            {"role": "user", "content": "Generate regex"}
        ],
    }
    llm_proxy._handle_request(payload)
    llm_proxy._handle_request({**payload, "request_id": "second"})

    assert backend.generate.call_count == 2


def test_empty_response_is_not_cached(tmp_path: Path) -> None:
    """Retry an empty model response on the next identical request.

    Parameters:
        tmp_path: Isolated permanent directory.
    """
    llm_proxy = ModuleFactory().create_llm_obj()
    llm_proxy.response_cache = LLMResponseCache(response_cache_path(tmp_path))
    llm_proxy._log_operation = Mock()
    llm_proxy._publish_response = Mock()
    backend = llm_proxy.backends["local_qwen"]
    backend.generate = Mock(return_value={
        "provider": "ollama", "model": "qwen2.5:3b",
        "text": "", "usage": {},
    })
    payload = {
        "request_id": "first", "requester": "alert_summary",
        "backend": "local_qwen", "cache": True,
        "messages": [{"role": "user", "content": "Observed event"}],
    }
    llm_proxy._handle_request(payload)
    llm_proxy._handle_request({**payload, "request_id": "second"})

    assert backend.generate.call_count == 2
