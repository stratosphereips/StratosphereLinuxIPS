"""Checks for the persistent LLM response cache."""

from pathlib import Path

from modules.llm_proxy.llm_backend_config import LLMBackendConfig
from modules.llm_proxy.response_cache import (
    LLMResponseCache,
    response_cache_path,
)
from tests.module_factory import ModuleFactory


def test_response_cache_survives_reopen_and_indexes_web_digest(
    tmp_path: Path,
) -> None:
    """Reuse an explanation after reopening the persistent database.

    Parameters:
        tmp_path: Isolated permanent directory.
    """
    _factory = ModuleFactory()
    path = response_cache_path(tmp_path)
    cache = LLMResponseCache(path)
    backend = LLMBackendConfig(
        alias="local", provider="llama_cpp", model="summary-model",
        base_url="http://127.0.0.1:8080/v1", timeout=60,
    )
    request = {
        "backend": "local", "messages": [{"role": "user", "content": "event"}],
        "temperature": 0, "max_tokens": 100,
    }
    key = cache.key(request, backend)
    cache.put(key, {
        "text": "Observed one event.", "provider": "llama_cpp",
        "model": "summary-model", "backend": "local",
    }, "a" * 64)

    reopened = LLMResponseCache(path, create=False)
    assert reopened.get(key)["text"] == "Observed one event."
    assert reopened.get_web("a" * 64)["text"] == "Observed one event."
    assert reopened.get_web("b" * 64) is None
    assert path.stat().st_mode & 0o777 == 0o600


def test_response_cache_key_changes_with_prompt_or_model(tmp_path: Path) -> None:
    """Keep different source data and model choices separate.

    Parameters:
        tmp_path: Isolated permanent directory.
    """
    _factory = ModuleFactory()
    cache = LLMResponseCache(response_cache_path(tmp_path))
    backend = LLMBackendConfig(
        alias="local", provider="llama_cpp", model="summary-model",
        base_url="http://127.0.0.1:8080/v1", timeout=60,
    )
    request = {
        "backend": "local", "messages": [{"role": "user", "content": "event"}],
        "temperature": 0, "max_tokens": 100,
    }
    original = cache.key(request, backend)
    assert original == cache.key({**request, "request_id": "another"}, backend)
    assert original != cache.key({**request, "model": "other-model"}, backend)
    assert original != cache.key({**request, "max_tokens": 200}, backend)
    changed = {**request, "messages": [{"role": "user", "content": "new event"}]}
    assert original != cache.key(changed, backend)
