# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import json
import logging
from unittest.mock import Mock, patch

import pytest
import urllib3

from modules.llm_proxy.llm_backend_config import LLMBackendConfig
from modules.llm_proxy.llm_errors import LLMRequestError
from modules.supported_module_names import Modules
from tests.module_factory import ModuleFactory


def test_prepare_request_uses_default_backend_and_prompt():
    llm = ModuleFactory().create_llm_obj()

    request = llm._prepare_request(
        {"request_id": "req-1", "prompt": "summarize this"}
    )

    assert request["backend"] == "local_qwen"
    assert request["messages"] == [
        {"role": "user", "content": "summarize this"}
    ]


def test_get_available_backends_registry_has_runtime_ready_backends():
    llm = ModuleFactory().create_llm_obj()

    assert llm._get_available_backends_registry() == {
        "default_backend": "local_qwen",
        "backends": {
            "local_qwen": {
                "provider": "ollama",
                "model": "qwen2.5:3b",
            }
        },
    }


def test_get_available_backends_registry_blanks_invalid_default():
    llm = ModuleFactory().create_llm_obj()
    llm.default_backend = "missing_backend"

    assert llm._get_available_backends_registry() == {
        "default_backend": "",
        "backends": {
            "local_qwen": {
                "provider": "ollama",
                "model": "qwen2.5:3b",
            }
        },
    }


def test_pre_main_publishes_runtime_ready_registry():
    llm = ModuleFactory().create_llm_obj()

    llm.pre_main()

    llm.db.reset_pending_llm_request_counts.assert_called_once()
    llm.db.set_available_llm_backends.assert_called_once_with(
        {
            "default_backend": "local_qwen",
            "backends": {
                "local_qwen": {
                    "provider": "ollama",
                    "model": "qwen2.5:3b",
                }
            },
        }
    )


def test_pre_main_publishes_empty_registry_when_disabled():
    llm = ModuleFactory().create_llm_obj()
    llm.enabled = False

    assert llm.pre_main() is True
    llm.db.reset_pending_llm_request_counts.assert_called_once()
    llm.db.set_available_llm_backends.assert_called_once_with(
        {
            "default_backend": "",
            "backends": {},
        }
    )


def test_pre_main_publishes_empty_registry_when_no_valid_backends():
    llm = ModuleFactory().create_llm_obj()
    llm.backends = {}

    assert llm.pre_main() is True
    llm.db.reset_pending_llm_request_counts.assert_called_once()
    llm.db.set_available_llm_backends.assert_called_once_with(
        {
            "default_backend": "",
            "backends": {},
        }
    )


def test_handle_request_publishes_success_response():
    llm = ModuleFactory().create_llm_obj()
    llm.backends = {
        "local_qwen": Mock(
            generate=Mock(
                return_value={
                    "text": "analysis result",
                    "usage": {
                        "input_tokens": 10,
                        "output_tokens": 5,
                        "total_tokens": 15,
                    },
                    "provider": "ollama",
                    "model": "qwen2.5:3b",
                }
            )
        )
    }

    llm._handle_request(
        {
            "request_id": "req-2",
            "requester": "HTTP Analyzer",
            "prompt": "analyze this flow",
            "metadata": {"uid": "C1"},
        }
    )

    channel, payload = llm.db.publish.call_args.args
    response = json.loads(payload)
    assert channel == "llm_response"
    assert response["success"] is True
    assert response["request_id"] == "req-2"
    assert response["text"] == "analysis result"
    assert response["metadata"] == {"uid": "C1"}
    llm.db.decrement_pending_llm_request_count.assert_called_once_with(
        "HTTP Analyzer"
    )


def test_handle_request_publishes_error_for_unknown_backend():
    llm = ModuleFactory().create_llm_obj()

    llm._handle_request(
        {
            "request_id": "req-3",
            "backend": "missing_backend",
            "prompt": "hello",
        }
    )

    channel, payload = llm.db.publish.call_args.args
    response = json.loads(payload)
    assert channel == "llm_response"
    assert response["success"] is False
    assert "Unknown LLM backend" in response["error"]
    llm.db.decrement_pending_llm_request_count.assert_called_once_with("")


def test_handle_request_stops_llm_stack_when_default_backend_hits_max_retries():
    llm = ModuleFactory().create_llm_obj()
    request_error = LLMRequestError("local_qwen request failed")
    request_error.__cause__ = urllib3.exceptions.MaxRetryError(
        None,
        "http://127.0.0.1:11434/api/chat",
        reason=OSError("connection refused"),
    )
    llm.backends = {
        "local_qwen": Mock(generate=Mock(side_effect=request_error))
    }
    llm.db.get_pid_of.side_effect = lambda module_name: {
        Modules.ALERT_SUMMARY: 101,
        Modules.REGEX_GENERATOR: 202,
        Modules.T_CELL: 303,
    }.get(module_name)
    llm.print = Mock()

    llm._handle_request(
        {
            "request_id": "req-default-max-retries",
            "prompt": "summarize this",
        }
    )

    assert llm.worker_stop_event.is_set() is False
    llm.print.assert_not_called()

    channel, payload = llm.db.publish.call_args.args
    response = json.loads(payload)
    assert channel == "llm_response"
    assert response["success"] is False
    assert response["backend"] is None
    assert response["error"] == "local_qwen request failed"


def test_handle_request_does_not_stop_llm_stack_for_non_default_backend_failure():
    llm = ModuleFactory().create_llm_obj()
    request_error = LLMRequestError("fallback_backend request failed")
    request_error.__cause__ = urllib3.exceptions.MaxRetryError(
        None,
        "http://127.0.0.1:11434/api/chat",
        reason=OSError("connection refused"),
    )
    llm.backends = {
        "fallback_backend": Mock(generate=Mock(side_effect=request_error))
    }
    llm.print = Mock()

    llm._handle_request(
        {
            "request_id": "req-non-default-max-retries",
            "backend": "fallback_backend",
            "prompt": "summarize this",
        }
    )

    assert llm.worker_stop_event.is_set() is False
    llm.print.assert_not_called()
    channel, payload = llm.db.publish.call_args.args
    response = json.loads(payload)
    assert channel == "llm_response"
    assert response["success"] is False
    assert response["backend"] == "fallback_backend"
    assert response["error"] == "fallback_backend request failed"


def test_enqueue_request_increments_requester_pending_count():
    llm = ModuleFactory().create_llm_obj()

    llm._enqueue_request(
        {
            "data": json.dumps(
                {
                    "request_id": "req-enqueue",
                    "requester": "alert_summary",
                    "prompt": "hello",
                }
            )
        }
    )

    llm.db.increment_pending_llm_request_count.assert_called_once_with(
        "alert_summary"
    )


def test_llm_backend_pool_size_scales_with_worker_threads():
    llm = ModuleFactory().create_llm_obj()
    llm.worker_threads = 3
    config = LLMBackendConfig.from_dict(
        "local_qwen",
        {
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "base_url": "http://127.0.0.1:11434",
        },
    )

    with patch(
        "modules.llm_proxy.llm_backend.urllib3.PoolManager"
    ) as mock_pool:
        llm._create_backend(config)

    assert mock_pool.call_args.kwargs["maxsize"] == 6


def test_init_suppresses_urllib3_connectionpool_warnings():
    llm = ModuleFactory().create_llm_obj()
    logger = logging.getLogger("urllib3.connectionpool")
    original_level = logger.level

    try:
        llm.init()
        assert logger.level == logging.ERROR
    finally:
        logger.setLevel(original_level)


@pytest.mark.parametrize(
    ("termination_requested", "msg_received", "expected"),
    [
        (False, False, False),
        (True, True, False),
        (True, False, True),
    ],
)
def test_should_stop_uses_base_module_stop_conditions(
    termination_requested,
    msg_received,
    expected,
):
    llm = ModuleFactory().create_llm_obj()
    llm.termination_event.is_set.return_value = termination_requested
    llm.channel_tracker = {
        "llm_request": {
            "msg_received": msg_received,
        }
    }

    assert llm.should_stop() is expected


def test_shutdown_gracefully_clears_available_backend_registry():
    llm = ModuleFactory().create_llm_obj()

    assert llm.shutdown_gracefully() is True
    llm.db.reset_pending_llm_request_counts.assert_called_once()
    llm.db.set_available_llm_backends.assert_called_once_with(
        {
            "default_backend": "",
            "backends": {},
        }
    )


def test_main_returns_none_when_no_llm_request_message():
    llm = ModuleFactory().create_llm_obj()
    llm.get_msg = Mock(return_value=None)

    assert llm.main() is None


def test_pre_main_creates_module_specific_llm_log(tmp_path, mocker):
    llm = ModuleFactory().create_llm_obj()
    llm.parent_output_dir = str(tmp_path)
    llm.output_dir = str(tmp_path / llm.name)
    llm.operation_log_path = llm.get_module_specific_output_path(
        "llm_proxy.log"
    )
    mocker.patch(
        "modules.llm_proxy.llm_proxy.utils.drop_root_privs_permanently"
    )

    llm.pre_main()
    llm.shutdown_gracefully()

    with open(llm.operation_log_path, "r", encoding="utf-8") as handle:
        content = handle.read()

    assert "LLM module ready." in content
    assert "LLM module stopped." in content
