# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import json
from unittest.mock import Mock, patch

from modules.llm_proxy.llm_backend_config import LLMBackendConfig
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


def test_should_stop_waits_for_pending_requests_during_shutdown():
    llm = ModuleFactory().create_llm_obj()
    llm.termination_event.is_set.return_value = True
    llm.request_queue.put_nowait({"request_id": "req-1"})

    assert llm.should_stop() is False


def test_should_stop_waits_for_shutdown_grace_period(mocker):
    llm = ModuleFactory().create_llm_obj()
    llm.termination_event.is_set.return_value = True
    llm.last_request_activity = 100

    mocker.patch("modules.llm_proxy.llm_proxy.time.time", return_value=104)
    assert llm.should_stop() is False

    mocker.patch("modules.llm_proxy.llm_proxy.time.time", return_value=105)
    assert llm.should_stop() is True


def test_should_stop_waits_for_upstream_modules_that_can_publish_late_requests(
    mocker,
):
    llm = ModuleFactory().create_llm_obj()
    llm.termination_event.is_set.return_value = True
    llm.last_request_activity = 100
    llm.db.get_pid_of.side_effect = lambda name: {
        "alert_summary": 12345,
        "evidence_handler": None,
    }.get(name)
    mocker.patch("modules.llm_proxy.llm_proxy.time.time", return_value=999)
    mocker.patch.object(llm, "_is_process_alive", return_value=True)

    assert llm.should_stop() is False


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
