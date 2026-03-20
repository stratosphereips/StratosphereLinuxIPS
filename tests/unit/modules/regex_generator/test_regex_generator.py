# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import re
import time
from unittest.mock import Mock

from modules.regex_generator.regex_generator import (
    PROMPT_VERSION,
    RegexGenerator,
    SYSTEM_PROMPT,
    TYPE_PROMPTS,
)
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.database.sqlite_db.regex_generator_db import (
    REGEX_TYPES,
    RegexGeneratorStorage,
)
from tests.module_factory import ModuleFactory


def _build_storage_conf(
    store_dir: str,
    persistent_store_dir: str = "",
    seed_benign_samples: bool = True,
    store_rejected_regexes: bool = False,
    max_stored_rejected_regexes: int = 10000,
    enable_local_whitelist: bool = True,
    local_whitelist_path: str = "config/whitelist.conf",
    tranco_top_benign_limit: int = 1000,
):
    conf = Mock()
    conf.regex_generator_store_dir = Mock(return_value=store_dir)
    conf.regex_generator_persistent_store_dir = Mock(
        return_value=persistent_store_dir
    )
    conf.regex_generator_seed_benign_samples = Mock(
        return_value=seed_benign_samples
    )
    conf.regex_generator_store_rejected_regexes = Mock(
        return_value=store_rejected_regexes
    )
    conf.regex_generator_max_stored_rejected_regexes = Mock(
        return_value=max_stored_rejected_regexes
    )
    conf.enable_local_whitelist = Mock(return_value=enable_local_whitelist)
    conf.local_whitelist_path = Mock(return_value=local_whitelist_path)
    conf.tranco_top_benign_limit = Mock(return_value=tranco_top_benign_limit)
    return conf


def test_regex_generator_config_defaults():
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {}

    assert parser.regex_generator_enabled() is False
    assert parser.regex_generator_create_log_file() is False
    assert parser.regex_generator_generation_interval_seconds() == 5
    assert parser.regex_generator_allowed_backends() == []
    assert parser.regex_generator_llm_temperature() == 1.2
    assert parser.regex_generator_llm_max_tokens() == 80
    assert parser.regex_generator_llm_response_timeout_seconds() == 90
    assert parser.regex_generator_recent_history_size() == 0
    assert parser.regex_generator_max_regex_length() == 180
    assert parser.regex_generator_regex_validation_timeout_seconds() == 2
    assert parser.regex_generator_benign_match_strength_threshold() == 75
    assert parser.regex_generator_store_dir() == "output/regex_generator"
    assert parser.regex_generator_persistent_store_dir() == ""
    assert parser.regex_generator_store_rejected_regexes() is False
    assert parser.regex_generator_max_stored_rejected_regexes() == 10000
    assert parser.regex_generator_seed_benign_samples() is True
    assert parser.tranco_top_benign_limit() == 1000


def test_regex_generator_config_sanitization():
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {
        "regex_generator": {
            "generation_interval_seconds": "bad",
            "create_log_file": "true",
            "allowed_backends": "local_qwen",
            "llm_temperature": "bad",
            "llm_max_tokens": "bad",
            "llm_response_timeout_seconds": 0,
            "recent_history_size": -2,
            "max_regex_length": "bad",
            "regex_validation_timeout_seconds": "bad",
            "benign_match_strength_threshold": "bad",
            "type_weights": {
                "dns_domain": 0,
                "uri": 0,
                "filename": 0,
                "tls_sni": 0,
                "certificate_cn": 0,
            },
            "store_dir": "",
            "persistent_store_dir": " /tmp/regex-db ",
            "store_rejected_regexes": "true",
            "max_stored_rejected_regexes": "bad",
            "seed_benign_samples": "false",
        }
    }

    assert parser.regex_generator_generation_interval_seconds() == 5
    assert parser.regex_generator_create_log_file() is True
    assert parser.regex_generator_allowed_backends() == []
    assert parser.regex_generator_llm_temperature() == 1.2
    assert parser.regex_generator_llm_max_tokens() == 80
    assert parser.regex_generator_llm_response_timeout_seconds() == 0
    assert parser.regex_generator_recent_history_size() == 0
    assert parser.regex_generator_max_regex_length() == 180
    assert parser.regex_generator_regex_validation_timeout_seconds() == 2
    assert parser.regex_generator_benign_match_strength_threshold() == 75
    assert parser.regex_generator_type_weights() == {
        "dns_domain": 1,
        "uri": 1,
        "filename": 1,
        "tls_sni": 1,
        "certificate_cn": 1,
    }
    assert parser.regex_generator_store_dir() == "output/regex_generator"
    assert parser.regex_generator_persistent_store_dir() == "/tmp/regex-db"
    assert parser.regex_generator_store_rejected_regexes() is True
    assert parser.regex_generator_max_stored_rejected_regexes() == 10000
    assert parser.regex_generator_seed_benign_samples() is False
    assert parser.tranco_top_benign_limit() == 1000


def test_regex_generator_generation_interval_allows_zero():
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {
        "regex_generator": {
            "generation_interval_seconds": 0,
        }
    }

    assert parser.regex_generator_generation_interval_seconds() == 0


def test_choose_regex_type_honors_weights(tmp_path):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.type_weights = {
        "dns_domain": 1,
        "uri": 0,
        "filename": 0,
        "tls_sni": 0,
        "certificate_cn": 0,
    }

    assert regex_generator._choose_regex_type() == "dns_domain"


def test_select_backend_prefers_allowed_backends(tmp_path):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.allowed_backends = ["local_qwen", "openai_default"]

    backend = regex_generator._select_backend(
        {
            "default_backend": "openai_default",
            "backends": {
                "openai_default": {"provider": "openai", "model": "gpt-4o-mini"},
                "local_qwen": {"provider": "ollama", "model": "qwen2.5:3b"},
            },
        }
    )

    assert backend == "local_qwen"


def test_select_backend_falls_back_to_default_backend(tmp_path):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.allowed_backends = []

    backend = regex_generator._select_backend(
        {
            "default_backend": "local_qwen",
            "backends": {
                "local_qwen": {"provider": "ollama", "model": "qwen2.5:3b"},
            },
        }
    )

    assert backend == "local_qwen"


def test_main_waits_when_no_runtime_ready_backend(tmp_path, mocker):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    mocker.patch(
        "modules.regex_generator.regex_generator.utils.drop_root_privs_permanently"
    )
    mocker.patch("modules.regex_generator.regex_generator.time.sleep")
    regex_generator.pre_main()
    regex_generator.db.get_available_llm_backends = Mock(
        return_value={"default_backend": "", "backends": {}}
    )
    regex_generator.next_generation_at = 0

    regex_generator.main()

    regex_generator.db.publish.assert_not_called()
    assert regex_generator.next_generation_at > 0
    regex_generator.shutdown_gracefully()


def test_create_log_file_writes_progress_log(tmp_path, mocker):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.output_dir = str(tmp_path / "output")
    regex_generator.log_file_path = str(tmp_path / "output" / "regex_generator.log")
    regex_generator.create_log_file = True
    mocker.patch(
        "modules.regex_generator.regex_generator.utils.drop_root_privs_permanently"
    )

    regex_generator.pre_main()
    regex_generator._log_detail("test log line")

    with open(regex_generator.log_file_path, "r", encoding="utf-8") as log_file:
        log_contents = log_file.read()

    assert "RegexGenerator module ready." in log_contents
    assert "test log line" in log_contents
    regex_generator.shutdown_gracefully()


def test_log_file_rotates_with_global_rotation_settings(tmp_path, mocker):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    output_dir = tmp_path / "output"
    regex_generator.output_dir = str(output_dir)
    regex_generator.log_file_path = str(output_dir / "regex_generator.log")
    regex_generator.create_log_file = True
    regex_generator.enable_log_rotation = True
    regex_generator.log_rotation_period = 1
    regex_generator.last_log_rotation_time = time.time() - 10
    mocker.patch(
        "modules.regex_generator.regex_generator.utils.drop_root_privs_permanently"
    )

    regex_generator.pre_main()
    with open(regex_generator.log_file_path, "a", encoding="utf-8") as log_file:
        log_file.write("old line\n")
    regex_generator.last_log_rotation_time = time.time() - 10

    regex_generator._log_detail("new line")

    rotated_logs = list(output_dir.glob("regex_generator.log.*"))
    assert rotated_logs
    with open(regex_generator.log_file_path, "r", encoding="utf-8") as log_file:
        log_contents = log_file.read()
    assert "new line" in log_contents
    regex_generator.shutdown_gracefully()


def test_clean_host_tw_imports_runtime_benign_strings(tmp_path, mocker):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    mocker.patch(
        "modules.regex_generator.regex_generator.utils.drop_root_privs_permanently"
    )
    regex_generator.pre_main()
    regex_generator.get_msg = Mock(
        side_effect=[
            {"data": "profile_192.168.1.10_timewindow7"},
        ]
    )
    regex_generator.db.get_all_host_ips = Mock(return_value=["192.168.1.10"])
    regex_generator.db.get_profileid_twid_alerts = Mock(return_value={})
    regex_generator.db.get_twid_evidence = Mock(return_value={})
    regex_generator.db.get_all_altflows_in_profileid_twid = Mock(
        return_value=[
            {
                "flow_type": "dns",
                "flow": {"query": "printer.example.org"},
            },
            {
                "flow_type": "http",
                "flow": {"host": "updates.example.org", "uri": "/downloads/setup.msi"},
            },
            {
                "flow_type": "ssl",
                "flow": {
                    "server_name": "api.github.com",
                    "subject": "C=US,O=GitHub,CN=github.com",
                },
            },
        ]
    )

    regex_generator._handle_one_tw_closed_message()

    assert "printer.example.org" in set(
        regex_generator.storage.iter_benign_strings("dns_domain")
    )
    assert "updates.example.org" in set(
        regex_generator.storage.iter_benign_strings("dns_domain")
    )
    assert "setup.msi" in set(
        regex_generator.storage.iter_benign_strings("filename")
    )
    assert "api.github.com" in set(
        regex_generator.storage.iter_benign_strings("tls_sni")
    )
    assert "github.com" in set(
        regex_generator.storage.iter_benign_strings("certificate_cn")
    )
    regex_generator.shutdown_gracefully()


def test_dirty_host_tw_does_not_import_runtime_benign_strings(tmp_path, mocker):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    mocker.patch(
        "modules.regex_generator.regex_generator.utils.drop_root_privs_permanently"
    )
    regex_generator.pre_main()
    before_dns = set(regex_generator.storage.iter_benign_strings("dns_domain"))
    regex_generator.get_msg = Mock(
        side_effect=[
            {"data": "profile_192.168.1.10_timewindow8"},
        ]
    )
    regex_generator.db.get_all_host_ips = Mock(return_value=["192.168.1.10"])
    regex_generator.db.get_profileid_twid_alerts = Mock(
        return_value={"alert-1": ["ev-1"]}
    )
    regex_generator.db.get_twid_evidence = Mock(
        return_value={"ev-1": json.dumps({"evidence_type": "MALICIOUS_FLOW"})}
    )
    regex_generator.db.get_all_altflows_in_profileid_twid = Mock(
        return_value=[
            {
                "flow_type": "dns",
                "flow": {"query": "should-not-be-added.example"},
            },
        ]
    )

    regex_generator._handle_one_tw_closed_message()

    after_dns = set(regex_generator.storage.iter_benign_strings("dns_domain"))
    assert after_dns == before_dns
    regex_generator.shutdown_gracefully()


def test_count_anomaly_evidence_counts_anomalous_flow():
    count = RegexGenerator._count_anomaly_evidence(
        {
            "ev-1": {"evidence_type": "ANOMALOUS_FLOW", "description": ""},
            "ev-2": {"evidence_type": "SSH_SUCCESSFUL", "description": ""},
        }
    )

    assert count == 1


def test_build_prompt_messages_uses_type_specific_prompt(tmp_path):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.storage = Mock()

    messages = regex_generator._build_prompt_messages("dns_domain", "nonce-1")

    assert messages[0]["content"] == SYSTEM_PROMPT
    assert TYPE_PROMPTS["dns_domain"] in messages[1]["content"]
    assert PROMPT_VERSION in messages[1]["content"]
    regex_generator.storage.get_recent_history.assert_not_called()
    regex_generator.storage.get_benign_examples.assert_not_called()


def test_send_generation_request_publishes_expected_payload(tmp_path):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.storage = Mock()

    regex_generator._send_generation_request("dns_domain", "local_qwen")

    channel, payload = regex_generator.db.publish.call_args.args
    request = json.loads(payload)
    assert channel == "llm_request"
    assert request["backend"] == "local_qwen"
    assert request["temperature"] == 1.2
    assert request["max_tokens"] == 80
    assert request["metadata"]["regex_type"] == "dns_domain"
    assert request["metadata"]["prompt_version"] == PROMPT_VERSION
    assert request["request_id"].startswith("RegexGenerator-")


def test_handle_pending_response_matches_by_request_id(tmp_path, mocker):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.pending_request = {
        "request_id": "req-1",
        "regex_type": "dns_domain",
        "backend": "local_qwen",
        "sent_at": time.time(),
    }
    regex_generator._finalize_request = Mock()
    regex_generator.get_msg = Mock(
        return_value={
            "data": json.dumps(
                {
                    "request_id": "other-req",
                    "success": True,
                    "text": "^abc$",
                }
            )
        }
    )

    regex_generator._handle_pending_response(time.time())

    regex_generator._finalize_request.assert_not_called()
    assert regex_generator.pending_request["request_id"] == "req-1"


def test_handle_pending_response_keeps_waiting_after_soft_timeout(
    tmp_path, mocker
):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    mocker.patch("modules.regex_generator.regex_generator.time.sleep")
    regex_generator.pending_request = {
        "request_id": "req-1",
        "regex_type": "dns_domain",
        "backend": "local_qwen",
        "sent_at": time.time() - 120,
        "last_warning_at": 0.0,
    }
    regex_generator.get_msg = Mock(return_value=None)

    regex_generator._handle_pending_response(time.time())

    assert regex_generator.pending_request["request_id"] == "req-1"
    assert regex_generator.pending_request["last_warning_at"] > 0
    regex_generator.print.assert_called()


def test_finalize_request_drops_malformed_llm_response_without_error_logging(
    tmp_path,
):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.pending_request = {
        "request_id": "req-1",
        "regex_type": "dns_domain",
        "backend": "local_qwen",
    }
    regex_generator._log_detail = Mock()
    regex_generator._validate_and_store_regex = Mock()

    regex_generator._finalize_request(
        {
            "request_id": "req-1",
            "success": True,
            "text": "not json",
        }
    )

    regex_generator.print.assert_not_called()
    regex_generator._log_detail.assert_not_called()
    regex_generator._validate_and_store_regex.assert_not_called()


def test_extract_regex_from_llm_text_rejects_invalid_payloads(tmp_path):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )

    assert regex_generator._extract_regex_from_llm_text("not json") == (
        "",
        "invalid_response",
    )
    assert regex_generator._extract_regex_from_llm_text('{"rationale":"x"}') == (
        "",
        "missing_regex",
    )


def test_extract_regex_from_llm_text_accepts_raw_regex_line(tmp_path):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )

    regex, error = regex_generator._extract_regex_from_llm_text(
        r"^xqz[a-z0-9]{8,12}\.invalid$"
    )

    assert error is None
    assert regex == r"^xqz[a-z0-9]{8,12}\.invalid$"


def test_extract_regex_from_llm_text_accepts_fenced_json(tmp_path):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )

    regex, error = regex_generator._extract_regex_from_llm_text(
        '```json\n{"regex":"^abc$","rationale":"ok"}\n```'
    )

    assert error is None
    assert regex == "^abc$"


def test_extract_regex_from_llm_text_accepts_embedded_json_object(tmp_path):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )

    regex, error = regex_generator._extract_regex_from_llm_text(
        'Here is the result: {"regex":"^abc$","rationale":"ok"}'
    )

    assert error is None
    assert regex == "^abc$"


def test_validate_regex_rejects_unsupported_or_too_broad_patterns(tmp_path):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )

    assert regex_generator._validate_regex(".*") == "regex_too_broad"
    assert (
        regex_generator._validate_regex("(?<=abc)def")
        == "unsupported_lookbehind"
    )
    assert (
        regex_generator._validate_regex(r"^(abc)\1$")
        == "unsupported_backreference"
    )
    assert (
        regex_generator._validate_regex(r"^(.*a)+$")
        == "nested_wildcards"
    )


def test_validate_and_store_regex_rejects_duplicate_exact(tmp_path):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.storage = Mock()
    regex_generator.storage.might_have_generated_regex.return_value = True
    regex_generator.storage.get_existing_generated_regex.return_value = {
        "regex": "^dup$"
    }

    regex_generator._validate_and_store_regex(
        {
            "regex_type": "dns_domain",
            "regex": "^dup$",
            "regex_hash": regex_generator._hash_regex("^dup$"),
            "backend_alias": "local_qwen",
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "temperature": 1.2,
            "prompt_version": PROMPT_VERSION,
            "request_id": "req-1",
            "created_at": time.time(),
        }
    )

    regex_generator.storage.store_generated_regex.assert_not_called()


def test_validate_and_store_regex_rejects_validation_timeout(tmp_path):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.storage = Mock()
    regex_generator.storage.might_have_generated_regex.return_value = False
    regex_generator._find_strong_benign_match = Mock(
        side_effect=TimeoutError("timed out")
    )

    regex_generator._validate_and_store_regex(
        {
            "regex_type": "dns_domain",
            "regex": r"^slow-example$",
            "regex_hash": regex_generator._hash_regex(r"^slow-example$"),
            "backend_alias": "local_qwen",
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "temperature": 1.2,
            "prompt_version": PROMPT_VERSION,
            "request_id": "req-timeout",
            "created_at": time.time(),
        }
    )

    stored = regex_generator.storage.store_generated_regex.call_args.args[0]
    assert stored["status"] == "rejected"
    assert stored["rejection_reason"] == "regex_validation_timeout"


def test_benign_seeding_initializes_all_types(tmp_path):
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf(str(tmp_path / "regex_generator")),
        "dummy_output_dir",
        12345,
    )

    for regex_type in REGEX_TYPES:
        assert storage.get_benign_examples(regex_type, limit=1)

    storage.close()


def test_storage_resolves_relative_store_dir_inside_run_output_dir(tmp_path):
    output_dir = tmp_path / "slips_run_output"
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf("output/regex_generator"),
        str(output_dir),
        12345,
    )

    assert storage.store_dir == str(output_dir / "regex_generator")
    storage.close()


def test_storage_prefers_persistent_store_dir_when_configured(tmp_path):
    output_dir = tmp_path / "slips_run_output"
    persistent_dir = tmp_path / "persistent_regex_generator"
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf(
            "output/regex_generator",
            persistent_store_dir=str(persistent_dir),
        ),
        str(output_dir),
        12345,
    )

    assert storage.store_dir == str(persistent_dir)
    storage.close()


def test_storage_imports_whitelist_domains_into_matching_regex_types(tmp_path):
    whitelist_path = tmp_path / "whitelist.conf"
    whitelist_path.write_text(
        '\n'.join(
            [
                '; comment',
                'domain,example.com,both,alerts',
                'domain,api.github.com,both,alerts',
                'ip,1.2.3.4,both,alerts',
            ]
        ),
        encoding="utf-8",
    )
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf(
            str(tmp_path / "regex_generator"),
            local_whitelist_path=str(whitelist_path),
        ),
        "dummy_output_dir",
        12345,
    )

    assert "example.com" in storage.get_benign_examples("dns_domain", limit=100)
    assert "example.com" in storage.get_benign_examples("tls_sni", limit=100)
    assert "example.com" in storage.get_benign_examples(
        "certificate_cn", limit=100
    )
    assert "github.com" in storage.get_benign_examples("dns_domain", limit=100)
    assert "/index.html" in storage.get_benign_examples("uri", limit=100)
    storage.close()


def test_storage_skips_whitelist_import_when_disabled(tmp_path):
    whitelist_path = tmp_path / "whitelist.conf"
    whitelist_path.write_text(
        'domain,example.com,both,alerts\n',
        encoding="utf-8",
    )
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf(
            str(tmp_path / "regex_generator"),
            enable_local_whitelist=False,
            local_whitelist_path=str(whitelist_path),
        ),
        "dummy_output_dir",
        12345,
    )

    assert "example.com" not in storage.get_benign_examples(
        "dns_domain", limit=100
    )
    storage.close()


def test_storage_imports_tranco_top_domains_into_matching_regex_types(tmp_path):
    db = Mock()
    db.get_tranco_top_domains = Mock(
        return_value=["google.com", "github.com", "microsoft.com"]
    )
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf(str(tmp_path / "regex_generator")),
        "dummy_output_dir",
        12345,
        db=db,
    )

    assert "google.com" in storage.get_benign_examples("dns_domain", limit=200)
    assert "github.com" in storage.get_benign_examples("tls_sni", limit=200)
    assert "microsoft.com" in storage.get_benign_examples(
        "certificate_cn", limit=200
    )
    db.get_tranco_top_domains.assert_called_once_with(limit=1000)
    storage.close()


def test_storage_skips_tranco_import_when_limit_is_zero(tmp_path):
    db = Mock()
    db.get_tranco_top_domains = Mock(return_value=["tranco-only-example.test"])
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf(
            str(tmp_path / "regex_generator"),
            seed_benign_samples=False,
            tranco_top_benign_limit=0,
        ),
        "dummy_output_dir",
        12345,
        db=db,
    )

    assert "tranco-only-example.test" not in storage.get_benign_examples(
        "dns_domain", limit=200
    )
    db.get_tranco_top_domains.assert_not_called()
    storage.close()


def test_benign_corpus_scan_rejects_matching_regex(tmp_path):
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf(
            str(tmp_path / "regex_generator"),
            store_rejected_regexes=True,
        ),
        "dummy_output_dir",
        12345,
    )
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.storage = storage

    regex_generator._validate_and_store_regex(
        {
            "regex_type": "dns_domain",
            "regex": r"^google\.com$",
            "regex_hash": regex_generator._hash_regex(r"^google\.com$"),
            "backend_alias": "local_qwen",
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "temperature": 1.2,
            "prompt_version": PROMPT_VERSION,
            "request_id": "req-1",
            "created_at": time.time(),
        }
    )

    rejected = storage.get_generated_regexes(
        regex_type="dns_domain",
        status="rejected",
    )
    assert rejected[0]["rejection_reason"] == "matched_benign_data_too_strong"
    assert rejected[0]["matched_benign_value"] == "google.com"
    storage.close()


def test_benign_corpus_scan_rejects_regex_matching_whitelist_domain(tmp_path):
    whitelist_path = tmp_path / "whitelist.conf"
    whitelist_path.write_text(
        'domain,example.com,both,alerts\n',
        encoding="utf-8",
    )
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf(
            str(tmp_path / "regex_generator"),
            store_rejected_regexes=True,
            local_whitelist_path=str(whitelist_path),
        ),
        "dummy_output_dir",
        12345,
    )
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.storage = storage

    regex_generator._validate_and_store_regex(
        {
            "regex_type": "dns_domain",
            "regex": r"^example\.com$",
            "regex_hash": regex_generator._hash_regex(r"^example\.com$"),
            "backend_alias": "local_qwen",
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "temperature": 1.2,
            "prompt_version": PROMPT_VERSION,
            "request_id": "req-whitelist",
            "created_at": time.time(),
        }
    )

    rejected = storage.get_generated_regexes(
        regex_type="dns_domain",
        status="rejected",
    )
    assert rejected[0]["rejection_reason"] == "matched_benign_data_too_strong"
    assert rejected[0]["matched_benign_value"] == "example.com"
    storage.close()


def test_partial_benign_match_can_be_accepted_below_strength_threshold(tmp_path):
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf(str(tmp_path / "regex_generator")),
        "dummy_output_dir",
        12345,
    )
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.storage = storage
    regex_generator.benign_match_strength_threshold = 80

    regex_generator._validate_and_store_regex(
        {
            "regex_type": "dns_domain",
            "regex": r"google",
            "regex_hash": regex_generator._hash_regex(r"google"),
            "backend_alias": "local_qwen",
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "temperature": 1.2,
            "prompt_version": PROMPT_VERSION,
            "request_id": "req-weak-benign",
            "created_at": time.time(),
        }
    )

    accepted = storage.get_generated_regexes(regex_type="dns_domain")
    assert accepted
    assert accepted[0]["regex"] == r"google"
    storage.close()


def test_match_strength_scores_full_specific_match_higher_than_partial_match(tmp_path):
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    full_score = regex_generator._compute_match_strength(
        re.compile(r"^google\.com$"),
        "google.com",
        regex_generator._measure_regex_specificity(r"^google\.com$"),
    )
    partial_score = regex_generator._compute_match_strength(
        re.compile(r"google"),
        "google.com",
        regex_generator._measure_regex_specificity(r"google"),
    )

    assert full_score > partial_score


def test_rejected_regexes_are_not_persisted_by_default(tmp_path):
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf(str(tmp_path / "regex_generator")),
        "dummy_output_dir",
        12345,
    )
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.storage = storage

    regex_generator._validate_and_store_regex(
        {
            "regex_type": "dns_domain",
            "regex": r"^google\.com$",
            "regex_hash": regex_generator._hash_regex(r"^google\.com$"),
            "backend_alias": "local_qwen",
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "temperature": 1.2,
            "prompt_version": PROMPT_VERSION,
            "request_id": "req-default-reject",
            "created_at": time.time(),
        }
    )

    assert storage.get_generated_regexes(status="rejected") == []
    assert storage.was_rejected_in_current_run(
        regex_generator._hash_regex(r"^google\.com$")
    )
    storage.close()


def test_stored_rejected_regexes_are_pruned_to_max_size(tmp_path):
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf(
            str(tmp_path / "regex_generator"),
            store_rejected_regexes=True,
            max_stored_rejected_regexes=1,
        ),
        "dummy_output_dir",
        12345,
    )

    storage.store_generated_regex(
        {
            "regex_type": "dns_domain",
            "regex": "^first$",
            "regex_hash": "hash-first",
            "status": "rejected",
            "rejection_reason": "invalid_regex_syntax",
            "matched_benign_value": None,
            "backend_alias": "local_qwen",
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "temperature": 1.2,
            "prompt_version": PROMPT_VERSION,
            "request_id": "req-first",
            "created_at": 1.0,
        }
    )
    storage.store_generated_regex(
        {
            "regex_type": "dns_domain",
            "regex": "^second$",
            "regex_hash": "hash-second",
            "status": "rejected",
            "rejection_reason": "invalid_regex_syntax",
            "matched_benign_value": None,
            "backend_alias": "local_qwen",
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "temperature": 1.2,
            "prompt_version": PROMPT_VERSION,
            "request_id": "req-second",
            "created_at": 2.0,
        }
    )

    rejected = storage.get_generated_regexes(status="rejected")
    assert [row["regex"] for row in rejected] == ["^second$"]
    storage.close()


def test_validate_and_store_regex_accepts_non_matching_regex(tmp_path):
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf(str(tmp_path / "regex_generator")),
        "dummy_output_dir",
        12345,
    )
    regex_generator = ModuleFactory().create_regex_generator_obj(
        store_dir=str(tmp_path / "regex_generator")
    )
    regex_generator.storage = storage

    regex_generator._validate_and_store_regex(
        {
            "regex_type": "dns_domain",
            "regex": r"^xqz[a-z0-9]{8,12}\.invalid$",
            "regex_hash": regex_generator._hash_regex(
                r"^xqz[a-z0-9]{8,12}\.invalid$"
            ),
            "backend_alias": "local_qwen",
            "provider": "ollama",
            "model": "qwen2.5:3b",
            "temperature": 1.2,
            "prompt_version": PROMPT_VERSION,
            "request_id": "req-2",
            "created_at": time.time(),
        }
    )

    accepted = storage.get_generated_regexes(
        regex_type="dns_domain",
        status="accepted",
    )
    assert accepted[0]["regex"] == r"^xqz[a-z0-9]{8,12}\.invalid$"
    storage.close()


def test_storage_generated_regex_bloom_filter_tracks_inserted_hash(tmp_path):
    storage = RegexGeneratorStorage(
        Mock(),
        _build_storage_conf(str(tmp_path / "regex_generator")),
        "dummy_output_dir",
        12345,
    )

    record = {
        "regex_type": "dns_domain",
        "regex": r"^xqz[a-z0-9]{8,12}\.invalid$",
        "regex_hash": "hash-1",
        "status": "accepted",
        "rejection_reason": None,
        "matched_benign_value": None,
        "backend_alias": "local_qwen",
        "provider": "ollama",
        "model": "qwen2.5:3b",
        "temperature": 1.2,
        "prompt_version": PROMPT_VERSION,
        "request_id": "req-3",
        "created_at": time.time(),
    }

    assert storage.might_have_generated_regex("hash-1") is False
    storage.store_generated_regex(record)
    assert storage.might_have_generated_regex("hash-1") is True
    storage.close()
