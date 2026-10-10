"""Tests for asynchronous permanent host profiling."""

import json
import sqlite3
import time
from pathlib import Path
from unittest.mock import Mock, patch

from modules.host_profile.host_profile import HostProfile
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from tests.module_factory import ModuleFactory


def test_host_profile_idle_wait_does_not_touch_multiprocessing_event() -> None:
    """Avoid the macOS condition-lock assertion after worker shutdown."""
    factory = ModuleFactory()
    module = HostProfile.__new__(HostProfile)
    module.process_batch = Mock(return_value=0)
    module.termination_event = factory.logger
    module.termination_event.is_set.return_value = False
    module.termination_event.wait.side_effect = AssertionError(
        "must acquire() condition before using wait()"
    )

    with patch("modules.host_profile.host_profile.time.sleep") as sleep:
        assert module.main() is False

    assert sleep.call_count == 4
    sleep.assert_any_call(0.25)
    module.termination_event.wait.assert_not_called()

    module.termination_event.is_set.side_effect = [False, True]
    with patch("modules.host_profile.host_profile.time.sleep") as sleep:
        assert module.main() is False
    sleep.assert_called_once_with(0.25)


def test_host_profile_processes_bounded_batches_without_profiler_writes(
    tmp_path: Path,
) -> None:
    """Catch up from run SQLite in batches and persist identity clues.

    Parameters:
        tmp_path: Isolated run and permanent directories.
    """
    factory = ModuleFactory()
    module = HostProfile.__new__(HostProfile)
    module.parent_output_dir = str(tmp_path / "run")
    module.ppid = 123
    module.args = Mock()
    module.conf = Mock()
    module.conf.permanent_dir.return_value = str(tmp_path / "permanent")
    module.db = factory.logger
    module.db.rdb.get_network_state.return_value = {}
    module.init()
    module.BATCH_SIZE = 2
    module.flows_path.parent.mkdir(parents=True)
    with sqlite3.connect(module.flows_path) as connection:
        connection.execute("CREATE TABLE flows (flow TEXT)")
        connection.execute("CREATE TABLE altflows (flow TEXT)")
        connection.executemany(
            "INSERT INTO flows (flow) VALUES (?)",
            [
                (
                    json.dumps(
                        {
                            "type_": "conn",
                            "saddr": "10.0.0.2",
                            "daddr": "8.8.8.8",
                            "starttime": "100",
                        }
                    ),
                ),
                (
                    json.dumps(
                        {
                            "type_": "conn",
                            "saddr": "10.0.0.2",
                            "daddr": "8.8.8.8",
                            "starttime": "101",
                        }
                    ),
                ),
                (
                    json.dumps(
                        {
                            "type_": "conn",
                            "saddr": "10.0.0.2",
                            "daddr": "8.8.8.8",
                            "starttime": "102",
                        }
                    ),
                ),
            ],
        )
        connection.execute(
            "INSERT INTO altflows (flow) VALUES (?)",
            (
                json.dumps(
                    {
                        "type_": "http",
                        "saddr": "10.0.0.2",
                        "daddr": "8.8.8.8",
                        "starttime": "103",
                        "host": "example.org",
                        "uri": "/page",
                    }
                ),
            ),
        )
    module.pre_main()
    module._enrich_hosts = Mock()

    assert module.process_batch() == 3
    assert module.flow_rowid == 2
    assert module.altflow_rowid == 1
    assert module.process_batch() == 1
    assert module.process_batch() == 0
    assert module.flow_rowid == 3
    profile = HostProfileStore.read(module.store.path, "8.8.8.8")[0]
    assert {fact["value"] for fact in profile["facts"]} == {
        "example.org",
        "http://example.org/page",
    }


def test_host_profile_enriches_ips_in_small_redis_batches() -> None:
    """Read cached names and threat sources without per-flow Redis calls."""
    factory = ModuleFactory()
    module = HostProfile.__new__(HostProfile)
    module.parent_output_dir = "output/test"
    module.init()
    module.store = Mock()
    module.db = factory.logger
    module._pending_ips.add("8.8.8.8")
    module.db.rdb.r.pipeline.return_value.execute.return_value = ["dns.google"]
    module.db.rdb.rcache.pipeline.return_value.execute.return_value = [
        "dns.google",
        None,
        None,
        None,
        json.dumps({"source": ["feed-one"]}),
    ]

    module._enrich_hosts()

    module.store.observe_ip_info.assert_called_once_with(
        "8.8.8.8",
        {
            "reverse_dns": "dns.google",
            "threatintelligence": {"source": ["feed-one"]},
        },
    )
    module.store.observe_hostname.assert_called_once_with(
        "dns.google", "profile_8.8.8.8"
    )
    assert module._pending_ips == set()

    module._enriched_at["8.8.8.8"] = time.monotonic() - 301
    module.db.rdb.rcache.pipeline.return_value.execute.return_value[-1] = (
        json.dumps({"source": ["feed-two"]})
    )
    module._enrich_hosts()
    assert module.store.observe_ip_info.call_count == 2
    assert module.store.observe_ip_info.call_args.args[1][
        "threatintelligence"
    ] == {"source": ["feed-two"]}

    module._enriched_at["8.8.8.8"] = time.monotonic() - 301
    module._enrich_hosts()
    assert module.store.observe_ip_info.call_count == 2
