"""Feed status preserves load counts and dates across checks and failures."""

from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

from modules.feeds_update_manager.feed_status import record_feed_load, record_feed_status
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("counts", [{"ips": 3, "domains": 2}, {"ja3": 0}])
def test_load_counts_survive_status_updates(counts: dict[str, int]) -> None:
    """Keep accepted counts and original load dates on later checks or failures.

    Parameters:
        counts: Accepted per-type counts, including a genuinely empty feed.
    """
    factory = ModuleFactory()
    db = factory.logger
    state = {"e-tag": "version-one", "downloaded_at": 123}
    db.get_ti_feed_info = Mock(side_effect=lambda _: state.copy())
    db.set_ti_feed_info = Mock(side_effect=lambda _, value: state.update(value))
    record_feed_load(db, "feed", counts)
    loaded_at = state["loaded_at"]
    assert state["counts"] == counts
    assert state["status"] == "ready"
    assert state["e-tag"] == "version-one"
    record_feed_status(db, "feed", status="error", checked_at=loaded_at + 10)
    assert state["counts"] == counts
    assert state["downloaded_at"] == 123
    assert state["loaded_at"] == loaded_at
    assert state["checked_at"] == loaded_at + 10
    assert state["status"] == "error"


def test_unchanged_feed_keeps_validators_and_counts() -> None:
    """An unchanged response advances its check without inventing a download."""
    updater = ModuleFactory().create_update_manager_obj()
    previous = {"e-tag": "same", "counts": {"ips": 9}, "downloaded_at": 123, "loaded_at": 124}
    updater.db.get_ti_feed_info.return_value = previous
    updater._mark_feed_as_updated("feed")
    info = updater.db.set_ti_feed_info.call_args.args[1]
    assert info["counts"] == {"ips": 9}
    assert info["e-tag"] == "same"
    assert info["downloaded_at"] == 123
    assert info["loaded_at"] == 124
    assert info["checked_at"] > 124
    assert "time" not in previous


def test_sources_are_registered_by_the_feed_worker() -> None:
    """Register pending sources without writing status during construction."""
    updater = ModuleFactory().create_update_manager_obj()
    updater.db.set_ti_feed_info.assert_not_called()
    updater._register_feed_sources()
    sources = {call.args[0]: call.args[1] for call in updater.db.set_ti_feed_info.call_args_list}
    assert sources[updater.tor_nodes_feed_link]["kind"] == "Tor exits"
    assert sources[updater.mac_db_link]["update_period"] == updater.mac_db_update_period
    assert all("loaded_at" not in record for record in sources.values())


def test_download_parse_and_check_dates_keep_their_order(tmp_path: Path) -> None:
    """Use the real feed parser to retain accepted counts and ordered dates.

    Parameters:
        tmp_path: Isolated location for the downloaded test feed.
    """
    updater = ModuleFactory().create_update_manager_obj()
    source = "https://example.com/feed.csv"
    updater.path_to_remote_ti_files_dir = str(tmp_path)
    updater.url_feeds = {source: {"threat_level": "low", "tags": ["test"]}}
    updater.ja3_feeds = updater.ssl_feeds = {}
    body = b"1.2.3.4,IP description\nexample.com,Domain description\n"
    response = MagicMock(status_code=200, headers={"ETag": "v1"})
    response.iter_content.return_value = [body]
    updater.download_file = Mock(return_value=response)
    metadata = {}
    updater.db.get_ti_feed_info.side_effect = lambda _: metadata.copy()
    updater.db.set_ti_feed_info.side_effect = lambda _, value: metadata.update(value)
    assert updater._update_ti_file_sync(source) is True
    assert metadata["counts"] == {"ips": 1, "domains": 1, "ip_ranges": 0}
    assert metadata["downloaded_at"] <= metadata["loaded_at"] <= metadata["checked_at"]
    assert metadata["download_bytes"] == len(body)
    assert metadata["e-tag"] == "v1"
    assert not (tmp_path / "feed.csv").exists()
