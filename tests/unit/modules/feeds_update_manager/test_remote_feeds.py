"""Regression tests for remote threat-feed failures."""

from unittest.mock import Mock

from modules.feeds_update_manager.remote_feed_updater_mixin import (
    RemoteFeedUpdaterMixin,
)
from modules.feeds_update_manager.ti_feed_parser_mixin import (
    TIFeedParserMixin,
)
from tests.module_factory import ModuleFactory


def test_empty_remote_feed_preserves_cached_entries(tmp_path) -> None:
    """An upstream 200 with no body must not erase the last valid feed.

    Parameters:
        tmp_path: Isolated directory for any attempted download.
    """
    factory = ModuleFactory()
    updater = RemoteFeedUpdaterMixin()
    url = "https://lists.blocklist.de/lists/ssh.txt"
    updater.responses = {url: Mock(text="")}
    updater.path_to_remote_ti_files_dir = str(tmp_path)
    updater.db = factory.logger
    updater.log = Mock()
    updater.print = Mock()

    assert updater._update_ti_file_sync(url) is False
    updater.db.delete_feed_entries.assert_not_called()
    updater.db.set_feed_last_update_time.assert_called_once()
    assert not (tmp_path / "ssh.txt").exists()
    updater.print.assert_not_called()


def test_invalid_feed_entry_is_skipped_without_error_log() -> None:
    """Expected upstream typos are diagnostic messages, not code errors."""
    factory = ModuleFactory()
    parser = TIFeedParserMixin()
    parser.log = factory.logger
    parser.print = Mock()

    assert (
        parser._is_valid_ioc_and_description("fhits.xy", "entry", "feed.txt")
        is False
    )
    parser.log.assert_called_once()
    parser.print.assert_not_called()
