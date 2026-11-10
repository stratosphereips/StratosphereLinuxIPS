"""Regression tests for Zeek log watcher event filtering."""

from unittest.mock import MagicMock, patch

import pytest

from tests.module_factory import ModuleFactory
from slips_files.common.input_type import InputType
from slips_files.core.helpers.filemonitor import FileEventHandler


@pytest.mark.parametrize(
    "source,destination,published",
    [
        ("config/tmp123.conf", "config/sebas-whitelist.conf", False),
        ("output/zeek/conn.log", "output/zeek/conn.1.log", True),
        ("config/conn.log", "config/conn.1.log", False),
    ],
)
def test_only_zeek_log_moves_publish_rotation(
    source: str, destination: str, published: bool
) -> None:
    """Send real log rotations through while rejecting config moves.

    Parameters:
        source: Original moved path.
        destination: Destination moved path.
        published: Whether the rotation channel should receive the event.
    """
    input_process = ModuleFactory().create_input_obj(
        "", InputType.ZEEK_LOG_FILE
    )
    input_process.db.publish = MagicMock()
    handler = FileEventHandler("output/zeek", input_process.db, "en0")
    event = MagicMock(
        src_path=source,
        dest_path=destination,
    )

    with patch("slips_files.core.helpers.filemonitor.time.sleep") as sleep:
        handler.on_moved(event)

    if published:
        input_process.db.publish.assert_called_once()
        sleep.assert_called_once_with(1)
    else:
        input_process.db.publish.assert_not_called()
        sleep.assert_not_called()
