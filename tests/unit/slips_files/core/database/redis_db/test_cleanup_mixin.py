"""Tests for periodic P2P cleanup on timewindow close."""

from unittest.mock import MagicMock

from slips_files.core.database.redis_db.cleanup_mixin import CleanupMixin
from slips_files.core.database.redis_db.constants import Constants


def make_mixin() -> CleanupMixin:
    """Create a cleanup mixin with mocked collaborators.

    Returns:
        Cleanup mixin ready for timewindow-close tests.
    """
    mixin = CleanupMixin()
    mixin.r = MagicMock()
    mixin.r.scan.return_value = (0, [])
    mixin.constants = Constants
    mixin.get_blocked_timewindows_of_profile = MagicMock(return_value=[])
    mixin.del_stale_p2p_connections = MagicMock()
    mixin.print = MagicMock()
    return mixin


def test_closing_a_timewindow_prunes_stale_p2p_connections() -> None:
    """A closed timewindow bounds both p2p counters and connections."""
    mixin = make_mixin()

    mixin.delete_past_timewindows("profile_1.2.3.4_timewindow5", MagicMock())

    mixin.del_stale_p2p_connections.assert_called_once_with()


def test_closing_a_timewindow_still_deletes_p2p_message_counts() -> None:
    """Pruning connections doesn't replace clearing message counters."""
    mixin = make_mixin()

    mixin.delete_past_timewindows("profile_1.2.3.4_timewindow5", MagicMock())

    mixin.r.delete.assert_any_call(f"{Constants.P2P_MESSAGE_COUNTS}_5")
