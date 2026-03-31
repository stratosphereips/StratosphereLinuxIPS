# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import signal
import sys
import types
from unittest.mock import MagicMock, patch
import pytest

# Stub out netifaces before any project import touches it
if "netifaces" not in sys.modules:
    sys.modules["netifaces"] = types.ModuleType("netifaces")


class TestShutdownGracefully:
    """Tests for Trust.shutdown_gracefully (issue #1840)."""

    def _make_trust_instance(self):
        """Return a bare Trust instance with only the attributes we need."""
        from modules.p2ptrust.p2ptrust import Trust

        # Build a minimal object without calling __init__
        obj = object.__new__(Trust)
        return obj

    def test_shutdown_gracefully_pigeon_none_no_exception(self):
        """shutdown_gracefully must not raise when self.pigeon is None."""
        trust = self._make_trust_instance()
        trust.pigeon = None  # mirrors the state set in _configure when binary missing

        # Should complete without AttributeError
        trust.shutdown_gracefully()

    def test_shutdown_gracefully_pigeon_sends_sigint(self):
        """shutdown_gracefully sends SIGINT when pigeon process is running."""
        trust = self._make_trust_instance()
        mock_pigeon = MagicMock()
        trust.pigeon = mock_pigeon

        trust.shutdown_gracefully()

        mock_pigeon.send_signal.assert_called_once_with(signal.SIGINT)

    def test_shutdown_gracefully_no_pigeon_attr(self):
        """shutdown_gracefully must not raise when pigeon attribute is absent."""
        trust = self._make_trust_instance()
        # Do NOT set trust.pigeon at all

        trust.shutdown_gracefully()
