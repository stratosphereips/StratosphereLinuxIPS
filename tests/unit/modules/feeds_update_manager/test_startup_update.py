"""Checks that every run loads its own local whitelist during startup."""

from unittest.mock import Mock, patch

import pytest
from exclusiveprocess import CannotAcquireLock

from modules.feeds_update_manager.feeds_update_manager import FeedsUpdateManager
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("lock_contended", [False, True])
def test_startup_loads_local_whitelist_with_org_lock_contention(
    lock_contended: bool,
) -> None:
    """Load run-local rules even when another process owns the org lock.

    Parameters:
        lock_contended: Whether the shared organization lock is unavailable.
    """
    _module_factory = ModuleFactory()
    manager = Mock()
    with patch.object(
        FeedsUpdateManager, "_build_startup_instance", return_value=manager
    ), patch.object(
        FeedsUpdateManager,
        "_update_ports_info_in_background",
        return_value=None,
    ), patch(
        "modules.feeds_update_manager.feeds_update_manager.Lock"
    ) as lock:
        if lock_contended:
            lock.return_value.__enter__.side_effect = CannotAcquireLock()
        FeedsUpdateManager.run_startup_update(
            logger=None,
            output_dir="test-output",
            redis_port=6379,
            args=None,
            conf=None,
            pid=1,
            local_files=True,
        )

    manager._init_whitelist.assert_called_once_with()
    manager.update_local_whitelist.assert_called_once_with()
    assert manager.update_org_files.call_count == (0 if lock_contended else 1)
