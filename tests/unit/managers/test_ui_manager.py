"""Tests for the local web interface launcher."""

from queue import Queue
from unittest.mock import patch

from managers.ui_manager import UIManager
from tests.module_factory import ModuleFactory


def test_webinterface_result_uses_thread_queue() -> None:
    """The launcher thread needs no multiprocessing semaphores."""
    factory = ModuleFactory()
    main = factory.logger
    main.conf.web_interface_port = 55000
    manager = UIManager(main)

    with (
        patch("managers.ui_manager.utils.is_port_in_use", return_value=False),
        patch("managers.ui_manager.threading.Thread") as thread,
    ):
        manager.start_webinterface()

    assert isinstance(manager.webinterface_return_value, Queue)
    thread.return_value.start.assert_called_once_with()
