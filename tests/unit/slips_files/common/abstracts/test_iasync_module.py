# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
from unittest.mock import Mock

import pytest

from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "exception",
    [KeyboardInterrupt(), SystemExit(), asyncio.CancelledError()],
)
def test_handle_task_exception_ignores_shutdown_exceptions(
    exception: BaseException,
) -> None:
    module_factory = ModuleFactory()
    flowalerts = module_factory.create_flowalerts_obj()
    task = Mock()
    task.exception.return_value = exception

    flowalerts.handle_task_exception(task)

    flowalerts.print.assert_not_called()


def test_handle_task_exception_ignores_cancelled_tasks() -> None:
    module_factory = ModuleFactory()
    flowalerts = module_factory.create_flowalerts_obj()
    task = Mock()
    task.exception.side_effect = asyncio.CancelledError()

    flowalerts.handle_task_exception(task)

    flowalerts.print.assert_not_called()


def test_handle_task_exception_logs_regular_exceptions() -> None:
    module_factory = ModuleFactory()
    flowalerts = module_factory.create_flowalerts_obj()
    exception = ValueError("boom")
    task = Mock()
    task.exception.return_value = exception
    flowalerts.print_traceback_from_exception = Mock()

    flowalerts.handle_task_exception(task)

    flowalerts.print.assert_called_once_with(
        "Unhandled exception in task: ValueError('boom') .. "
    )
    flowalerts.print_traceback_from_exception.assert_called_once_with(
        exception, task
    )


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (KeyboardInterrupt(), True),
        (SystemExit(), True),
        (asyncio.CancelledError(), True),
        (ValueError("boom"), False),
        (None, False),
    ],
)
def test_is_shutdown_exception(
    exception: BaseException | None, expected: bool
) -> None:
    module_factory = ModuleFactory()
    flowalerts = module_factory.create_flowalerts_obj()

    assert flowalerts.is_shutdown_exception(exception) is expected


def test_handle_loop_exception_ignores_shutdown_future() -> None:
    module_factory = ModuleFactory()
    flowalerts = module_factory.create_flowalerts_obj()
    future = Mock()
    future.result.side_effect = asyncio.CancelledError()
    flowalerts.print_traceback = Mock()

    flowalerts.handle_loop_exception(Mock(), {"future": future})

    flowalerts.print.assert_not_called()
    flowalerts.print_traceback.assert_not_called()


def test_handle_loop_exception_logs_future_error() -> None:
    module_factory = ModuleFactory()
    flowalerts = module_factory.create_flowalerts_obj()
    future = Mock()
    future.result.side_effect = ValueError("boom")
    flowalerts.print_traceback = Mock()

    flowalerts.handle_loop_exception(Mock(), {"future": future})

    flowalerts.print_traceback.assert_called_once_with()


@pytest.mark.parametrize(
    "exception",
    [KeyboardInterrupt(), SystemExit(), asyncio.CancelledError()],
)
def test_handle_loop_exception_ignores_shutdown_exception(
    exception: BaseException,
) -> None:
    module_factory = ModuleFactory()
    flowalerts = module_factory.create_flowalerts_obj()

    flowalerts.handle_loop_exception(Mock(), {"exception": exception})

    flowalerts.print.assert_not_called()


def test_handle_loop_exception_logs_regular_exception() -> None:
    module_factory = ModuleFactory()
    flowalerts = module_factory.create_flowalerts_obj()
    exception = ValueError("boom")

    flowalerts.handle_loop_exception(Mock(), {"exception": exception})

    flowalerts.print.assert_called_once_with("Unhandled loop exception: boom")


def test_handle_loop_exception_logs_message() -> None:
    module_factory = ModuleFactory()
    flowalerts = module_factory.create_flowalerts_obj()

    flowalerts.handle_loop_exception(Mock(), {"message": "boom"})

    flowalerts.print.assert_called_once_with("Unhandled loop error: boom")
