# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import signal
from types import FrameType, TracebackType
from typing import NoReturn


class _NullTimeout:
    def __enter__(self) -> None:
        """
        Enter a no-op timeout context.

        Returns:
            None
        """
        return None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        """
        Exit a no-op timeout context.

        Args:
            exc_type: Exception type raised in the context, if any.
            exc: Exception raised in the context, if any.
            exc_tb: Traceback attached to the exception, if any.

        Returns:
            False to propagate any exception raised in the context.
        """
        return False


class _SignalTimeout:
    def __init__(self, timeout_seconds: float) -> None:
        """
        Create a signal-backed timeout context.

        Args:
            timeout_seconds: Number of seconds before timing out.

        Returns:
            None
        """
        self.timeout_seconds = timeout_seconds
        self._previous_handler = None

    def __enter__(self) -> None:
        """
        Start the timeout timer.

        Returns:
            None
        """
        self._previous_handler = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, self._handle_timeout)
        signal.setitimer(signal.ITIMER_REAL, self.timeout_seconds)
        return None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        """
        Stop the timeout timer and restore the previous signal handler.

        Args:
            exc_type: Exception type raised in the context, if any.
            exc: Exception raised in the context, if any.
            exc_tb: Traceback attached to the exception, if any.

        Returns:
            False to propagate any exception raised in the context.
        """
        signal.setitimer(signal.ITIMER_REAL, 0)
        if self._previous_handler is not None:
            signal.signal(signal.SIGALRM, self._previous_handler)
        return False

    @staticmethod
    def _handle_timeout(signum: int, frame: FrameType | None) -> NoReturn:
        """
        Raise an exception when the signal timer expires.

        Args:
            signum: Signal number received from the operating system.
            frame: Current stack frame when the signal was handled.

        Returns:
            This method does not return.
        """
        raise TimeoutError("regex validation timed out")
