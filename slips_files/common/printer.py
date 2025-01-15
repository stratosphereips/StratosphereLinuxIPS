# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from slips_files.common.abstracts.observer import IObservable
from slips_files.core.output import Output


class Printer(IObservable):
    """
    This is a proxy between any module that wants to print something,
    and slips_files/core/output.py
    The goal of this Printer is to have 1 print function and have all the
    modules use it.
    """

    def __init__(self, logger: Output, name: str):
        # name of the module using the printer
        self.name = name
        IObservable.__init__(self)
        self.logger = logger
        self.add_observer(self.logger)

    def print(
        self, text, verbose=1, debug=0, log_to_logfiles_only=False, end="\n"
    ):
        """
        Function to use to print text using the slips_files/core/output.py.
        The output process then decides how, when and where to print this txt.
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print.
        :param log_to_logfiles_only: if this is True, Sips logs to logfile
        only and doesn't log the given text to cli
        :param end: this is exactly linke print()'s end kwarg
        """
        self.notify_observers(
            {
                "from": self.name,
                "txt": text,
                "verbose": verbose,
                "debug": debug,
                "log_to_logfiles_only": log_to_logfiles_only,
                "end": end,
            }
        )
