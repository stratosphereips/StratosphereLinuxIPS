# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from abc import ABC, abstractmethod

from slips_files.common.printer import Printer
from slips_files.core.database.database_manager import DBManager


class IInputReader(ABC):
    """
    Interface for all input readers supported by slips placed in
    slips_files/core/input_readers/
    """

    def __init__(
        self,
        logger,
        output_dir,
        redis_port,
        conf,
        ppid: int,
        profiler_queue,
        input_type,
        testing=False,
        **kwargs
    ):
        """
        Common initializations for all readers
        """
        self.testing = testing
        self.logger = logger
        self.output_dir = output_dir
        self.redis_port = redis_port
        self.conf = conf
        self.ppid = ppid
        self.profiler_queue = profiler_queue
        self.input_type = input_type
        self.printer = Printer(self.logger, self.name)
        self.db = DBManager(
            self.logger, self.output_dir, self.redis_port, self.conf, self.ppid
        )
        self.init()

    @abstractmethod
    def init(self):
        """
        Reader-specific initializations
        """

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def give_profiler(self, line):
        """
        sends the given txt/dict to the profilerqueue for process
        sends the total amount of flows to process with the first flow only
        """
        to_send = {"line": line, "input_type": self.input_type}
        # when the queue is full, the default behaviour is to block
        # if necessary until a free slot is available
        self.profiler_queue.put(to_send)

    def _make_gen(self, reader):
        """yeilds (64 kilobytes) at a time from the file"""
        while True:
            b = reader(2**16)
            if not b:
                break
            yield b

    def get_flows_number(self, file: str) -> int:
        """
        returns the number of flows/lines in a given file
        """
        # using wc -l doesn't count last line of the file if it does not have end of line character
        # using  grep -c "" returns incorrect line numbers sometimes
        # this method is the most efficient and accurate i found online
        # https://stackoverflow.com/a/68385697/11604069

        with open(file, "rb") as f:
            # counts the occurances of \n in a file
            count = sum(buf.count(b"\n") for buf in self._make_gen(f.raw.read))

        if hasattr(self, "is_zeek_tabs") and self.is_zeek_tabs:
            # subtract comment lines in zeek tab files,
            # they shouldn't be considered flows

            # NOTE: the counting of \n returns the actual lines-1 bc the
            # very last line of a zeek tab log file doesn't contain a \n
            # so instead of subtracting the 9 comment lines, we'll subtract
            # 8 bc the very last comment line isn't even included in count
            count -= 9

        return count

    @abstractmethod
    def read(self, *args):
        """
        Read the input source
        """
        pass
