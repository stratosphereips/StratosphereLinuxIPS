# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# StartupMixin groups construction and startup of core processes and shared
# runtime helpers used by ProcessManager.
import threading
from typing import Optional

from managers.update_manager import UpdateManager
from modules.feeds_update_manager.feeds_update_manager import (
    FeedsUpdateManager,
)
from modules.supported_module_names import Modules
from slips_files.common.input_type import InputType
from slips_files.core.evidence_handler import EvidenceHandler
from slips_files.core.helpers.bloom_filters_manager import BFManager
from slips_files.core.input import Input
from slips_files.core.output import Output
from slips_files.core.profiler import Profiler


class StartupMixin:
    """Provide helpers that construct and start child processes."""

    def declare_that_slips_is_done_starting_all_children(self) -> None:
        """
        Mark that all required child processes have started.
        """
        self.all_children_started = True

    def start_slips_update_manager(self) -> UpdateManager:
        """
        Create the update manager used by the live-update workflow.

        Returns:
            Configured update manager instance.
        """
        return UpdateManager(
            database=self.main.db,
            is_slips_live_updating_event=self.is_slips_live_updating_event,
            print_func=self.main.print,
        )

    def start_output_process(
        self, stderr: str, slips_logfile: str, stdout: str = ""
    ) -> Output:
        """
        Create the output process.

        Parameters:
            stderr: stderr destination.
            slips_logfile: Slips log file path.
            stdout: stdout destination.

        Returns:
            Created output process.
        """
        output_process = Output(
            stdout=stdout,
            stderr=stderr,
            slips_logfile=slips_logfile,
            verbose=self.main.args.verbose or 0,
            debug=self.main.args.debug,
            input_type=self.main.input_type,
            create_logfiles=False if self.main.args.stopdaemon else True,
            slips_args=self.main.args,
        )
        self.slips_logfile = output_process.slips_logfile
        return output_process

    def start_profiler_process(self) -> Profiler:
        """
        Start the profiler process.

        Returns:
            Started profiler process.
        """
        profiler_process = Profiler(
            self.main.logger,
            self.main.args.output,
            self.main.redis_port,
            self.termination_event,
            self.main.args,
            self.main.conf,
            self.main.pid,
            self.main.bloom_filters_man,
            is_profiler_done_semaphore=self.is_profiler_done_semaphore,
            profiler_queue=self.profiler_queue,
            is_profiler_done_event=self.is_profiler_done_event,
            is_input_done_event=self.is_input_done_event,
            is_input_failed_event=self.is_input_failed_event,
            is_profiler_done_starting_initial_workers_event=(
                self.is_profiler_done_starting_initial_workers_event
            ),
            total_processes_to_start=self.total_processes_to_start,
        )
        profiler_process.start()
        self.announce_started(
            Modules.PROFILER,
            profiler_process.pid,
            profiler_process.description,
            self.main.db,
        )
        self.main.db.store_pid("Profiler", int(profiler_process.pid))
        # Interface input starts profiler workers before the input process
        # sends any flows. File-like inputs need the input process to send the
        # first message before the profiler can choose the input handler.
        if self.main.input_type == InputType.INTERFACE:
            self.is_profiler_done_starting_initial_workers_event.wait(30)
        self.profiler_process = profiler_process
        return profiler_process

    def start_evidence_process(self) -> EvidenceHandler:
        """
        Start the evidence handler process.

        Returns:
            Started evidence handler process.
        """
        evidence_process = EvidenceHandler(
            self.main.logger,
            self.main.args.output,
            self.main.redis_port,
            self.evidence_handler_termination_event,
            self.main.args,
            self.main.conf,
            self.main.pid,
            self.main.bloom_filters_man,
            total_processes_to_start=self.total_processes_to_start,
        )
        evidence_process.start()
        self.announce_started(
            Modules.EVIDENCE_HANDLER,
            evidence_process.pid,
            evidence_process.description,
            self.main.db,
        )
        self.main.db.store_pid("evidence_handler", int(evidence_process.pid))
        self.evidence_process = evidence_process
        return evidence_process

    def start_input_process(self) -> Input:
        """
        Start the input process.

        Returns:
            Started input process.
        """
        input_process = Input(
            self.main.logger,
            self.main.args.output,
            self.main.redis_port,
            self.termination_event,
            self.main.args,
            self.main.conf,
            self.main.pid,
            self.main.bloom_filters_man,
            is_input_done=self.is_input_done,
            profiler_queue=self.profiler_queue,
            input_type=self.main.input_type,
            input_information=self.main.input_information,
            cli_packet_filter=self.main.args.pcapfilter,
            zeek_or_bro=self.main.zeek_bro,
            line_type=self.main.line_type,
            is_profiler_done_event=self.is_profiler_done_event,
            is_input_done_event=self.is_input_done_event,
            is_input_failed_event=self.is_input_failed_event,
            is_slips_live_updating_event=(self.is_slips_live_updating_event),
            is_profiler_done_starting_initial_workers_event=(
                self.is_profiler_done_starting_initial_workers_event
            ),
        )
        input_process.start()
        self.announce_started(
            Modules.INPUT,
            input_process.pid,
            input_process.description,
            self.main.db,
        )
        self.main.db.store_pid("Input", int(input_process.pid))
        self.input_process = input_process
        return input_process

    def init_bloom_filters_manager(self) -> BFManager:
        """
        Create the shared bloom filters manager.

        Returns:
            Shared bloom filters manager instance.
        """
        return BFManager(
            self.main.logger,
            self.main.args.output,
            self.main.redis_port,
            self.main.conf,
            self.main.pid,
        )

    def start_feeds_update_manager(
        self, local_files: bool = False, ti_feeds: bool = False
    ) -> Optional[threading.Thread]:
        """
        Run the feeds update manager in the current process.

        Parameters:
            local_files: Whether to update local ports and org files.
            ti_feeds: Whether to update remote threat-intel feeds.

        Returns:
            The background thread updating local ports info, if one was
            started. Slips doesn't need to wait for it before starting
            the rest of the modules, so callers can ignore it.
        """
        return FeedsUpdateManager.run_startup_update(
            logger=self.main.logger,
            output_dir=self.main.args.output,
            redis_port=self.main.redis_port,
            args=self.main.args,
            conf=self.main.conf,
            pid=self.main.pid,
            bloom_filters_man=getattr(self.main, "bloom_filters_man", None),
            local_files=local_files,
            ti_feeds=ti_feeds,
        )
