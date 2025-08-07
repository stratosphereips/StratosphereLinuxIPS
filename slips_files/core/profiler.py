# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
import asyncio
import os
import threading

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz,
# stratosphere@aic.fel.cvut.cz
import queue
import multiprocessing
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address
from typing import (
    List,
    Union,
)


from slips_files.common.abstracts.iobserver import IObservable
from slips_files.common.style import green
from slips_files.common.abstracts.iasync_module import IAsyncModule
from slips_files.core.helpers.flow_processor import FlowProcessor
from slips_files.core.helpers.whitelist.whitelist import Whitelist


SEPARATORS = {
    "zeek": "",
    "suricata": "",
    "nfdump": ",",
    "binetflow": ",",
    "zeek-tabs": "\t",
    "binetflow-tabs": "\t",
}


class Profiler(IAsyncModule, IObservable):
    """A class to create the profiles for IPs"""

    name = "Profiler"

    async def init(
        self,
        is_profiler_done: multiprocessing.Semaphore = None,
        profiler_queue=None,
        is_profiler_done_event: multiprocessing.Event = None,
        **kwargs,
    ):
        IObservable.__init__(self)
        self.channels = {
            "reload_whitelist": self.new_reload_whitelist_msg_handler,
        }
        print(f"@@@@@@@@@@@@@@@@ profilerr {self.channels.keys()}")
        await self.db.subscribe(self.pubsub, self.channels.keys())
        print(f"@@@@@@@@@@@@@@@@ profiler:: {self.pubsub}")
        self.add_observer(self.logger)
        self.read_configuration()
        # when profiler is done processing, it releases this semaphore,
        # that's how the process_manager knows it's done
        # when both the input and the profiler are done,
        # the input process signals the rest of the modules to stop
        self.done_processing: multiprocessing.Semaphore = is_profiler_done
        # every line put in this queue should be profiled
        self.profiler_queue: multiprocessing.Queue = profiler_queue

        self.whitelist = Whitelist(self.logger, self.db)

        # is set by this proc to tell input proc that we are done
        # processing and it can exit no issue
        self.is_profiler_done_event = is_profiler_done_event

        self.profiler_threads = []
        self.stop_profiler_threads = threading.Event()
        # each msg received from inputprocess will be put here, and each one
        # profiler_threads will retrieve from this queue.
        # the goal of this is to have main() handle the stop msg.
        # so without this, only 1 of the 3 threads receive the stop msg
        # and exits, and the rest of the 2 threads AND the main() keep
        # waiting for new msgs
        self.flows_to_process_q = threading.Queue()
        # that queue will be used in 4 different threads. the 3 profilers
        # and main().
        self.pending_flows_queue_lock = threading.Lock()

    def is_stop_msg(self, msg: str) -> bool:
        """
        this 'stop' msg is the last msg ever sent by the input process
        to indicate that no more flows are coming
        """
        return msg == "stop"

    def get_msg_from_q(self, q: multiprocessing.Queue, thread_safe=False):
        """
        retrieves a msg from the given queue
        :kwarg thread_safe: set it to true if the queue passed is used by
        the profiler threads (e.g pending_flows_queue).
         when set to true, this function uses the pending flows queue lock.
        """
        try:
            if thread_safe:
                with self.pending_flows_queue_lock:
                    return q.get(timeout=1, block=False)
            else:
                return q.get(timeout=1, block=False)
        except queue.Empty:
            return None
        except Exception:
            return None

    def start_profiler_threads(self):
        """starts 3 profiler threads for faster processing of the flows"""
        # @@@@@@@@@@@2 reset to 3:D
        num_of_profiler_threads = 3
        for _ in range(num_of_profiler_threads):
            print(
                f"@@@@@@@@@@@@@@@@ starting thread {len(self.profiler_threads)}"
            )
            t = self.create_thread(self.process_flow)
            print(f"@@@@@@@@@@@@@@@@ [profilerr] starting {t}")
            t.start()
            self.profiler_threads.append(t)

    async def process_flow(self):
        """
        This function runs in 3 parallel threads for faster processing of
        the flows.
        """
        loop = asyncio.get_event_loop()
        loop.set_exception_handler(self.handle_loop_exception)

        processor = FlowProcessor(
            stop_profiler_threads_event=self.stop_profiler_threads,
            flows_to_process_q=self.flows_to_process_q,
            pending_flows_queue_lock=self.pending_flows_queue_lock,
            logger=self.logger,
            output_dir=self.output_dir,
            redis_port=self.redis_port,
            conf=self.conf,
            slips_args=self.args,
            main_pid=self.ppid,
            start_redis_server=False,  # connect to an already running redis
            # server, don't start a new one
        )
        # this function returns when the current thread is done processing
        # all flows, aka when stop_profiler_threads is set
        await processor.start()
        print(f"@@@@@@@@@@@@@@@@ {os.getpid()} {id(self.db)}")

    def should_stop(self):
        """
        overrides Imodule's should_stop()
        the common Imodule's should_stop() stop when there's no msg in
        each channel and the termination event is set
        since this module is the one responsible for signaling the
        termination event (via process_manager) then it doesnt make sense
        to check for it. it will never be set before this module stops.
        """
        return False

    def join_profiler_threads(self):
        # wait for the profiler threads to complete
        for thread in self.profiler_threads:
            thread.join()

    async def shutdown_gracefully(self):
        self.stop_profiler_threads.set()
        # wait for all flows to be processed by the profiler threads.
        self.join_profiler_threads()
        # close the queues to avoid deadlocks.
        # this step SHOULD NEVER be done before closing the threads
        self.flows_to_process_q.close()
        self.profiler_queue.close()

        await self.db.set_new_incoming_flows(False)
        self.mark_process_as_done_processing()

    def read_configuration(self):
        self.client_ips: List[
            Union[IPv4Network, IPv6Network, IPv4Address, IPv6Address]
        ]
        self.client_ips = self.conf.client_ips()

    def pre_main(self):
        client_ips = [str(ip) for ip in self.client_ips]
        if client_ips:
            self.print(f"Used client IPs: {green(', '.join(client_ips))}")
        self.start_profiler_threads()

    def new_reload_whitelist_msg_handler(self):
        """
        listen on reload_whitelist channel in case whitelist.conf is changed,
        we need to process the new changes

        PS: if whitelist.conf is edited using pycharm
        a msg will be sent to this channel on every keypress,
        because pycharm saves files automatically
        otherwise this channel will get a msg only when
        whitelist.conf is modified and saved to disk
        """
        self.whitelist.update()

    def mark_process_as_done_processing(self):
        """
        is called to mark this process as done processing so
        slips.py would know when to terminate
        """
        # signal slips.py that this process is done
        self.print(
            "Marking Profiler as done processing.", log_to_logfiles_only=True
        )
        self.done_processing.release()
        self.print("Profiler is done processing.", log_to_logfiles_only=True)
        self.is_profiler_done_event.set()
        self.print(
            "Profiler is done telling input.py " "that it's done processing.",
            log_to_logfiles_only=True,
        )

    async def main(self):
        # we use the double queue thing here because we cant have
        msg = self.get_msg_from_q(self.profiler_queue)
        if not msg:
            # this function is called in a loop in IAsyncModule,
            # so if there's no msg, it will wait for a new one
            return False

        # ALYA, DO NOT REMOVE THIS CHECK
        # without it, there's no way this module will know it's
        # time to stop and no new flows are coming
        if self.is_stop_msg(msg):
            # shutdown gracefully will be called by IAsyncModule() once this
            # function returns 1
            return 1

        with self.pending_flows_queue_lock:
            self.flows_to_process_q.put(msg)
