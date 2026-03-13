# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz,
# stratosphere@aic.fel.cvut.cz

import threading
import multiprocessing
from typing import List
import os
import time

from multiprocessing import Process
from slips_files.common.style import (
    green,
)
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.evidence_logger import EvidenceLogger
from slips_files.common.abstracts.icore import ICore
from slips_files.core.evidence_handler_worker import EvidenceHandlerWorker

IS_IN_A_DOCKER_CONTAINER = os.environ.get("IS_IN_A_DOCKER_CONTAINER", False)
DEFAULT_EVIDENCE_HANDLER_WORKERS = 3


# Evidence Process
class EvidenceHandler(ICore):
    name = "EvidenceHandler"

    def init(self):
        self.read_configuration()
        # to keep track of the number of generated evidence
        self.db.init_evidence_number()
        # thats just a tmp value, this variable will be set and used when
        # the module is stopping.
        self.last_msg_received_time = time.time()
        # we don't want the workers to subscribe to channels and
        # read from there, in that case all workers will process the same
        # msg. instead we use a queue, so that each worker processes a
        # unique msg.
        self.evidence_worker_queue = multiprocessing.Queue(maxsize=30000000)
        self.evidence_worker_child_processes: List[Process] = []

        # A thread that handing I/O to disk (writing evidence to log files)
        self.logger_stop_signal = threading.Event()
        self.evidence_logger_q = multiprocessing.Queue(maxsize=30000000)
        self.evidence_logger = EvidenceLogger(
            logger_stop_signal=self.logger_stop_signal,
            evidence_logger_q=self.evidence_logger_q,
            output_dir=self.output_dir,
        )
        self.logger_thread = threading.Thread(
            target=self.evidence_logger.run_logger_thread,
            daemon=True,
            name="thread_that_handles_evidence_logging_to_disk",
        )
        utils.start_thread(self.logger_thread, self.db)

    def subscribe_to_channels(self):
        self.c1 = self.db.subscribe("evidence_added")
        self.c2 = self.db.subscribe("new_blame")
        self.channels = {
            "evidence_added": self.c1,
            "new_blame": self.c2,
        }

    def read_configuration(self):
        conf = ConfigParser()
        self.width: float = conf.get_tw_width_in_seconds()
        self.detection_threshold = conf.evidence_detection_threshold()
        self.print(
            f"Detection Threshold: {self.detection_threshold} "
            f"attacks per minute "
            f"({self.detection_threshold * int(self.width) / 60} "
            f"in the current time window width)",
            2,
            0,
        )

    def shutdown_gracefully(self):
        self.stop_evidence_workers()
        self.logger_stop_signal.set()
        try:
            self.logger_thread.join(timeout=5)
        except Exception:
            pass

        used_queues = [
            self.evidence_worker_queue,
            self.evidence_logger_q,
        ]

        for q in used_queues:
            q.cancel_join_thread()
            q.close()

    def stop_evidence_workers(self):
        for _ in self.evidence_worker_child_processes:
            self.evidence_worker_queue.put("stop")

        for process in self.evidence_worker_child_processes:
            try:
                process.join()
            except (OSError, ChildProcessError):
                pass

    def start_evidence_worker(self, worker_id: int = None):
        worker_name = f"EvidenceHandlerWorker_Process_{worker_id}"
        worker = EvidenceHandlerWorker(
            logger=self.logger,
            output_dir=self.output_dir,
            redis_port=self.redis_port,
            termination_event=self.termination_event,
            conf=self.conf,
            ppid=self.ppid,
            slips_args=self.args,
            bloom_filters_manager=self.bloom_filters,
            name=worker_name,
            evidence_queue=self.evidence_worker_queue,
            evidence_logger_q=self.evidence_logger_q,
        )
        worker.start()
        self.evidence_worker_child_processes.append(worker)

    def should_stop(self) -> bool:
        """
        Overrides imodule's should_stop() to make sure thi smodule only
        stops after 1 minute of the last received evidence.
        """
        if not self.termination_event.is_set():
            return False

        if self.is_msg_received_in_any_channel():
            self.last_msg_received_time = time.time()
            return False

        # no new msgs are received in any of the channels here
        # wait some extra time for new evidence to arrive
        # without this, slips has problems processing the last evidence
        # sent by some of the modules.
        if time.time() - self.last_msg_received_time < 30:
            return False

        # 1 min passed since the last evidence with no new msgs. stop.
        return True

    def pre_main(self):
        self.print(f"Using threshold: {green(self.detection_threshold)}")
        for worker_id in range(DEFAULT_EVIDENCE_HANDLER_WORKERS):
            self.start_evidence_worker(worker_id)

    def main(self):
        while not self.should_stop():
            if msg := self.get_msg("evidence_added"):
                self.evidence_worker_queue.put(
                    {
                        "channel": "evidence_added",
                        "message": msg,
                    }
                )

            if msg := self.get_msg("new_blame"):
                self.evidence_worker_queue.put(
                    {
                        "channel": "new_blame",
                        "message": msg,
                    }
                )
