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
import time

from multiprocessing import Process

from slips_files.common.output_paths import get_alerts_path_inside_output_dir
from slips_files.common.style import (
    green,
)
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.evidence_logger import EvidenceLogger
from slips_files.common.abstracts.icore import ICore
from slips_files.core.evidence_handler_worker import EvidenceHandlerWorker


DEFAULT_EVIDENCE_HANDLER_WORKERS = 3


# Evidence Process
class EvidenceHandler(ICore):
    name = "evidence_handler"

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
            output_dir=get_alerts_path_inside_output_dir(
                self.parent_output_dir
            ),
            slips_args=self.args,
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
        self.GID = conf.get_GID()
        self.UID = conf.get_UID()

        self.popup_alerts = conf.popup_alerts()
        # In docker, disable alerts no matter what slips.yaml says
        if IS_IN_A_DOCKER_CONTAINER:
            self.popup_alerts = False

    def handle_unable_to_log(self, failed_log, error=None):
        self.print(f"Error logging evidence/alert: {error}. {failed_log}.")

    def add_alert_to_json_log_file(self, alert: Alert):
        """
        Add a new alert/event line to our alerts.json file in json format.
        """
        idmef_alert: dict = self.idmefv2.convert_to_idmef_alert(alert)
        if not idmef_alert:
            self.handle_unable_to_log(alert, "Can't convert to IDMEF alert")
            return

        to_log = {
            "to_log": idmef_alert,
            "where": "alerts.json",
        }
        self.evidence_logger_q.put(to_log)

    def add_evidence_to_json_log_file(
        self,
        evidence,
        accumulated_threat_level: float = 0,
    ):
        """
        Add a new evidence line to our alerts.json file in json format.
        """
        idmef_evidence: dict = self.idmefv2.convert_to_idmef_event(evidence)
        if not idmef_evidence:
            self.handle_unable_to_log(
                evidence, "Can't convert to IDMEF evidence"
            )
            return

        try:
            idmef_evidence.update(
                {
                    "Note": json.dumps(
                        {
                            # this is all the uids of the flows that cause
                            # this evidence
                            "uids": evidence.uid,
                            "accumulated_threat_level": accumulated_threat_level,
                            "threat_level": str(evidence.threat_level),
                            "evidence_signal": str(
                                evidence.evidence_signal
                            ),
                            "timewindow": evidence.timewindow.number,
                        }
                    )
                }
            )

            to_log = {
                "to_log": idmef_evidence,
                "where": "alerts.json",
            }

            self.evidence_logger_q.put(to_log)

        except KeyboardInterrupt:
            return True
        except Exception as e:
            self.handle_unable_to_log(evidence, e)

    def add_to_log_file(self, data: str):
        """
        Add a new evidence line to the alerts.log and other log files if
        logging is enabled.
        """
        to_log = {"to_log": data, "where": "alerts.log"}
        self.evidence_logger_q.put(to_log)

    def log_alert(self, alert: Alert, blocked=False):
        """
        constructs the alert descript ion from the given alert and logs it
        to alerts.log and alerts.json
        :param blocked: bool. if the ip was blocked by the blocking module,
                we should say so in alerts.log, if not, we should say that
                we generated an alert
        """
        now = utils.get_human_readable_datetime()

        alert_description = (
            f"{alert.last_flow_datetime}: " f"Src IP {alert.profile.ip:26}. "
        )
        if blocked:
            # Add to log files that this srcip is being blocked
            alert_description += "Is blocked "
        else:
            alert_description += "Generated an alert "

        alert_description += (
            f"given enough evidence on timewindow "
            f"{alert.timewindow.number}. (real time {now})"
        )
        # log to alerts.log
        self.add_to_log_file(alert_description)
        # log to alerts.json
        self.add_alert_to_json_log_file(alert)

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
        worker_name = f"evidence_handler_worker_process_{worker_id}"
        worker = EvidenceHandlerWorker(
            logger=self.logger,
            output_dir=self.parent_output_dir,
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
