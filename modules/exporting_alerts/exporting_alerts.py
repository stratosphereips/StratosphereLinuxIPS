# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import queue
import threading

from modules.exporting_alerts.slack_exporter import SlackExporter
from modules.exporting_alerts.stix_exporter import StixExporter
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.imodule import IModule


class ExportingAlerts(IModule):
    """
    Module to export alerts to slack and/or STIX
    You need to have the token in your environment
    variables to use this module
    """

    name = "Exporting Alerts"
    description = "Export alerts to slack or STIX format"
    authors = ["Alya Gomaa"]

    def init(self):
        self.slack = SlackExporter(self.logger, self.db)
        self.stix = StixExporter(self.logger, self.db)
        self.c1 = self.db.subscribe("export_evidence")
        self.channels = {"export_evidence": self.c1}
        self.print("Subscribed to export_evidence channel.", 1, 0)
        self.direct_export_q = None
        self.direct_export_stop = None
        self.direct_export_workers = []

    def _start_direct_export_workers(self):
        self.direct_export_q = queue.Queue()
        self.direct_export_stop = threading.Event()
        self.direct_export_workers = []
        for idx in range(self.stix.direct_export_workers):
            worker = threading.Thread(
                target=self._direct_export_worker,
                name=f"stix_direct_export_worker_{idx}",
                daemon=True,
            )
            worker.start()
            self.direct_export_workers.append(worker)
        self.stix._log_export(
            f"Direct export workers started count={len(self.direct_export_workers)}"
        )

    def _direct_export_worker(self):
        while True:
            if self.direct_export_stop and self.direct_export_stop.is_set():
                if self.direct_export_q and self.direct_export_q.empty():
                    return
            try:
                evidence = self.direct_export_q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self.stix.export_evidence_direct(evidence)
            finally:
                self.direct_export_q.task_done()

    def shutdown_gracefully(self):
        self.slack.shutdown_gracefully()
        if self.direct_export_stop:
            self.direct_export_stop.set()
            for worker in self.direct_export_workers:
                worker.join(timeout=5)
        self.stix.shutdown_gracefully()

    def pre_main(self):
        utils.drop_root_privs_permanently()

        export_to_slack = self.slack.should_export()
        export_to_stix = self.stix.should_export()

        if not export_to_slack and not export_to_stix:
            self.print(
                "Exporting Alerts module disabled (no export targets configured).",
                0,
                2,
            )
            return 1

        if export_to_slack:
            self.slack.send_init_msg()

        if export_to_stix and self.stix.direct_export:
            self._start_direct_export_workers()
        elif export_to_stix and self.stix.is_running_non_stop:
            # This thread is responsible for waiting n seconds before
            # each push to the stix server
            # it starts the timer when the first alert happens
            self.stix.start_exporting_thread()

    def remove_sensitive_info(self, evidence: dict) -> str:
        """
        removes the leaked location co-ords from the evidence
        description before exporting
        returns the description without sensitive info
        """
        if "NETWORK_GPS_LOCATION_LEAKED" not in evidence["evidence_type"]:
            return evidence["description"]

        description = evidence["description"]
        return description[: description.index("Leaked location")]

    def main(self):
        # a msg is sent here for each evidence that was part of an alert
        if msg := self.get_msg("export_evidence"):
            evidence = json.loads(msg["data"])
            self.print(
                f"[ExportingAlerts] Evidence {evidence.get('id')} "
                f"type={evidence.get('evidence_type')} received.",
                2,
                0,
            )
            description = self.remove_sensitive_info(evidence)
            if self.slack.should_export():
                srcip = evidence["profile"]["ip"]
                msg_to_send = f"Src IP {srcip} Detected {description}"
                self.slack.export(msg_to_send)

            if self.stix.should_export():
                if self.stix.direct_export:
                    if not self.direct_export_q:
                        self._start_direct_export_workers()
                    self.direct_export_q.put(evidence)
                    qsize = self.direct_export_q.qsize()
                    self.stix._log_export(
                        f"Direct export queued id={evidence.get('id')} "
                        f"queue_size={qsize}"
                    )
                else:
                    added_to_stix: bool = self.stix.add_to_stix_file(
                        evidence
                    )
                    if added_to_stix:
                        # now export to taxii
                        self.stix.export()
                    else:
                        self.print("Problem in add_to_stix_file()", 0, 3)
