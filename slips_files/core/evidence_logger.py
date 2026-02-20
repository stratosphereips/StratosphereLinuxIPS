import json
import os
import queue
import threading
import time
import traceback
from datetime import datetime
import csv

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils


class EvidenceLogger:
    def __init__(
        self,
        logger_stop_signal: threading.Event,
        evidence_logger_q: queue.Queue,
        output_dir: str,
    ):
        self.logger_stop_signal = logger_stop_signal
        self.evidence_logger_q = evidence_logger_q
        self.output_dir = output_dir
        self.read_configuration()

        # clear output/alerts.log
        self.logfile = self.clean_file(self.output_dir, "alerts.log")
        utils.change_logfiles_ownership(self.logfile.name, self.UID, self.GID)
        # clear output/alerts.json
        self.jsonfile = self.clean_file(self.output_dir, "alerts.json")
        utils.change_logfiles_ownership(self.jsonfile.name, self.UID, self.GID)
        # clear output/latency.csv
        self.latencyfile = self.clean_file(self.output_dir, "latency.csv")
        utils.change_logfiles_ownership(
            self.latencyfile.name, self.UID, self.GID
        )
        self._init_latency_csv()

    def read_configuration(self):
        conf = ConfigParser()
        self.GID = conf.get_GID()
        self.UID = conf.get_UID()

    def clean_file(self, output_dir, file_to_clean):
        """
        Clear the file if exists and return an open handle to it
        """
        logfile_path = os.path.join(output_dir, file_to_clean)
        if os.path.exists(logfile_path):
            open(logfile_path, "w").close()
        return open(logfile_path, "a")

    def print_to_alerts_logfile(self, data: str):
        """
        Add a new evidence line to the alerts.log
        """
        try:
            # write to alerts.log
            self.logfile.write(data)
            if not data.endswith("\n"):
                self.logfile.write("\n")
            self.logfile.flush()
        except KeyboardInterrupt:
            return True
        except Exception:
            self.print("Error in evidence_logger.print_to_alerts_logfile()")
            self.print(traceback.format_exc(), 0, 1)

    def print_to_alerts_json(self, idmef_evidence: dict):
        try:
            json.dump(idmef_evidence, self.jsonfile)
            self.jsonfile.write("\n")
            self.jsonfile.flush()  # flush Python buffer
            os.fsync(self.jsonfile.fileno())  # flush OS buffer
            self.log_latency_if_evidence(idmef_evidence)
        except KeyboardInterrupt:
            return
        except Exception:
            return

    def _init_latency_csv(self):
        try:
            writer = csv.writer(self.latencyfile)
            writer.writerow(
                ["evidence_id", "current_timestamp", "latency_in_seconds"]
            )
            self.latencyfile.flush()
        except Exception:
            return

    def log_latency_if_evidence(self, idmef_msg: dict):
        try:
            if idmef_msg.get("Status") != "Event":
                return
            start_time = idmef_msg.get("StartTime")
            create_time = idmef_msg.get("CreateTime")
            if not start_time or not create_time:
                return
            start_dt = datetime.fromisoformat(start_time)
            create_dt = datetime.fromisoformat(create_time)
            latency_seconds = (create_dt - start_dt).total_seconds()
            writer = csv.writer(self.latencyfile)
            writer.writerow(
                [
                    idmef_msg.get("ID"),
                    time.time(),
                    latency_seconds,
                ]
            )
            self.latencyfile.flush()
        except Exception:
            return

    def run_logger_thread(self):
        """
        runs forever in a loop reveiving msgs from evidence_handler and
        logging them to alert.log or alerts.json
        to avoid blocking evidence handler when high traffic attacks are
        happening, so slips can process evidence faster there while we log
        as fast as possible here
        """
        while not self.logger_stop_signal.is_set():
            try:
                msg = self.evidence_logger_q.get(timeout=1)
            except queue.Empty:
                continue
            except Exception:
                continue

            destination = msg["where"]

            if destination == "alerts.log":
                self.print_to_alerts_logfile(msg["to_log"])

            elif destination == "alerts.json":
                self.print_to_alerts_json(msg["to_log"])

        self.shutdown_gracefully()

    def shutdown_gracefully(self):
        self.logfile.close()
        self.jsonfile.close()
        self.latencyfile.close()
