import csv
import json
import os
import queue
import threading
import traceback
import multiprocessing

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.performance_paths import get_performance_csv_path
from slips_files.common.slips_utils import utils

ACCUMULATED_THREAT_LEVEL_CSV = "accumulated_threat_level.csv"


class EvidenceLogger:
    def __init__(
        self,
        logger_stop_signal: threading.Event,
        evidence_logger_q: multiprocessing.Queue,
        output_dir: str,
        slips_args=None,
    ):
        self.logger_stop_signal = logger_stop_signal
        self.evidence_logger_q = evidence_logger_q
        self.output_dir = output_dir
        self.args = slips_args
        self.read_configuration()

        # clear output/alerts.log
        self.logfile = self.clean_file(self.output_dir, "alerts.log")
        utils.change_logfiles_ownership(self.logfile.name, self.UID, self.GID)
        # clear output/alerts.json
        self.jsonfile = self.clean_file(self.output_dir, "alerts.json")
        utils.change_logfiles_ownership(self.jsonfile.name, self.UID, self.GID)
        self.latency_file = None
        self.latency_writer = None
        self.accumulated_threat_level_file = None
        self.accumulated_threat_level_writer = None
        self.last_accumulated_threat_level_row = None
        self._init_accumulated_threat_level_file()
        if self.generate_performance_plots:
            self._init_latency_file()

    def read_configuration(self):
        conf = ConfigParser()
        self.GID = conf.get_GID()
        self.UID = conf.get_UID()
        self.generate_performance_plots = (
            conf.generate_performance_plots() is True
        )

    def _init_latency_file(self):
        self.latency_file = self.clean_file(
            self.output_dir,
            get_performance_csv_path(self.output_dir, "latency.csv"),
        )
        utils.change_logfiles_ownership(
            self.latency_file.name, self.UID, self.GID
        )
        self.latency_writer = csv.writer(self.latency_file)
        self.latency_writer.writerow(["ts", "evidence_id", "latency"])
        self.latency_file.flush()

    def _init_accumulated_threat_level_file(self) -> None:
        """
        Open the monitored profile accumulated threat level CSV.
        """
        self.accumulated_threat_level_file = self.clean_file(
            self.output_dir,
            ACCUMULATED_THREAT_LEVEL_CSV,
        )
        utils.change_logfiles_ownership(
            self.accumulated_threat_level_file.name, self.UID, self.GID
        )
        self.accumulated_threat_level_writer = csv.writer(
            self.accumulated_threat_level_file
        )
        self.accumulated_threat_level_writer.writerow(
            [
                "profile",
                "timewindow",
                "time_since_slips_started",
                "accumulated_threat_level",
                "risk_accumulated_threat_level",
            ]
        )
        self.accumulated_threat_level_file.flush()

    def clean_file(self, output_dir, file_to_clean):
        """
        Clear the file if exists and return an open handle to it
        """
        if os.path.isabs(file_to_clean):
            logfile_path = file_to_clean
        else:
            logfile_path = os.path.join(output_dir, file_to_clean)

        logfile_dir = os.path.dirname(logfile_path)
        if logfile_dir:
            os.makedirs(logfile_dir, exist_ok=True)

        if os.path.exists(logfile_path):
            utils.initialize_logfile(
                logfile_path,
                getattr(self.args, "is_slips_started_by_an_update", False),
                create_parent_dirs=False,
            )
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
        except KeyboardInterrupt:
            return
        except Exception:
            return

    def print_to_latency_csv(self, row: dict):
        if self.latency_writer is None or self.latency_file is None:
            return

        try:
            self.latency_writer.writerow(
                [row["ts"], row["evidence_id"], row["latency"]]
            )
            self.latency_file.flush()  # flush Python buffer
            os.fsync(self.latency_file.fileno())  # flush OS buffer
        except KeyboardInterrupt:
            return True
        except Exception:
            return

    def print_to_accumulated_threat_level_csv(self, row: dict) -> None:
        """
        Write one monitored profile accumulated threat level CSV row.

        Parameters:
            row: Mapping with profile, timewindow, elapsed time, ATL, and
                risk-weighted ATL values.
        """
        if (
            self.accumulated_threat_level_writer is None
            or self.accumulated_threat_level_file is None
        ):
            return

        try:
            csv_row = [
                str(row["profile"]),
                str(row["timewindow"]),
                str(row["time_since_slips_started"]),
                str(row["accumulated_threat_level"]),
                str(row["risk_accumulated_threat_level"]),
            ]
            if csv_row == self.last_accumulated_threat_level_row:
                return

            self.accumulated_threat_level_writer.writerow(csv_row)
            self.last_accumulated_threat_level_row = csv_row
            self.accumulated_threat_level_file.flush()
            os.fsync(self.accumulated_threat_level_file.fileno())
        except KeyboardInterrupt:
            return
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
        while True:
            try:
                msg = self.evidence_logger_q.get(timeout=1)
            except queue.Empty:
                if self.logger_stop_signal.is_set():
                    break
                continue
            except Exception:
                if self.logger_stop_signal.is_set():
                    break
                continue

            destination = msg["where"]

            if destination == "alerts.log":
                self.print_to_alerts_logfile(msg["to_log"])

            elif destination == "alerts.json":
                self.print_to_alerts_json(msg["to_log"])
            elif destination == "latency.csv":
                self.print_to_latency_csv(msg["to_log"])
            elif destination == ACCUMULATED_THREAT_LEVEL_CSV:
                self.print_to_accumulated_threat_level_csv(msg["to_log"])

        self.shutdown_gracefully()

    def shutdown_gracefully(self):
        self.logfile.close()
        self.jsonfile.close()
        if self.latency_file is not None:
            self.latency_file.close()
        if self.accumulated_threat_level_file is not None:
            self.accumulated_threat_level_file.close()
