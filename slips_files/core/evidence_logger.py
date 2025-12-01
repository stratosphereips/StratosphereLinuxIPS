import json
import queue
import threading
import traceback
from typing import TextIO


class EvidenceLogger:
    def __init__(
        self,
        stop_signal: threading.Event,
        evidence_logger_q: queue.Queue,
        logfile: TextIO,
        jsonfile: TextIO,
    ):
        self.stop_signal = stop_signal
        self.evidence_logger_q = evidence_logger_q
        self.logfile = logfile
        self.jsonfile = jsonfile

    def print_to_alerts_logfile(self, data: str):
        """
        Add a new evidence line to the alerts.log and other log files if
        logging is enabled.
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
        while not self.stop_signal.is_set():
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
