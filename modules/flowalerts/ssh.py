import contextlib
import json

from modules.flowalerts.timer_thread import TimerThread
from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils


class SSH(IFlowalertsAnalyzer):
    def init(self):
        # Cache list of connections that we already checked
        # in the timer thread for ssh check
        self.connections_checked_in_ssh_timer_thread = []
        # after this number of failed ssh logins, we alert pw guessing
        self.pw_guessing_threshold = 20
        self.read_configuration()
        self.password_guessing_cache = {}
        self.classifier = FlowClassifier()

    def name(self) -> str:
        return "ssh_analyzer"

    def read_configuration(self):
        conf = ConfigParser()
        self.ssh_succesful_detection_threshold = (
            conf.ssh_succesful_detection_threshold()
        )

    def detect_successful_ssh_by_slips(self, profileid, twid, flow):
        """
        Try Slips method to detect if SSH was successful by
        comparing all bytes sent and received to our threshold
        """
        # this is the ssh flow read from conn.log not ssh.log
        original_ssh_flow = self.db.get_flow(flow.uid)
        original_flow_uid = next(iter(original_ssh_flow))
        if original_ssh_flow[original_flow_uid]:
            ssh_flow_dict = json.loads(original_ssh_flow[original_flow_uid])
            size = ssh_flow_dict["sbytes"] + ssh_flow_dict["dbytes"]
            if size > self.ssh_succesful_detection_threshold:
                daddr = ssh_flow_dict["daddr"]
                saddr = ssh_flow_dict["saddr"]
                # Set the evidence because there is no
                # easier way to show how Slips detected
                # the successful ssh and not Zeek
                self.set_evidence.ssh_successful(
                    twid,
                    saddr,
                    daddr,
                    size,
                    flow.uid,
                    flow.timestamp,
                    by="Slips",
                )
                with contextlib.suppress(ValueError):
                    self.connections_checked_in_ssh_timer_thread.remove(
                        flow.uid
                    )
                return True

        elif flow.uid not in self.connections_checked_in_ssh_timer_thread:
            # It can happen that the original SSH flow is not in the DB yet
            # comes here if we haven't started the timer
            # thread for this connection before
            # mark this connection as checked
            # self.print(f'Starting the timer to check on {flow_dict}, uid {uid}.
            # time {datetime.datetime.now()}')
            self.connections_checked_in_ssh_timer_thread.append(flow.uid)
            params = [profileid, twid, flow]
            timer = TimerThread(15, self.check_successful_ssh, params)
            timer.start()

    def detect_successful_ssh_by_zeek(self, profileid, twid, flow):
        """
        Check for auth_success: true in the given zeek flow
        """
        original_ssh_flow = self.db.search_tws_for_flow(
            profileid, twid, flow.uid
        )
        original_flow_uid = next(iter(original_ssh_flow))
        if original_ssh_flow[original_flow_uid]:
            ssh_flow_dict = json.loads(original_ssh_flow[original_flow_uid])
            daddr = ssh_flow_dict["daddr"]
            saddr = ssh_flow_dict["saddr"]
            size = ssh_flow_dict["sbytes"] + ssh_flow_dict["dbytes"]
            self.set_evidence.ssh_successful(
                twid,
                saddr,
                daddr,
                size,
                flow.uid,
                flow.timestamp,
                by="Zeek",
            )
            with contextlib.suppress(ValueError):
                self.connections_checked_in_ssh_timer_thread.remove(flow.uid)
            return True

        elif flow.uid not in self.connections_checked_in_ssh_timer_thread:
            # It can happen that the original SSH flow is not in the DB yet
            # comes here if we haven't started the timer thread
            # for this connection before
            # mark this connection as checked
            # self.print(f'Starting the timer to check on {flow_dict},
            # uid {uid}. time {datetime.datetime.now()}')
            self.connections_checked_in_ssh_timer_thread.append(flow.uid)
            params = [flow.uid, flow.timestamp, profileid, twid]
            timer = TimerThread(15, self.detect_successful_ssh_by_zeek, params)
            timer.start()

    def check_successful_ssh(self, profileid, twid, flow):
        """
        Function to check if an SSH connection logged in successfully
        """
        # it's true in zeek json files, T in zeke tab files
        if flow.auth_success in ["true", "T"]:
            self.detect_successful_ssh_by_zeek(profileid, twid, flow)
        else:
            self.detect_successful_ssh_by_slips(profileid, twid, flow)

    def check_ssh_password_guessing(self, profileid, twid, flow):
        """
        This detection is only done when there's a failed ssh attempt
        alerts ssh pw bruteforce when there's more than
        20 failed attempts by the same ip to the same IP
        """
        if flow.auth_success in ("true", "T"):
            return False

        cache_key = f"{profileid}-{twid}-{flow.daddr}"
        # update the number of times this ip performed a failed ssh login
        if cache_key in self.password_guessing_cache:
            self.password_guessing_cache[cache_key].append(flow.uid)
        else:
            self.password_guessing_cache = {cache_key: [flow.uid]}

        conn_count = len(self.password_guessing_cache[cache_key])

        if conn_count >= self.pw_guessing_threshold:
            description = f"SSH password guessing to IP {flow.daddr}"
            uids = self.password_guessing_cache[cache_key]
            self.set_evidence.pw_guessing(
                description, flow.timestamp, twid, uids, by="Slips"
            )
            # reset the counter
            del self.password_guessing_cache[cache_key]

    def analyze(self, msg):
        if not utils.is_msg_intended_for(msg, "new_ssh"):
            return

        data = msg["data"]
        data = json.loads(data)
        profileid = data["profileid"]
        twid = data["twid"]
        flow = self.classifier.convert_to_flow_obj(data["flow"])

        self.check_successful_ssh(profileid, twid, flow)
        self.check_ssh_password_guessing(profileid, twid, flow)
