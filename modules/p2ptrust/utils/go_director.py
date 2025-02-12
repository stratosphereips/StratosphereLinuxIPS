# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import base64
import binascii
import json
from typing import Dict
import time


from slips_files.common.printer import Printer
from slips_files.core.output import Output
from modules.p2ptrust.utils.utils import (
    validate_ip_address,
    validate_timestamp,
    get_ip_info_from_slips,
    send_evaluation_to_go,
)
from modules.p2ptrust.trust.trustdb import TrustDB
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Attacker,
    EvidenceType,
    IoCType,
    Direction,
)


class GoDirector:
    """Class that deals with requests and reports from the go part of p2ptrust
    The reports from other peers are processed and inserted into the database
     directly.
    Requests from other peers are validated, data is read from the database
    and from slips, and the response is sent.
    If peer sends invalid data, his reputation is lowered.
    """

    name = "P2P Go Director"

    def __init__(
        self,
        logger: Output,
        trustdb: TrustDB,
        db,
        storage_name: str,
        override_p2p: bool = False,
        report_func=None,
        request_func=None,
        gopy_channel: str = "p2p_gopy",
        pygo_channel: str = "p2p_pygo",
        p2p_reports_logfile: str = "p2p_reports.log",
    ):
        self.printer = Printer(logger, self.name)

        # todo what is override_p2p
        if override_p2p and not (report_func and request_func):
            raise Exception(
                "Override_p2p set but not provided appropriate functions"
            )
        self.trustdb = trustdb
        self.pygo_channel = pygo_channel
        self.storage_name = storage_name
        self.override_p2p = override_p2p
        self.report_func = report_func
        self.request_func = request_func
        # clear the logfile
        open(p2p_reports_logfile, "w").close()
        self.reports_logfile = open(p2p_reports_logfile, "a")
        self.print(f"Storing peer reports in {p2p_reports_logfile}")
        # TODO: there should be some better mechanism to add new processing
        #  functions.. Maybe load from files?
        self.evaluation_processors = {
            "score_confidence": self.process_evaluation_score_confidence
        }
        self.key_type_processors = {"ip": validate_ip_address}
        self.read_configuration()
        self.db = db

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def read_configuration(self):
        conf = ConfigParser()
        self.width = conf.get_tw_width_as_float()

    def log(self, text: str):
        """
        Writes the log text to p2p_reports.log
        """
        now = time.time()
        human_readable_datetime = utils.convert_format(
            now, utils.alerts_format
        )
        self.reports_logfile.write(f"{human_readable_datetime} - {text}\n")

    def handle_gopy_data(self, data_dict: dict):
        """
        Method that receives raw data from peers sent into p2p_gopy redis channel
        """
        try:
            message_type = data_dict["message_type"]
            message_contents = data_dict["message_contents"]
            if message_type == "peer_update":
                # update in peers reliability or IP address.
                self.process_go_update(message_contents)

            elif message_type == "go_data":
                # a peer request or update
                self.process_go_data(message_contents)

            else:
                self.print(f"Invalid command: {message_type}", 0, 2)

        except json.decoder.JSONDecodeError:
            self.print(
                f"Couldn't load message from pigeon - invalid Json from the pigeon: {data_dict}",
                0,
                1,
            )

        except KeyError:
            self.print(
                f"Json from the pigeon: {data_dict} doesn't contain "
                "expected values message_type or message_contents",
                0,
                1,
            )

    def process_go_data(self, report: dict) -> None:
        """Process peer updates, requests and reports sent by the go layer

        The data is expected to be a list of messages received from go peers.
        They are parsed and inserted into the database.
        If a message does not comply with the format, the reporter's reputation is lowered.
        """
        # "message_type":"go_data",
        # "message_contents":{"reporter":"aconcagua","report_time":1649445643,"message":
        # "eyJtZXNzY..."}}

        # check that the data was parsed correctly in the go part of the app
        # if there were any issues, the reports list will be empty

        # report is the dictionary containing reporter, report_time and message

        # if intersection of a set of expected keys and the actual keys has four items, it means all keys are there
        key_reporter = "reporter"
        key_report_time = "report_time"
        key_message = "message"

        # expected_keys = {key_reporter, key_report_time, key_message}
        # if the overlap of the two sets is smaller than the set of keys, some keys are missing. The & operator
        # picks the items that are present in both sets: {2, 4, 6, 8, 10, 12} & {3, 6, 9, 12, 15} = {3, 12}

        report_time = validate_timestamp(report[key_report_time])
        if report_time is None:
            self.print("Invalid timestamp", 0, 2)
            return

        reporter = report[key_reporter]
        message = report[key_message]
        # decode b64
        message_type, data = self.validate_message(message)

        self.print(
            f"[The Network -> Slips] Received msg {data} from peer {reporter}"
        )

        if message_type == "report":
            # a peer reporting an IP
            self.process_message_report(reporter, report_time, data)

        elif message_type == "request":
            # a peer requesting info about an ip
            self.process_message_request(reporter, report_time, data)

        elif message_type == "blame":
            # TODO SLIPS doesn't getthis kind of msgs at all. all reports are treated as one
            # self.print("blame is not implemented yet", 0, 2)
            # calls process_message_report in p2ptrust.py
            # which gives the report to evidenceProcess to decide whether to block or not
            self.report_func(reporter, report_time, data)

        else:
            # TODO: lower reputation
            self.print(
                f"Peer {report} sent unknown message type "
                f"{message_type}: {data}",
                0,
                2,
            )
            self.print("Peer sent unknown message type", 0, 2)

    def validate_message(self, message: str) -> (str, dict):
        """
        Check that message is formatted correctly, read message type and
         return decoded data.

        :param message: base64 encoded message sent by the peer
        :return: message type, message as dictionary
        """

        # message is in json in base64
        try:
            decoded = base64.b64decode(message)
            data = json.loads(decoded)
            return data["message_type"], data

        except binascii.Error:
            self.print("base64 cannot be parsed properly", 0, 2)

        except json.decoder.JSONDecodeError:
            self.print("Peer sent invalid json", 0, 2)

        except KeyError:
            self.print("Peer didn't specify message type", 0, 2)

        return "", {}

    def validate_message_request(self, data: Dict) -> bool:
        """
        Validate keys in message request. Check for corrupted fields and also
         supported fields
        """
        try:
            key = data["key"]
            key_type = data["key_type"]
            evaluation_type = data["evaluation_type"]
        except KeyError:
            self.print("Correct keys are missing in the message", 0, 2)
            # TODO: lower reputation
            return False

        # validate key_type and key
        if key_type != "ip":
            self.print(f"Module can't process key type {key_type}", 0, 2)
            return False

        if not self.key_type_processors[key_type](key):
            self.print(
                f"Provided key {key} isn't a valid value for "
                f"it's type {key_type}",
                0,
                2,
            )
            # TODO: lower reputation
            return False

        # validate evaluation type
        if evaluation_type != "score_confidence":
            self.print(
                f"Module can't process evaluation type " f"{evaluation_type}",
                0,
                2,
            )
            return False
        return True

    def process_message_request(
        self, reporter: str, _: int, data: Dict
    ) -> None:
        """
        Process and answer a msg from a peer that requests info about an IP

        Details are read from the request, and response is read from slips
         database.
        Response data is formatted as json
        and sent to the peer that asked.

        :param reporter: The peer that sent the request
        :param _: Time of receiving the request, provided by the go part
        :param data: Request data
        :return: None. Result is sent directly to the peer
        """
        # validate keys in message
        if not self.validate_message_request(data):
            return

        key = data["key"]
        self.print(
            f"[The Network -> Slips] request about {key} from: {reporter}",
        )

        #  override_p2p is false by default
        if self.override_p2p:
            # print("Overriding p2p")
            # calls respond_to_message_request in p2ptrust.py
            self.request_func(key, reporter)
        else:
            # self.print("Not overriding p2p")
            self.respond_to_message_request(key, reporter)

    def respond_to_message_request(self, key, reporter):
        """
        Gets the info about the IP the peer asked about, and send it to the network
        """
        score, confidence = get_ip_info_from_slips(key, self.db)
        if score is not None:
            send_evaluation_to_go(
                key, score, confidence, reporter, self.pygo_channel, self.db
            )
            self.print(
                f"[Slips -> The Network] Slips responded with info score={score} "
                f"confidence={confidence} about IP: {key} to {reporter}.",
                2,
                0,
            )
            # print(f"[Slips -> The Network] Slips responded with info score={score}
            # confidence={confidence} about IP: {key} to {reporter}.")
        else:
            self.print(
                f"[Slips -> The Network] Slips has no info about IP:"
                f" {key}. Not responding to {reporter}",
                2,
                0,
            )

    def process_message_report(
        self, reporter: str, report_time: int, data: dict
    ):
        """
        Handle a report from a peer

        Details are read from the report and inserted into the database.

        :param reporter: The peer that sent the report
        :param report_time: Time of receiving the report, provided by
        the go part
        :param data: Report data
        :return: None. Result is saved to the database
        """

        # validate keys in message
        try:
            key = data["key"]
            key_type = data["key_type"]
            evaluation_type = data["evaluation_type"]
            evaluation = data["evaluation"]
        except KeyError:
            self.print("Correct keys are missing in the message", 0, 2)
            # TODO: lower reputation
            return

        # validate keytype and key
        if key_type not in self.key_type_processors:
            self.print("Module can't process given key type", 0, 2)
            return

        if not self.key_type_processors[key_type](key):
            self.print("Provided key isn't a valid value for it's type", 0, 2)
            # TODO: lower reputation
            return

        # validate evaluation type
        if evaluation_type not in self.evaluation_processors:
            self.print("Module can't process given evaluation type", 0, 2)
            return

        # after making sure that the data received from peers is valid,
        # pass the report to p2ptrust module
        # to decide what to do with it
        if self.override_p2p:
            # calls process_message_report in p2ptrust.py
            self.report_func(reporter, report_time, data)
            return

        self.evaluation_processors[evaluation_type](
            reporter, report_time, key_type, key, evaluation
        )
        if evaluation is not None:
            msg = (
                f"[The Network -> Slips] Peer report about {key} "
                f"Evaluation: {evaluation}"
            )
            self.print(msg)
            # log the reporter too
            msg += f" from peer: {reporter}"
            self.log(msg)
        # TODO: evaluate data from peer and asses if it was good or not.
        #       For invalid base64 etc, note that the node is bad

    def process_evaluation_score_confidence(
        self,
        reporter: str,
        report_time: int,
        key_type: str,
        key: str,
        evaluation: dict,
    ):
        """
        Handle reported score and confidence from another peer

        Data is read from provided dictionary, and saved into the database.

        :param reporter: The peer that sent the data
        :param report_time: Time of receiving the data, provided by the go part
        :param key_type: The type of key the peer is reporting (only "ip" is
        supported now)
        :param key: The key itself
        :param evaluation: Dictionary containing score and confidence values
        :return: None, data is saved to the database
        """

        if evaluation is None:
            self.print(
                f"Peer {reporter} has no data to share about {key}", 2, 0
            )
            return

        if not isinstance(evaluation, dict):
            self.print("Evaluation is not a dictionary", 0, 2)
            # TODO: lower reputation
            return

        # check that fields are present and with correct type
        try:
            score = float(evaluation["score"])
            confidence = float(evaluation["confidence"])
        except KeyError:
            self.print("Score or confidence are missing", 0, 2)
            # TODO: lower reputation
            return
        except ValueError:
            self.print("Score or confidence have wrong data type", 0, 2)
            # TODO: lower reputation
            return

        # validate value ranges (must be from <0, 1>)
        if score < -1 or score > 1:
            self.print("Score value is out of bounds", 0, 2)
            # TODO: lower reputation
            return

        if confidence < 0 or confidence > 1:
            self.print("Confidence value is out of bounds", 0, 2)
            # TODO: lower reputation
            return

        self.trustdb.insert_new_go_report(
            reporter, key_type, key, score, confidence, report_time
        )
        result = (
            f"Data processing ok: reporter {reporter}, report time "
            f"{report_time}, key {key} ({key_type}), "
            f"score {score}, confidence {confidence}"
        )
        self.print(result, 2, 0)
        # print(f"*** [debugging p2p] ***  stored a report about about
        # {key} from {reporter} in p2p_reports key in the db ")
        # save all report info in the db
        # convert ts to human readable format
        report_info = {
            "reporter": reporter,
            "report_time": utils.convert_format(
                report_time, utils.alerts_format
            ),
        }
        report_info.update(evaluation)
        self.db.store_p2p_report(key, report_info)

        # create a new profile for the reported ip
        # with the width from slips.yaml and the starttime as the report time
        if key_type == "ip":
            profileid_of_attacker = f"profile_{key}"
            self.db.add_profile(profileid_of_attacker, report_time)
            self.set_evidence_p2p_report(
                key,
                reporter,
                score,
                confidence,
                report_time,
                profileid_of_attacker,
            )

    def set_evidence_p2p_report(
        self: str,
        ip: str,
        reporter: str,
        score: float,
        confidence: float,
        timestamp: str,
        profileid_of_attacker: str,
    ):
        """
        set evidence for the newly created attacker
        profile stating that it attacked another peer
        """
        threat_level = utils.threat_level_to_string(score)

        # confidence depends on how long the connection
        # scale the confidence from 0 to 1, 1 means 24 hours long
        last_update_time, reporter_ip = self.trustdb.get_ip_of_peer(reporter)

        # this should never happen. if we have a report,
        # we will have a reporter and will have the ip of the reporter
        # but just in case
        if not reporter_ip:
            reporter_ip = ""

        description = (
            f"attacking another peer: {reporter_ip} "
            f"({reporter}). confidence: {confidence}"
        )

        # get the tw of this report time
        if twid := self.db.get_tw_of_ts(profileid_of_attacker, timestamp):
            twid = twid[0]
        else:
            # create a new twid for the attacker profile that has the
            # report time to add this evidence to
            twid = self.db.get_timewindow(timestamp, profileid_of_attacker)

        timestamp = utils.convert_format(timestamp, utils.alerts_format)
        evidence = Evidence(
            evidence_type=EvidenceType.P2P_REPORT,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=ip
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=ip),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[""],
            timestamp=timestamp,
        )

        self.db.set_evidence(evidence)

    def process_go_update(self, data: dict) -> None:
        """
        Handle update in peers reliability or IP address.

        The message is expected to be JSON string, and it should contain data
         according to the specified format.
        It must have the field `peerid`, which specifies the peer that is
        being updated,
        and then values to update: `ip` or `reliability`.
        It is OK if only one of these is provided.
        Additionally, `timestamp` may be set, but is not mandatory - if it is
        missing, current time will be used.
        :param message: A string sent from go, should be json as specified above
        :return: None
        """
        ip_address, reliability, peerid, timestamp = "", "", "", ""
        try:
            peerid = data["peerid"]
        except KeyError:
            self.print("Peerid missing", 0, 1)
            return

        # timestamp is optional. If it is not provided (or is wrong), it is set to None, and None timestamp is replaced
        # with current time in the database
        try:
            timestamp = data["timestamp"]
            timestamp = validate_timestamp(timestamp)
            if timestamp is None:
                self.print("Timestamp is invalid", 2, 0)
        except KeyError:
            self.print(f"Timestamp is missing from data {data}", 2, 0)
            timestamp = None

        try:
            reliability = float(data["reliability"])
            self.trustdb.insert_go_reliability(
                peerid, reliability, timestamp=timestamp
            )
        except KeyError:
            self.print("Reliability missing", 2, 0)
        except ValueError:
            self.print("Reliability is not a float", 2, 0)

        try:
            ip_address = data["ip"]
            if not validate_ip_address(ip_address):
                self.print(f"IP address {ip_address} is invalid", 2, 0)
                return
            self.trustdb.insert_go_ip_pairing(
                peerid, ip_address, timestamp=timestamp
            )
            msg = (
                f"[The Network -> Slips] Peer update or new peer {peerid} "
                f"with IP: {ip_address} "
                f"Reliability: {reliability } "
            )

            self.print(
                msg,
                2,
                0,
            )
            self.log(msg)

        except KeyError:
            self.print("IP address missing", 2, 0)
            return
