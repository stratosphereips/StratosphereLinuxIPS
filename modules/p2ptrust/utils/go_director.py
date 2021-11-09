import base64
import binascii
import configparser
import json
from typing import Dict

from modules.p2ptrust.utils.utils import validate_ip_address, validate_timestamp, \
    get_ip_info_from_slips, send_evaluation_to_go, send_empty_evaluation_to_go
from modules.p2ptrust.utils.printer import Printer
from modules.p2ptrust.trust.trustdb import TrustDB


class GoDirector:
    """Class that deals with requests and reports from the go part of p2ptrust

    The reports from other peers are processed and inserted into the database directly.
    Requests from other peers are validated, data is read from the database and from slips, and the response is sent.
    If peer sends invalid data, his reputation is lowered.
    """

    def __init__(self,
                 printer: Printer,
                 trustdb: TrustDB,
                 config: configparser.ConfigParser,
                 storage_name: str,
                 override_p2p: bool = False,
                 report_func=None,
                 request_func=None,
                 gopy_channel: str = "p2p_gopy",
                 pygo_channel: str = "p2p_pygo"):

        if override_p2p and not (report_func and request_func):
            raise Exception("Override_p2p set but not provided appropriate functions")

        self.printer = printer
        self.trustdb = trustdb
        self.config = config
        self.pygo_channel = pygo_channel
        self.storage_name = storage_name
        self.override_p2p = override_p2p
        self.report_func = report_func
        self.request_func = request_func

        # TODO: there should be some better mechanism to add new processing functions.. Maybe load from files?
        self.evaluation_processors = {"score_confidence": self.process_evaluation_score_confidence}
        self.key_type_processors = {"ip": validate_ip_address}

    def print(self, text: str, verbose: int = 1, debug: int = 0) -> None:
        self.printer.print("[TrustDB] " + text, verbose, debug)

    def handle_gopy_data(self, data: str):
        """
        Method that receives raw data sent into p2p_gopy redis channel
        """
        try:
            data_dict = json.loads(data)
            message_type = data_dict["message_type"]
            message_contents = data_dict["message_contents"]

            if message_type == "peer_update":
                self.process_go_update(message_contents)

            elif message_type == "go_data":
                self.process_go_data(message_contents)

            else:
                self.print("Invalid command: " + message_type)

        except json.decoder.JSONDecodeError:
            self.print("Couldn't load message from pigeon - invalid json")

        except KeyError:
            self.print("Json from the pigeon doesn't contain expected values")

    def process_go_data(self, report: dict) -> None:
        """Process data sent by the go layer

        The data is expected to be a list of messages received from go peers. They are parsed and inserted into the
         database. If a message does not comply with the format, the reporter's reputation is lowered.
        """

        # check that the data was parsed correctly in the go part of the app
        # if there were any issues, the reports list will be empty

        # report is the dictionary containing reporter, report_time and message

        # if intersection of a set of expected keys and the actual keys has four items, it means all keys are there
        key_reporter = "reporter"
        key_report_time = "report_time"
        key_message = "message"

        expected_keys = {key_reporter, key_report_time, key_message}
        # if the overlap of the two sets is smaller than the set of keys, some keys are missing. The & operator
        # picks the items that are present in both sets: {2, 4, 6, 8, 10, 12} & {3, 6, 9, 12, 15} = {3, 12}
        if len(expected_keys & set(report.keys())) != 3:
            self.print("Some key is missing in report")
            return

        report_time = validate_timestamp(report[key_report_time])
        if report_time is None:
            self.print("Invalid timestamp")
            return

        reporter = report[key_reporter]
        message = report[key_message]

        message_type, data = self.validate_message(message)

        if message_type == "report":
            self.process_message_report(reporter, report_time, data)

        elif message_type == "request":
            self.process_message_request(reporter, report_time, data)

        elif message_type == "blame":
            self.print("blame is not implemented yet")

        else:
            # TODO: lower reputation
            self.print("Peer sent unknown message type")

    def validate_message(self, message: str) -> (str, dict):
        """
        Check that message is formatted correctly, read message type and return decoded data.

        :param message: base64 encoded message sent by the peer
        :return: message type, message as dictionary
        """

        # message is in json in base64
        try:
            decoded = base64.b64decode(message)
            data = json.loads(decoded)
            return data["message_type"], data

        except binascii.Error:
            self.print("base64 cannot be parsed properly")

        except json.decoder.JSONDecodeError:
            self.print("Peer sent invalid json")

        except KeyError:
            self.print("Peer didn't specify message type")

        return "", {}

    def validate_message_request(self, data: Dict) -> bool:
        """
        Validate keys in message request. Check for corrupted fields and also supported fields
        """
        try:
            key = data["key"]
            key_type = data["key_type"]
            evaluation_type = data["evaluation_type"]
        except KeyError:
            self.print("Correct keys are missing in the message")
            # TODO: lower reputation
            return False

        # validate key_type and key
        if key_type != "ip":
            self.print(f"Module can't process key type {key_type}")
            return False

        if not self.key_type_processors[key_type](key):
            self.print("Provided key isn't a valid value for it's type")
            # TODO: lower reputation
            return False

        # validate evaluation type
        if evaluation_type != "score_confidence":
            self.print(f"Module can't process evaluation type {evaluation_type}")
            return False
        return True

    def process_message_request(self, reporter: str, _: int, data: Dict) -> None:
        """
        Handle data request from a peer

        Details are read from the request, and response is read from slips database. Response data is formatted as json
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
        if self.override_p2p:
            print("Overriding p2p")
            self.request_func(key, reporter)
        else:
            print("Not overriding p2p")
            self.respond_to_message_request(key, reporter)

    def respond_to_message_request(self, key, reporter):
        score, confidence = get_ip_info_from_slips(key)
        if score is not None:
            send_evaluation_to_go(key, score, confidence, reporter, self.pygo_channel)
        else:
            send_empty_evaluation_to_go(key, reporter, self.pygo_channel)

    def process_message_report(self, reporter: str, report_time: int, data: dict):
        """
        Handle a report from a peer

        Details are read from the report and inserted into the database.

        :param reporter: The peer that sent the report
        :param report_time: Time of receiving the report, provided by the go part
        :param data: Report data
        :return: None. Result is saved to the database
        """

        if self.override_p2p:
            self.report_func(reporter, report_time, data)
            return

        # validate keys in message
        try:
            key = data["key"]
            key_type = data["key_type"]
            evaluation_type = data["evaluation_type"]
            evaluation = data["evaluation"]
        except KeyError:
            self.print("Correct keys are missing in the message")
            # TODO: lower reputation
            return

        # validate keytype and key
        if key_type not in self.key_type_processors:
            self.print("Module can't process given key type")
            return

        if not self.key_type_processors[key_type](key):
            self.print("Provided key isn't a valid value for it's type")
            # TODO: lower reputation
            return

        # validate evaluation type
        if evaluation_type not in self.evaluation_processors:
            self.print("Module can't process given evaluation type")
            return

        self.evaluation_processors[evaluation_type](reporter, report_time, key_type, key, evaluation)

        # TODO: evaluate data from peer and asses if it was good or not.
        #       For invalid base64 etc, note that the node is bad

    def process_evaluation_score_confidence(self,
                                            reporter: str,
                                            report_time: int,
                                            key_type: str,
                                            key: str,
                                            evaluation: dict):
        """
        Handle reported score and confidence

        Data is read from provided dictionary, and saved into the database.

        :param reporter: The peer that sent the data
        :param report_time: Time of receiving the data, provided by the go part
        :param key_type: The type of key the peer is reporting (only "ip" is supported now)
        :param key: The key itself
        :param evaluation: Dictionary containing score and confidence values
        :return: None, data is saved to the database
        """

        if evaluation is None:
            self.print("Peer has no data to share")
            return

        if type(evaluation) != dict:
            self.print("Evaluation is not a dictionary")
            # TODO: lower reputation
            return

        # check that fields are present and with correct type
        try:
            score = float(evaluation["score"])
            confidence = float(evaluation["confidence"])
        except KeyError:
            self.print("Score or confidence are missing")
            # TODO: lower reputation
            return
        except ValueError:
            self.print("Score or confidence have wrong data type")
            # TODO: lower reputation
            return

        # validate value ranges (must be from <0, 1>)
        if score < -1 or score > 1:
            self.print("Score value is out of bounds")
            # TODO: lower reputation
            return

        if confidence < 0 or confidence > 1:
            self.print("Confidence value is out of bounds")
            # TODO: lower reputation
            return

        self.trustdb.insert_new_go_report(reporter, key_type, key, score, confidence, report_time)
        result = f"Data processing ok: reporter {reporter}, report time {report_time}, key {key} ({key_type}), " \
                 f"score {score}, confidence {confidence}"
        self.print(result)

    def process_go_update(self, data: dict) -> None:
        """
        Handle update in peers reliability or IP address.

        The message is expected to be JSON string, and it should contain data according to the specified format. It must
        have the field `peerid`, which specifies the peer that is being updated, and then values to update: `ip` or
        `reliability`. It is OK if only one of these is provided. Additionally, `timestamp` may be set, but is not
        mandatory - if it is missing, current time will be used.
        :param message: A string sent from go, should be json as specified above
        :return: None
        """

        try:
            peerid = data["peerid"]
        except KeyError:
            self.print("Peerid missing")
            return

        # timestamp is optional. If it is not provided (or is wrong), it is set to None, and None timestamp is replaced
        # with current time in the database
        try:
            timestamp = data["timestamp"]
            timestamp = validate_timestamp(timestamp)
            if timestamp is None:
                self.print("Timestamp is invalid")
        except KeyError:
            self.print("Timestamp is missing")
            self.print("Data: " + str(data))
            timestamp = None

        try:
            reliability = float(data["reliability"])
            self.trustdb.insert_go_reliability(peerid, reliability, timestamp=timestamp)
        except KeyError:
            self.print("Reliability missing")
        except ValueError:
            self.print("Reliability is not a float")

        try:
            ip_address = data["ip"]
            if not validate_ip_address(ip_address):
                self.print("IP address is invalid")
                return
            self.trustdb.insert_go_ip_pairing(peerid, ip_address, timestamp=timestamp)
        except KeyError:
            self.print("IP address missing")
            return
