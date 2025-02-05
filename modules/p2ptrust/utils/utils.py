# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import base64
import configparser
import ipaddress
import time
import json
from typing import Union, Dict


# TODO: add outputQueue printing to this file (or remove all prints, they are debug anyway)


#
# DATA VALIDATION METHODS
#
def validate_ip_address(ip: str) -> bool:
    """
    Make sure that the given string is a valid IP address

    :param ip: The IP address to validate
    :return: True if it is ok, False if it isn't an IP
    """

    try:
        # this fails on invalid ip address
        ipaddress.ip_address(ip)
    except ValueError:
        return False

    return True


threat_levels = {
    "info": 0,
    "low": 0.2,
    "medium": 0.5,
    "high": 0.8,
    "critical": 1,
}


def validate_timestamp(timestamp: str) -> Union[int, None]:
    """
    Make sure the given string is a timestamp between 0 and now

    :param timestamp: The string to validate
    :return: timestamp (or zero when validation failed) and success of the validation
    """

    try:
        # originally, I wanted to accept only strict ints, not floats. But for unix, it doesn't even matter. Also, the
        # int() function turns it into int, so any floating point stuff is removed.
        int_timestamp = int(timestamp)
    except ValueError:
        print("Timestamp is not a number")
        return None

    if int_timestamp > time.time() or int_timestamp < 0:
        print("Invalid timestamp value")
        return None

    return int_timestamp


def validate_go_reports(data: str) -> list:
    """
    Process data received from go. It should be a json list dumped as string.

    :param data: Data received from go
    :return: The parsed list. In case of error, the list will be empty.
    """

    # try parsing the json. If this fails, there is an error in the redis channel or in go code, not the remote peers
    try:
        reports = json.loads(data)
    except json.decoder.JSONDecodeError:
        print("Go send invalid json")
        return []

    if not isinstance(reports, list):
        print("Expected list, got something else")
        return []

    return reports


#
# READ DATA FROM REDIS, WRITE DATA TO REDIS
#


def get_ip_info_from_slips(ip_address: str, db) -> (float, float):
    """
    Get score and confidence on IP from Slips.

    :param ip_address: The IP address to check
    :return: Tuple with score and confidence. If data is not there, (None, None) is returned instead.
    """

    # poll new info from redis
    ip_info = db.get_ip_info(ip_address)

    # There is a bug in the database where sometimes False is returned when key is not found. Correctly, dictionary
    # should be always returned, even if it is empty. This check cannot be simplified to `if not ip_info`, because I
    # want the empty dictionary to be handled by the read data function.
    # TODO: when database is fixed and doesn't return booleans, remove this IF statement
    if ip_info is False:
        return None, None

    slips_score, slips_confidence = read_data_from_ip_info(ip_info)
    # check that both values were provided
    # TODO by Martin: Dita does not handle scenario when only confidence is None, is it intentional?
    return (
        (None, None)
        if slips_score is None
        else (slips_score, slips_confidence)
    )


# parse data from redis
def read_data_from_ip_info(ip_info: dict) -> (float, float):
    """
    Get score and confidence from the data that is saved in Redis.

    :param ip_info: The redis data for one IP address
    :return: Tuple with score and confidence. If data is not there,
    (None, None) is returned instead.
    """
    # the higher the score, the more malicious this ip
    try:
        if "threat_level" in ip_info:
            score = threat_levels[ip_info["threat_level"]]
        else:
            score = ip_info["score"]

        confidence = ip_info["confidence"]
        try:
            confidence = float(confidence)
        except ValueError:
            # sometimes the confidence is stored as a float,
            # and sometimes it's stored like this 'confidence: 0.6'
            # #TODO see what stores it in the second format instead of this try except
            confidence = float(confidence.split()[-1])

        return float(score), confidence
    except KeyError:
        return None, None


def save_ip_report_to_db(
    ip, score, confidence, network_trust, db, timestamp=None
):
    if timestamp is None:
        timestamp = time.time()

    report_data = {
        "score": score,
        "confidence": confidence,
        "network_score": network_trust,
        "timestamp": timestamp,
    }

    # store it in p2p_reports key
    # print(f"*** [debugging p2p] ***  stored a report about
    # {ip} in p2p_Reports and IPsInfo keys")
    db.store_p2p_report(ip, report_data)

    # store it in IPsInfo key
    wrapped_data = {"p2p4slips": report_data}
    db.set_ip_info(ip, wrapped_data)


#
# SEND COMMUNICATION TO GO
#
def build_go_message(
    message_type: str,
    key_type: str,
    key: str,
    evaluation_type: str,
    evaluation=None,
) -> dict:
    """
    Assemble parameters to one dictionary, with keys that are expected by the remote peer.

    :param message_type: Type of message (request, report, blame...)
    :param key_type: Type of key, usually "ip"
    :param key: The key the message is about
    :param evaluation_type: Type of evaluation that is reported (for report and blame) or expected (for request message)
    :param evaluation: The score that is being reported (for report and blame). This can be left out for request message
    :return: A dictionary with proper values set.
    """

    message = {
        "message_type": message_type,
        "key_type": key_type,
        "key": key,
        "evaluation_type": evaluation_type,
    }
    if message_type != "request":
        message["evaluation"] = evaluation
    return message


def build_score_confidence(score: float, confidence: float) -> dict:
    """
    Build the dictionary with score and confidence

    :param score: The score value
    :param confidence: The confidence value
    :return: The evaluation dictionary
    """

    return {"score": score, "confidence": confidence}


def send_evaluation_to_go(
    ip: str,
    score: float,
    confidence: float,
    recipient: str,
    channel_name: str,
    db,
) -> None:
    """
    Take data and send it to a peer as report.

    :param ip: The IP that is being reported
    :param score: The score for that IP
    :param confidence: The confidence for that IP
    :param recipient: The peer that should receive the report. Use "*" wildcard to broadcast to everyone
    :return: None
    """

    evaluation_raw = build_score_confidence(score, confidence)
    message_raw = build_go_message(
        "report", "ip", ip, "score_confidence", evaluation=evaluation_raw
    )

    send_message_to_go(ip, recipient, channel_name, message_raw, db)


def send_message_to_go(
    ip: str, recipient: str, channel_name: str, msg: Dict, db
):
    """
    Send raw msg as json and b64 to other peer.

    :param ip: The IP that is being reported
    :param recipient: The peer that should receive the report. Use "*" wildcard to broadcast to everyone
    :param channel_name name of channel
    :param msg dictionary message
    :return: None
    """
    message_json = json.dumps(msg)
    message_b64 = base64.b64encode(bytes(message_json, "ascii")).decode()

    send_b64_to_go(message_b64, recipient, channel_name, db)


def send_blame_to_go(
    ip: str, score: float, confidence: float, channel_name: str, db
) -> None:
    """
    Take data and send it to a peer as a blame.

    :param ip: The IP that is being blamed
    :param score: The score for that IP
    :param confidence: The confidence for that IP
    :return: None
    """

    recipient = "*"
    evaluation_raw = build_score_confidence(score, confidence)
    message_raw = build_go_message(
        "blame", "ip", ip, "score_confidence", evaluation=evaluation_raw
    )

    message_json = json.dumps(message_raw)
    message_b64 = base64.b64encode(bytes(message_json, "ascii")).decode()

    send_b64_to_go(message_b64, recipient, channel_name, db)


def send_request_to_go(ip: str, channel_name: str, db) -> None:
    """
    Send a request about an IP to peers.

    There is no return value. Peers might answer and the answer will be processed by this module eventually.

    :param ip: The IP that we are asking about
    :return: None
    """

    recipient = "*"
    message_raw = build_go_message("request", "ip", ip, "score_confidence")

    message_json = json.dumps(message_raw)
    message_b64 = base64.b64encode(bytes(message_json, "ascii")).decode()

    send_b64_to_go(message_b64, recipient, channel_name, db)


def send_b64_to_go(
    message: str, recipient: str, channel_name: str, db
) -> None:
    """
    Send message to a peer

    Encode message as base64 string, assign the recipient for the message and send it to the go part.
    It will look for the recipient and send the message to him.
     Use "*" to broadcast to everybody.

    :param message: The message to send base64 encoded
    :param recipient: The peerID of the peer that should get the message,
                        or "*" to broadcast the message
    :return: None
    """

    data_raw = {"message": message, "recipient": recipient}
    data_json = json.dumps(data_raw)
    db.publish(channel_name, data_json)
    # only channel used right now is self.pygo_channel defined in p2ptrst.py
    decoded_data = base64.b64decode(message)
    data_json = json.loads(decoded_data.decode("utf-8"))


def read_configuration(config, section: str, name: str) -> str:
    """Read the configuration file for what we need"""
    # Get the time of log report
    try:
        conf_variable = config.config.get(section, name)
    except (
        configparser.NoOptionError,
        configparser.NoSectionError,
        NameError,
    ):
        # There is a conf, but there is no option, or no section or no configuration file specified
        conf_variable = None
    return conf_variable
