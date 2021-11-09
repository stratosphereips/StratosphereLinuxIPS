import base64
import configparser
import ipaddress
import time
import json
from typing import Union, Dict

from slips_files.core.database import __database__


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


# TODO by Martin: This function is not used
# TODO However, it's checking if go_reports are in a list (as documentation says that it should be like this)
# TODO used implementation so far counts only with dict. What is correct way?
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

    if type(reports) != list:
        print("Expected list, got something else")
        return []

    return reports


#
# READ DATA FROM REDIS, WRITE DATA TO REDIS
#

# TODO by Martin: remove second arg when usage of this func in p2ptrust.py is modified and verified
def get_ip_info_from_slips(ip_address: str, storage_name: str = "") -> (float, float):
    """
    Get score and confidence on IP from Slips.

    :param ip_address: The IP address to check
    :return: Tuple with score and confidence. If data is not there, (None, None) is returned instead.
    """

    # poll new info from redis
    ip_info = __database__.getIPData(ip_address)

    # There is a bug in the database where sometimes False is returned when key is not found. Correctly, dictionary
    # should be always returned, even if it is empty. This check cannot be simplified to `if not ip_info`, because I
    # want the empty dictionary to be handled by the read data function.
    # TODO: when database is fixed and doesn't return booleans, remove this IF statement
    if ip_info is False:
        return None, None

    slips_score, slips_confidence = read_data_from_ip_info(ip_info)
    # check that both values were provided
    # TODO by Martin: Dita does not handle scenario when only conficence is None, is it intentional?
    if slips_score is None:
        return None, None

    return slips_score, slips_confidence


# TODO by Martin: this func is copied from database.py, refactor usage to the original one everywhere and delete this
def getIPData(ip, storage_name):
    """
    Return information about this IP from the IPs has
    Returns a dictionary
    We need to separate these three cases:
    1- IP is in the DB without data
    2- IP is in the DB with data
    3- IP is not in the DB
    """
    data = __database__.r.hget(storage_name, ip)
    if data or data == {}:
        # This means the IP was in the database, with or without data
        # Convert the data
        data = json.loads(data)
        # print(f'In the DB: IP {ip}, and data {data}')
    else:
        # The IP was not in the DB
        data = False
        # print(f'In the DB: IP {ip}, and data {data}')
    # Always return a dictionary
    return data


# parse data from redis
def read_data_from_ip_info(ip_info: dict) -> (float, float):
    """
    Get score and confidence from the data that is saved in Redis.

    :param ip_info: The redis data for one IP address
    :return: Tuple with score and confidence. If data is not there, (None, None) is returned instead.
    """

    try:
        score = ip_info["score"]
        confidence = ip_info["confidence"]
        return float(score), float(confidence)
    except KeyError:
        return None, None


# TODO by martin: Following 3 functions should probably be in database.py file
def save_ip_report_to_db(ip, score, confidence, network_trust, storage_name, timestamp=None):
    # TODO: because of bugs in the database, I can only save this once.

    if timestamp is None:
        timestamp = time.time()

    report_data = {"score": score, "confidence": confidence, "network_score": network_trust, "timestamp": timestamp}
    wrapped_data = {"p2p4slips": report_data}

    # TODO: remove the first call after database is fixed
    setNewIP(ip, storage_name)
    setInfoForIPs(ip, wrapped_data, storage_name)


# TODO by martin: copied from database.py. Why? I guess remove it
def setNewIP(ip, storage_name):
    data = getIPData(ip, storage_name)
    if data is False:
        __database__.r.hset(storage_name, ip, '{}')
        __database__.publish('new_ip', ip)


# TODO by martin: copied from database.py. Why? I guess remove it
def setInfoForIPs(ip, wrapped_data, storage_name):
    data = getIPData(ip, storage_name)

    if not data:
        setNewIP(ip, storage_name)
        data = getIPData(ip, storage_name)

    for key in iter(wrapped_data):
        if type(data) == str:
            data = json.loads(data)

        data_to_store = wrapped_data[key]
        try:
            _ = data[key]
        except KeyError:
            data[key] = data_to_store
            newdata_str = json.dumps(data)
            __database__.r.hset(storage_name, ip, newdata_str)
            # Publish the changes
            __database__.r.publish('ip_info_change', ip)


#
# SEND COMMUNICATION TO GO
#

def build_go_message(message_type: str, key_type: str, key: str, evaluation_type: str, evaluation=None) -> dict:
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
        "evaluation_type": evaluation_type
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

    evaluation = {
        "score": score,
        "confidence": confidence
    }
    return evaluation


def send_evaluation_to_go(ip: str, score: float, confidence: float, recipient: str, channel_name: str) -> None:
    """
    Take data and send it to a peer as report.

    :param ip: The IP that is being reported
    :param score: The score for that IP
    :param confidence: The confidence for that IP
    :param recipient: The peer that should receive the report. Use "*" wildcard to broadcast to everyone
    :return: None
    """

    evaluation_raw = build_score_confidence(score, confidence)
    message_raw = build_go_message("report", "ip", ip, "score_confidence", evaluation=evaluation_raw)

    send_message_to_go(ip, recipient, channel_name, message_raw)


def send_empty_evaluation_to_go(ip: str, recipient: str, channel_name: str) -> None:
    """
    Creates empty message and sends it to recipient;ip

    :param ip: The IP that is being reported
    :param recipient: The peer that should receive the report. Use "*" wildcard to broadcast to everyone
    :return: None
    """
    message_raw = build_go_message("report", "ip", ip, "score_confidence", evaluation=None)
    send_message_to_go(ip, recipient, channel_name, message_raw)


def send_message_to_go(ip: str, recipient: str, channel_name: str, msg: Dict):
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

    send_b64_to_go(message_b64, recipient, channel_name)


def send_blame_to_go(ip: str, score: float, confidence: float, channel_name: str) -> None:
    """
    Take data and send it to a peer as a blame.

    :param ip: The IP that is being blamed
    :param score: The score for that IP
    :param confidence: The confidence for that IP
    :return: None
    """

    recipient = "*"
    evaluation_raw = build_score_confidence(score, confidence)
    message_raw = build_go_message("blame", "ip", ip, "score_confidence", evaluation=evaluation_raw)

    message_json = json.dumps(message_raw)
    message_b64 = base64.b64encode(bytes(message_json, "ascii")).decode()

    send_b64_to_go(message_b64, recipient, channel_name)


def send_request_to_go(ip: str, channel_name: str) -> None:
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

    send_b64_to_go(message_b64, recipient, channel_name)


def send_b64_to_go(message: str, recipient: str, channel_name: str) -> None:
    """
    Send message to a peer

    Encode message as base64 string, assign the recipient for the message and send it to the go part. It will look for
    the recipient and send the message to him. Use "*" to broadcast to everybody.

    :param message: The message to send
    :param recipient: The peerID of the peer that should get the message, or "*" to broadcast the message
    :return: None
    """

    data_raw = {"message": message, "recipient": recipient}
    data_json = json.dumps(data_raw)
    print("[publish trust -> go]", data_json)
    __database__.publish(channel_name, data_json)

    decoded_data = base64.b64decode(message)
    print("[raw published data]", decoded_data)


def read_configuration(config, section: str, name: str) -> str:
    """ Read the configuration file for what we need """
    # Get the time of log report
    try:
        conf_variable = config.config.get(section, name)
    except (configparser.NoOptionError, configparser.NoSectionError, NameError):
        # There is a conf, but there is no option, or no section or no configuration file specified
        conf_variable = None
    return conf_variable
