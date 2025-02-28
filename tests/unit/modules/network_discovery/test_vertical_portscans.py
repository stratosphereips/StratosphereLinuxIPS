# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
import random
import binascii
import base64
import os
from tests.module_factory import ModuleFactory


def get_random_uid():
    return base64.b64encode(binascii.b2a_hex(os.urandom(9))).decode("utf-8")


def not_enough_dports_to_reach_the_threshold():
    """
    returns a dict with conns to dport that are not enough
    to reach the minimum dports to trigger the first scan
    """
    module = ModuleFactory().create_vertical_portscan_obj()

    # get a random list of ints(ports) that are below the threshold
    # Generate a random number between 0 and threshold
    amount_of_dports: int = random.randint(
        0, module.minimum_dports_to_set_evidence - 1
    )

    ip: str = "8.8.8.8"
    res = {ip: {"stime": "1700828217.314165", "uid": [], "dstports": {}}}

    # Generate x random integers and append them to the list
    for _ in range(amount_of_dports):
        random_port = random.randint(0, 65535)
        res[ip]["dstports"].update({random_port: 1})

    # Return the list of random integers
    return res


def enough_dports_to_reach_the_threshold():
    """
    returns conns to dport that are not enough
    to reach the minimum dports to trigger the first scan
    """
    module = ModuleFactory().create_vertical_portscan_obj()

    # get a random list of ints(ports) that are below the threshold
    # Generate a random number between 0 and threshold
    amount_of_dports: int = random.randint(
        module.minimum_dports_to_set_evidence, 100
    )

    ip: str = "8.8.8.8"
    res = {ip: {"stime": "1700828217.314165", "uid": [], "dstports": {}}}

    # Generate x random integers and append them to the list
    for _ in range(amount_of_dports):
        random_port = random.randint(0, 65535)
        res[ip]["dstports"].update({random_port: 1})

    # Return the list of random integers
    return res


def not_enough_dports_to_combine_1_evidence():
    """
    returns dports that are not enough to combine an evidence
    any number of dports within the range threshold -> threshold +15 is ok
    here, aka won't be enough
    :param key:
    """
    module = ModuleFactory().create_vertical_portscan_obj()

    # get a random list of ints(ports) that are below the threshold
    # Generate a random number between 0 and threshold
    amount_of_dports: int = random.randint(
        module.minimum_dports_to_set_evidence, 100
    )

    ip: str = "8.8.8.8"
    res = {ip: {"stime": "1700828217.314165", "uid": [], "dstports": {}}}

    # Generate x random integers and append them to the list
    for _ in range(amount_of_dports):
        random_port = random.randint(0, 65535)
        res[ip]["dstports"].update({random_port: 1})

    # Return the list of random integers
    return res


@pytest.mark.parametrize(
    "get_test_conns, expected_return_val",
    [
        (not_enough_dports_to_reach_the_threshold, False),
        (enough_dports_to_reach_the_threshold, True),
    ],
)
def test_min_dports_threshold(get_test_conns, expected_return_val: bool):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj()

    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dstip = "8.8.8.8"

    conns: dict = get_test_conns()
    vertical_ps.db.get_data_from_profile_tw.return_value = conns

    cache_key = vertical_ps.get_twid_identifier(profileid, timewindow, dstip)
    amount_of_dports = len(conns[dstip]["dstports"])

    assert (
        vertical_ps.check_if_enough_dports_to_trigger_an_evidence(
            cache_key, amount_of_dports
        )
        == expected_return_val
    )


@pytest.mark.parametrize(
    "ports_reported_last_evidence, cur_amount_of_dports, expected_return_val",
    [
        (0, 5, True),
        (5, 5, False),
        (5, 4, False),
        (5, 6, False),
        (5, 20, True),
        (20, 34, False),
        (20, 35, True),
    ],
)
def test_check_if_enough_dports_to_trigger_an_evidence(
    mock_db,
    ports_reported_last_evidence,
    cur_amount_of_dports,
    expected_return_val,
):
    """
    slip sdetects can based on the number of current dports scanned to the
    number of the ports scanned before
        we make sure the amount of dports reported each evidence
        is higher than the previous one +5
    """
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dstip = "8.8.8.8"

    vertical_ps = ModuleFactory().create_vertical_portscan_obj()

    key: str = vertical_ps.get_twid_identifier(profileid, timewindow, dstip)
    vertical_ps.cached_thresholds_per_tw[key] = ports_reported_last_evidence

    enough: bool = vertical_ps.check_if_enough_dports_to_trigger_an_evidence(
        key, cur_amount_of_dports
    )
    assert enough == expected_return_val
