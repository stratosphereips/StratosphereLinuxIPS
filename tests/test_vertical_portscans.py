# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
import random
import binascii
import base64
import os

from slips_files.common.slips_utils import utils
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
    "last_logged_ports, current_dports, expected",
    [
        (0, 1, False),
        (1, 9, False),
        (1, 10, True),
        (10, 99, False),
        (10, 100, True),
        (100, 999, False),
        (100, 1000, True),
    ],
)
def test_check_if_enough_dports_to_trigger_an_evidence(
    mock_db,
    last_logged_ports,
    current_dports,
    expected,
):
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    dstip = "8.8.8.8"

    vertical_ps = ModuleFactory().create_vertical_portscan_obj()

    twid_identifier = f"{profileid}:{twid}:dstip:{dstip}"

    if last_logged_ports > 0:
        vertical_ps.cached_thresholds_per_tw[twid_identifier] = utils.log10(
            last_logged_ports
        )

    result = vertical_ps.check_if_enough_dports_to_trigger_an_evidence(
        profileid=profileid,
        twid=twid,
        dstip=dstip,
        amount_of_dports=current_dports,
    )

    assert result is expected
