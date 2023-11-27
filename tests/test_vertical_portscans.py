import pytest
import random
import binascii
import base64
import os
from tests.module_factory import ModuleFactory

def get_random_uid():
    return base64.b64encode(binascii.b2a_hex(os.urandom(9))).decode('utf-8')


def not_enough_dports_to_reach_the_threshold(mock_rdb):
    """
    returns a dict with conns to dport that are not enough
    to reach the minimum dports to trigger the first scan
    """
    module = ModuleFactory().create_vertical_portscan_obj(mock_rdb)

    # get a random list of ints(ports) that are below the threshold
    # Generate a random number between 0 and threshold
    amount_of_dports: int = random.randint(0, module.port_scan_minimum_dports-1)

    ip: str = '8.8.8.8'
    res = {
        ip: {
            'stime': '1700828217.314165',
            'uid': [],
            'dstports': {}
        }
    }

    # Generate x random integers and append them to the list
    for _ in range(amount_of_dports):
        random_int = random.randint(0, 65535)
        res[ip]['dstports'].update({random_int: 1})

    # Return the list of random integers
    return res

@pytest.mark.parametrize(
    'get_test_conns, expected_return_val',
    [
        (not_enough_dports_to_reach_the_threshold, False),
        # (enough_dports_to_reach_the_threshold, True),
    ]
)
def test_vertical_portscan(get_test_conns,
                           expected_return_val: bool,
                           mock_rdb):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_rdb)

    profileid = 'profile_1.1.1.1'
    timewindow = 'timewindow0'
    dstip = '8.8.8.8'

    conns: dict = get_test_conns(mock_rdb)
    mock_rdb.get_data_from_profile_tw.return_value = conns

    cache_key = vertical_ps.get_cache_key(profileid, timewindow, dstip)
    amount_of_dports = len(conns[dstip]['dstports'])

    assert vertical_ps.check_if_enough_dports_to_trigger_an_evidence(
        cache_key, amount_of_dports
    ) == expected_return_val