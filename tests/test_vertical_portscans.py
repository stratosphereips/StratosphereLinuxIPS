import pytest
import random
import binascii
import base64
import os
from tests.module_factory import ModuleFactory

def get_random_uid():
    return base64.b64encode(binascii.b2a_hex(os.urandom(9))).decode('utf-8')


def not_enough_dports_to_reach_the_threshold(mock_db):
    """
    returns a dict with conns to dport that are not enough
    to reach the minimum dports to trigger the first scan
    """
    module = ModuleFactory().create_vertical_portscan_obj(mock_db)

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
        random_port = random.randint(0, 65535)
        res[ip]['dstports'].update({random_port: 1})

    # Return the list of random integers
    return res

def enough_dports_to_reach_the_threshold(mock_db):
    """
    returns conns to dport that are not enough
    to reach the minimum dports to trigger the first scan
    """
    module = ModuleFactory().create_vertical_portscan_obj(mock_db)

    # get a random list of ints(ports) that are below the threshold
    # Generate a random number between 0 and threshold
    amount_of_dports: int = random.randint(
        module.port_scan_minimum_dports, 100)

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
        random_port = random.randint(0, 65535)
        res[ip]['dstports'].update({random_port: 1})

    # Return the list of random integers
    return res


def not_enough_dports_to_combine_1_evidence(mock_db):
    """
    returns dports that are not enough to combine an evidence
    any number of dports within the range threshold -> threshold +15 is ok
    here, aka won't be enough
    :param key:
    """
    module = ModuleFactory().create_vertical_portscan_obj(mock_db)

    # get a random list of ints(ports) that are below the threshold
    # Generate a random number between 0 and threshold
    amount_of_dports: int = random.randint(
        module.port_scan_minimum_dports, 100)

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
        random_port = random.randint(0, 65535)
        res[ip]['dstports'].update({random_port: 1})

    # Return the list of random integers
    return res



@pytest.mark.parametrize(
    'get_test_conns, expected_return_val',
    [
        (not_enough_dports_to_reach_the_threshold, False),
        (enough_dports_to_reach_the_threshold, True),
    ]
)
def test_min_dports_threshold(
        get_test_conns,
        expected_return_val: bool,
        mock_db
    ):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)

    profileid = 'profile_1.1.1.1'
    timewindow = 'timewindow0'
    dstip = '8.8.8.8'

    conns: dict = get_test_conns(mock_db)
    mock_db.get_data_from_profile_tw.return_value = conns

    cache_key = vertical_ps.get_cache_key(profileid, timewindow, dstip)
    amount_of_dports = len(conns[dstip]['dstports'])

    assert vertical_ps.check_if_enough_dports_to_trigger_an_evidence(
        cache_key, amount_of_dports
    ) == expected_return_val



@pytest.mark.parametrize(
    'number_of_pending_evidence, expected_return_val',
    [
        (0, True),
        (1, False),
        (2, False),
        (3, True),
        (6, True),
    ]
)
def test_combining_evidence(
        number_of_pending_evidence,
        expected_return_val: bool,
        mock_db
    ):
    """
    first evidence will be alerted, the rest will be combined
    """
    profileid = 'profile_1.1.1.1'
    timewindow = 'timewindow0'
    dstip = '8.8.8.8'

    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    key: str = vertical_ps.get_cache_key(profileid, timewindow, dstip)
    # get a random bunch of dstips, this dict is not important
    dstips:dict = enough_dports_to_reach_the_threshold(mock_db)
    amount_of_dports = len(dstips[dstip]['dstports'])

    pkts_sent = sum(dstips[dstip]['dstports'].values())

    for evidence_ctr in range(number_of_pending_evidence+1):
        # as if there's 1 pending evience
        # module.pending_vertical_ps_evidence[key].append(1)
        # this will add 2 evidence to the pending evidence list
        evidence = {
                'timestamp': dstips[dstip]['stime'],
                'pkts_sent': pkts_sent ,
                'protocol': 'TCP',
                'profileid': profileid,
                'twid': timewindow,
                'uid': dstips[dstip]['uid'],
                'amount_of_dports': amount_of_dports,
                'dstip': dstip,
                'state': 'Not Established',
            }
        # in the first iteration, enough_to_combine is gonna be True bc
        # it's the first evidence ever
        # next 2 should be false

        enough_to_combine = vertical_ps.decide_if_time_to_set_evidence_or_combine(
            evidence,
            key
        )

        if evidence_ctr == 0:
            continue

    assert enough_to_combine == expected_return_val


@pytest.mark.parametrize(
    'prev_amount_of_dports, cur_amount_of_dports, expected_return_val',
    [
        (0, 5 , True),
        (5, 6, False),
        (5, 8, False),
        (5, 15, True),
        (15, 20, True),
    ]
)
def test_check_if_enough_dports_to_trigger_an_evidence(
        mock_db,
        prev_amount_of_dports,
        cur_amount_of_dports,
        expected_return_val):
    """
    slip sdetects can based on the number of current dports scanned to the
    number of the ports scanned before
        we make sure the amount of dports reported each evidence
        is higher than the previous one +5
    """
    profileid = 'profile_1.1.1.1'
    timewindow = 'timewindow0'
    dstip = '8.8.8.8'

    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)

    key: str = vertical_ps.get_cache_key(profileid, timewindow, dstip)
    vertical_ps.cached_tw_thresholds[key] = prev_amount_of_dports

    enough: bool = vertical_ps.check_if_enough_dports_to_trigger_an_evidence(
        key, cur_amount_of_dports)
    assert enough == expected_return_val
