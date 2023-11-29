import pytest
import random

from tests.module_factory import ModuleFactory

def enough_dports_to_reach_the_threshold(mock_rdb):
    """
    returns conns to dport that are not enough
    to reach the minimum dports to trigger the first scan
    """
    module = ModuleFactory().create_horizontal_portscan_obj(mock_rdb)

    # get a random list of ints(ports) that are below the threshold
    # Generate a random number between 0 and threshold
    amount_of_dports: int = random.randint(
        module.port_scan_minimum_dips, 100)

    dport = 5555
    res = {
        dport: {
            'dstips': {
                '8.8.8.8': {
                    'dstports': {
                        1234: 1,
                        2222: 1,
                        12234: 1,
                        5555: 1,
                        }
                    }
                }
        }
    }

    return res


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
        mock_rdb
    ):
    """
    first evidence will be alerted, the rest will be combined
    """
    profileid = 'profile_1.1.1.1'
    timewindow = 'timewindow0'
    dstip = '8.8.8.8'
    dport = 5555

    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_rdb)
    key: str = horizontal_ps.get_cache_key(profileid, timewindow, dstip)

    # get a random bunch of dstips, this dict is not important
    dports: dict = enough_dports_to_reach_the_threshold(mock_rdb)
    dstips: dict = dports[dport]['dstips']


    for evidence_ctr in range(number_of_pending_evidence+1):
        # as if there's 1 pending evience
        # module.pending_vertical_ps_evidence[key].append(1)
        # this will add 2 evidence to the pending evidence list
        evidence = {
                'protocol': 'TCP',
                'profileid': profileid,
                'twid': timewindow,
                'uids': [],
                'uid': [],
                'dport':dport,
                'pkts_sent': 5,
                'timestamp': '1234.54',
                'stime': '1234.54',
                'state': 'Not Established',
                'amount_of_dips': 70
            }
        # in the first iteration, enough_to_combine is gonna be True bc
        # it's the first evidence ever
        # next 2 should be false

        enough_to_combine: bool = \
            horizontal_ps.decide_if_time_to_set_evidence_or_combine(
                evidence,
                key
        )

        if evidence_ctr == 0:
            continue

    assert enough_to_combine == expected_return_val

@pytest.mark.parametrize(
    'prev_amount_of_dstips, cur_amount_of_dstips, expected_return_val',
    [
        (0, 5 , True),
        (5, 6, False),
        (5, 8, False),
        (5, 15, True),
        (15, 20, True),
    ]
)
def test_check_if_enough_dports_to_trigger_an_evidence(mock_rdb,
                                   prev_amount_of_dstips,
                                   cur_amount_of_dstips,
                                   expected_return_val):
    """
    slip sdetects can based on the number of current dports scanned to the
    number of the ports scanned before
        we make sure the amount of dports reported each evidence
        is higher than the previous one +5
    """
    profileid = 'profile_1.1.1.1'
    timewindow = 'timewindow0'
    dport = 5555

    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_rdb)

    key: str = horizontal_ps.get_cache_key(profileid, timewindow, dport)
    horizontal_ps.cached_tw_thresholds[key] = prev_amount_of_dstips

    enough: bool = horizontal_ps.check_if_enough_dstips_to_trigger_an_evidence(
        key, cur_amount_of_dstips)
    assert enough == expected_return_val
