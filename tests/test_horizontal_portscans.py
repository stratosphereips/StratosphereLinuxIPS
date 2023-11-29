import pytest

from tests.module_factory import ModuleFactory




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
