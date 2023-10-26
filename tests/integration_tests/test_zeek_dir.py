from tests.common_test_utils import (
        get_total_profiles,
        alerts_file,
        is_evidence_present,
        create_output_dir,
        has_errors,
        run_slips,
)
from tests.module_factory import ModuleFactory
import pytest
from ...slips import *
import shutil


@pytest.mark.parametrize(
    'zeek_dir_path,expected_profiles, expected_evidence,  output_dir, redis_port',
    [
        (
            'dataset/test9-mixed-zeek-dir',
            4,
            [
                'Incompatible certificate CN',
                'Malicious JA3: 6734f37431670b3ab4292b8f60f29984',
                'sending ARP packet to a destination address outside of local network',
                'broadcasting unsolicited ARP',
            ],
            'test9-mixed-zeek-dir/',
            6661,
        ),
        (
            'dataset/test16-malicious-zeek-dir',
            0,
            [
                'sending ARP packet to a destination address outside of local network',
                'broadcasting unsolicited ARP',
            ],
            'test16-malicious-zeek-dir/',
            6671,
        ),
        (
            'dataset/test14-malicious-zeek-dir',
            2,
            [
                'bad SMTP login to 80.75.42.226',
                'SMTP login bruteforce to 80.75.42.226. 3 logins in 10 seconds',
                'multiple empty HTTP connections to bing.com',
                'suspicious user-agent',
                'download of an executable',
                'GRE tunnel'
            ],
            'test14-malicious-zeek-dir/',
            6670
        ),
        (
            'dataset/test15-malicious-zeek-dir',
            2,
            [
                'SSH client version changing',
                'Incompatible certificate CN',
                'Malicious JA3: 6734f37431670b3ab4292b8f60f29984',
            ],
            'test15-malicious-zeek-dir',
            2345
        ),
        (
            'dataset/test10-mixed-zeek-dir',
            20,
            'horizontal port scan',
            'test10-mixed-zeek-dir/',
            6660,
        ),
    ],
)
def test_zeek_dir(
    zeek_dir_path,
    expected_profiles,
    expected_evidence,
    output_dir,
    redis_port,
):

    output_dir = create_output_dir(output_dir)

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -f {zeek_dir_path}  -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    run_slips(command)
    assert has_errors(output_dir) is False

    database = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)
    profiles = database.get_profiles_len()
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)
    if type(expected_evidence) == list:
        # make sure all the expected evidence are there
        for evidence in expected_evidence:
            assert is_evidence_present(log_file, evidence) is True
    else:
        assert is_evidence_present(log_file, expected_evidence) is True
    shutil.rmtree(output_dir)

