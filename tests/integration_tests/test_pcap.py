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
    'pcap_path, expected_profiles, output_dir, expected_evidence, redis_port',
    [
        (
            'dataset/test7-malicious.pcap',
            15,
            'test7/',
            'A device changing IPs',
            6666,
        ),
        ('dataset/test8-malicious.pcap', 3, 'test8/', 'performing an arp scan', 6665),
    ],
)
def test_pcap(
    pcap_path, expected_profiles, output_dir, expected_evidence, redis_port
):
    output_dir = create_output_dir(output_dir)
    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -f {pcap_path} -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    run_slips(command)
    assert has_errors(output_dir) is False

    db = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)
    profiles = db.get_profiles_len()
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)
    assert is_evidence_present(log_file, expected_evidence) is True
    shutil.rmtree(output_dir)
