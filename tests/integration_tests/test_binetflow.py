import pytest
import shutil
from tests.common_test_utils import run_slips
from tests.common_test_utils import (
        get_total_profiles,
        is_evidence_present,
        create_output_dir,
        has_errors,
)
from tests.module_factory import ModuleFactory
from ...slips import *

@pytest.mark.parametrize(
    'binetflow_path, expected_profiles, expected_evidence, output_dir, redis_port',
    [
        (
            'dataset/test4-malicious.binetflow',
            2,
            'horizontal port scan to port  81',
            'test4/',
            6662,
        ),
        (
            'dataset/test3-mixed.binetflow',
            20,
            'horizontal port scan to port  3389',
            'test3/',
            6663,
        ),
        (
            'dataset/test2-malicious.binetflow',
            1,
            'Detected Long Connection.',
            'test2/',
            6664,
        ),
        (
            'dataset/test5-mixed.binetflow',
             4,
             'Long Connection',
             'test5/',
             6655
         ),
        # (
        #     'dataset/test11-portscan.binetflow',
        #     0,
        #     'ICMP scanning',
        #     'test11/',
        #     6669
        # )
    ],
)
def test_binetflow(
    binetflow_path,
    expected_profiles,
    expected_evidence,
    output_dir,
    redis_port,
):
    output_dir = create_output_dir(output_dir)

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -o {output_dir}  -P {redis_port} -f {binetflow_path}  >  {output_file} 2>&1'
    # this function returns when slips is done
    run_slips(command)

    assert has_errors(output_dir) is False

    database = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)
    profiles = database.get_profiles_len()
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)
    assert is_evidence_present(log_file, expected_evidence) is True

    shutil.rmtree(output_dir)