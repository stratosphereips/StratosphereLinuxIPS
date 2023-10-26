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
    'conn_log_path, expected_profiles, expected_evidence,  output_dir, redis_port',
    [
        (
            'dataset/test9-mixed-zeek-dir/conn.log',
            4,
            'horizontal port scan',
            'test9-conn_log_only/',
            6659,
        ),
        (
            'dataset/test10-mixed-zeek-dir/conn.log',
            5,
            'horizontal port scan',
            'test10-conn_log_only/',
            6658,
        ),
    ],
)
def test_zeek_conn_log(
    conn_log_path,
    expected_profiles,
    expected_evidence,
    output_dir,
    redis_port,
):
    output_dir = create_output_dir(output_dir)

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -f {conn_log_path}  -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    run_slips(command)
    assert has_errors(output_dir) is False

    database = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)
    profiles = database.get_profiles_len()
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)
    assert is_evidence_present(log_file, expected_evidence) is True
    shutil.rmtree(output_dir)

