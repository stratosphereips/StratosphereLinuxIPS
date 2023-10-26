import pytest
import shutil
from tests.common_test_utils import run_slips
from tests.common_test_utils import (
        create_output_dir,
        has_errors,
)
from tests.module_factory import ModuleFactory
from ...slips import *


@pytest.mark.skipif(
    'nfdump' not in shutil.which('nfdump'), reason='nfdump is not installed'
)
@pytest.mark.parametrize(
    'nfdump_path,  output_dir, redis_port',
    [('dataset/test1-normal.nfdump', 'test1/', 6656)],
)
def test_nfdump(
        nfdump_path,
        output_dir,
        redis_port
        ):
    """
    checks that slips is reading nfdump no issue,
     the file is not malicious so there's no evidence that should be present
    """
    output_dir = create_output_dir(output_dir)

    # expected_evidence = 'Connection to unknown destination port 902/TCP'

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -f {nfdump_path}  -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    run_slips(command)

    database = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)
    profiles = database.get_profiles_len()
    assert has_errors(output_dir) is False
    # make sure slips generated profiles for this file (can't
    # put the number of profiles exactly because slips
    # doesn't generate a const number of profiles per file)
    assert profiles > 0

    # log_file = os.path.join(output_dir, alerts_file)
    # assert is_evidence_present(log_file, expected_evidence) == True
    shutil.rmtree(output_dir)