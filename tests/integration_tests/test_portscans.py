# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
import shutil
import os

from tests.common_test_utils import (
    run_slips,
    is_evidence_present,
    create_output_dir,
    assert_no_errors,
)
from tests.module_factory import ModuleFactory

alerts_file = "alerts.log"


@pytest.mark.parametrize(
    "path,  output_dir, redis_port",
    [
        (
            "dataset/port-scans/horizontal/conn.log",
            "testing_horizontal_ps/",
            7894,
        )
    ],
)
def test_horizontal(path, output_dir, redis_port):
    """
    checks that slips is detecting horizontal ps no issue,
    """
    output_dir = create_output_dir(output_dir)

    expected_evidence = (
        "Horizontal port scan to port  80/TCP. " "From 10.0.2.112"
    )

    output_file = os.path.join(output_dir, "slips_output.txt")
    command = (
        f"./slips.py -e 1 -t -f {path} "
        f" -o {output_dir} "
        f"-P {redis_port} > {output_file} 2>&1"
    )
    # this function returns when slips is done
    run_slips(command)

    database = ModuleFactory().create_db_manager_obj(
        redis_port, output_dir=output_dir, start_redis_server=False
    )

    assert_no_errors(output_dir)
    # make sure slips generated profiles for this file (can't
    # put the number of profiles exactly because slips
    # doesn't generate a const number of profiles per file)
    profiles: int = database.get_profiles_len()
    assert profiles > 0

    log_file = os.path.join(output_dir, alerts_file)
    assert is_evidence_present(log_file, expected_evidence)

    shutil.rmtree(output_dir)


@pytest.mark.parametrize(
    "path, output_dir, redis_port",
    [("dataset/port-scans/vertical/conn.log", "testing_vertical_ps/", 7895)],
)
def test_vertical(path, output_dir, redis_port):
    """
    checks that slips is detecting horizontal ps no issue,
    """
    output_dir = create_output_dir(output_dir)

    expected_evidence = (
        "vertical port scan to IP 45.33.32.156 from 192.168.1.9."
    )

    output_file = os.path.join(output_dir, "slips_output.txt")
    command = (
        f"./slips.py -e 1 -t -f {path} "
        f" -o {output_dir}"
        f" -P {redis_port} > {output_file} 2>&1"
    )
    # this function returns when slips is done
    run_slips(command)

    database = ModuleFactory().create_db_manager_obj(
        redis_port, output_dir=output_dir, start_redis_server=False
    )
    assert_no_errors(output_dir)

    # make sure slips generated profiles for this file (can't
    # put the number of profiles exactly because slips
    # doesn't generate a const number of profiles per file)
    profiles: int = database.get_profiles_len()
    assert profiles > 0

    log_file = os.path.join(output_dir, alerts_file)
    assert is_evidence_present(log_file, expected_evidence)

    shutil.rmtree(output_dir)
