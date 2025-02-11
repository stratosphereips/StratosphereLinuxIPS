# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from tests.common_test_utils import (
    run_slips,
    is_evidence_present,
    create_output_dir,
    assert_no_errors,
)
from tests.module_factory import ModuleFactory
import pytest
import shutil
import os

alerts_file = "alerts.log"


@pytest.mark.parametrize(
    "pcap_path, expected_profiles, output_dir, expected_evidence, redis_port",
    [
        (
            "dataset/test8-malicious.pcap",
            3,
            "test8/",
            "performing an arp scan",
            6665,
        ),
    ],
)
def test_pcap(
    pcap_path, expected_profiles, output_dir, expected_evidence, redis_port
):
    output_dir = create_output_dir(output_dir)
    output_file = os.path.join(output_dir, "slips_output.txt")
    command = (
        f"./slips.py -e 1 -t -f {pcap_path} -o {output_dir} "
        f" -P {redis_port} > {output_file} 2>&1"
    )
    # this function returns when slips is done
    run_slips(command)
    assert_no_errors(output_dir)

    db = ModuleFactory().create_db_manager_obj(
        redis_port, output_dir=output_dir
    )
    profiles = db.get_profiles_len()
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)
    assert is_evidence_present(log_file, expected_evidence) is True
    shutil.rmtree(output_dir)
