# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from tests.common_test_utils import (
    run_slips,
    is_evidence_present,
    create_output_dir,
    assert_no_errors,
    get_total_analyzed_ips_from_output,
    get_slips_test_command,
    skip_if_missing_runtime_dependencies,
)
import pytest
import shutil
import os

alerts_file = "alerts.log"


@pytest.mark.parametrize(
    "pcap_path, expected_profiles, output_dir, expected_evidence",
    [
        (
            "dataset/test8-malicious.pcap",
            3,
            "test8/",
            "performing an arp scan",
        ),
    ],
)
def test_pcap(
    pcap_path,
    expected_profiles,
    output_dir,
    expected_evidence,
    integration_port_factory,
):
    skip_if_missing_runtime_dependencies(
        python_modules=("termcolor",), binaries=("redis-server",)
    )
    redis_port = integration_port_factory("redis")
    output_dir = create_output_dir(output_dir)
    success = False
    try:
        output_file = os.path.join(output_dir, "slips_output.txt")
        command = get_slips_test_command(
            f"-e 1 -t -f {pcap_path} -o {output_dir} -P {redis_port}"
        )
        command = f"{command} > {output_file} 2>&1"
        # this function returns when slips is done
        run_slips(command)
        assert_no_errors(output_dir)

        profiles = get_total_analyzed_ips_from_output(output_dir)
        assert profiles > expected_profiles

        log_file = output_dir / "alerts" / alerts_file
        assert is_evidence_present(log_file, expected_evidence) is True
        success = True
    finally:
        if success:
            shutil.rmtree(output_dir)
