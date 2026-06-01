# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
This file tests all kinds of input in our dataset/
It checks a random evidence and the total number of profiles in every file
"""

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
    "binetflow_path, expected_profiles, expected_evidence, output_dir",
    [
        (
            "dataset/test4-malicious.binetflow",
            2,
            "Horizontal port scan to port http-alt 81/tcp. From 192.168.2.12",
            "test4/",
        ),
        (
            "dataset/test3-mixed.binetflow",
            20,
            "Horizontal port scan to port rdp 3389/tcp. From 46.166.151.160",
            "test3/",
        ),
        (
            "dataset/test2-malicious.binetflow",
            1,
            "Long Connection.",
            "test2/",
        ),
        (
            "dataset/test5-mixed.binetflow",
            4,
            "Long Connection",
            "test5/",
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
            f"-e 1 -t -o {output_dir} -P {redis_port} -f {binetflow_path}"
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


@pytest.mark.parametrize(
    "suricata_path, output_dir, expected_evidence",
    [
        (
            "dataset/test6-malicious.suricata.json",
            "test6/",
            [
                "Connection to unknown destination port",
                "vertical port scan",
                "Connecting to private IP",
            ],
        )
    ],
)
def test_suricata(
    suricata_path,
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
            f"-e 1 -t -f {suricata_path} -o {output_dir} -P {redis_port}"
        )
        command = f"{command} > {output_file} 2>&1"
        # this function returns when slips is done
        run_slips(command)

        assert_no_errors(output_dir)

        profiles = get_total_analyzed_ips_from_output(output_dir)
        # todo the profiles should be way more than 10, maybe 76, but it varies
        #  each run, we need to sy why
        assert profiles > 10

        log_file = output_dir / "alerts" / alerts_file
        assert any(
            is_evidence_present(log_file, ev) for ev in expected_evidence
        )
        success = True
    finally:
        if success:
            shutil.rmtree(output_dir)


@pytest.mark.skipif(
    "nfdump" not in shutil.which("nfdump"), reason="nfdump is not installed"
)
@pytest.mark.parametrize(
    "nfdump_path,  output_dir",
    [("dataset/test1-malicious.nfdump", "test1/")],
)
def test_nfdump(nfdump_path, output_dir, integration_port_factory):
    """
    checks that slips is reading nfdump no issue,
     the file is not malicious so there's no evidence that should be present
    """
    skip_if_missing_runtime_dependencies(
        python_modules=("termcolor",), binaries=("redis-server",)
    )
    redis_port = integration_port_factory("redis")
    output_dir = create_output_dir(output_dir)
    success = False
    try:
        # expected_evidence = 'Connection to unknown destination port 902/TCP'

        output_file = os.path.join(output_dir, "slips_output.txt")
        command = get_slips_test_command(
            f"-e 1 -t -f {nfdump_path} -o {output_dir} -P {redis_port}"
        )
        command = f"{command} > {output_file} 2>&1"
        # this function returns when slips is done
        run_slips(command)

        profiles = get_total_analyzed_ips_from_output(output_dir)
        assert_no_errors(output_dir)
        assert profiles > 0
        success = True
    finally:
        if success:
            shutil.rmtree(output_dir)
