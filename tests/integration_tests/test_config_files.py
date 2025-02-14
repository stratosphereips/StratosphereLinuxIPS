# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
This file tests 2 different config files other than slips' default config/slips.yaml
test/test.yaml and tests/test2.yaml
"""

from slips.main import Main
from tests.common_test_utils import (
    is_evidence_present,
    create_output_dir,
    assert_no_errors,
    check_for_text,
)
from tests.module_factory import ModuleFactory
import pytest
import shutil
import os
import yaml
from pathlib import Path

alerts_file = "alerts.log"


def modify_yaml_config(
    input_path="config/slips.yaml",
    output_filename="updated_slips.yaml",
    changes=None,
):
    """
    Reads a YAML config file, modifies specified values, and writes the new
     config to the current directory.

    :param input_path: path to the input yaml file
    :param output_filename: name of the output yaml file
    :param changes: dictionary containing keys to update and their new values
    """
    input_file = Path(input_path)
    output_file = Path.cwd() / output_filename

    if not input_file.exists():
        raise FileNotFoundError(f"YAML config file not found: {input_path}")

    with input_file.open("r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if changes:
        for key, value in changes.items():
            key: str
            value: dict
            if key in config:
                config[key].update(value)

    with output_file.open("w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

    return output_file


def create_Main_instance(input_information):
    """returns an instance of Main() class in slips.py"""
    main = Main(testing=True)
    main.input_information = input_information
    main.input_type = "pcap"
    main.line_type = False
    return main


@pytest.mark.parametrize(
    "pcap_path, expected_profiles, output_dir, redis_port",
    [
        (
            "dataset/test7-malicious.pcap",
            290,
            "test_configuration_file/",
            6667,
        )
    ],
)
def test_conf_file(pcap_path, expected_profiles, output_dir, redis_port):
    """
    In this test we're using tests/test.conf
    """
    config_file = "tests/integration_tests/test.yaml"
    modify_yaml_config(
        output_filename=config_file,
        changes={
            "DisabledAlerts": {
                "disabled_detections": ["ConnectionWithoutDNS"]
            },
            "detection": {"evidence_detection_threshold": 0.1},
            "parameters": {
                "analysis_direction": "all",
                "delete_zeek_files": True,
                "store_zeek_files_in_the_output_dir": False,
                "label": "malicious",
                "time_window_width": "only_one_tw",
                "store_a_copy_of_zeek_files": True,
            },
            "modules": {
                "disable": [
                    "template",
                    "ensembling",
                    "Flow ML Detection",
                    "Update Manager",
                ]
            },
        },
    )
    output_dir = create_output_dir(output_dir)
    output_file = os.path.join(output_dir, "slips_output.txt")
    command = (
        f"./slips.py "
        f"-t -e 1 "
        f"-f {pcap_path} "
        f"-o {output_dir} "
        f"-c {config_file} "
        f"-P {redis_port} "
        f"> {output_file} 2>&1"
    )
    print("running slips ...")
    # this function returns when slips is done
    os.system(command)
    print("Slip is done, checking for errors in the output dir.")
    assert_no_errors(output_dir)
    print("Comparing profiles with expected profiles")
    database = ModuleFactory().create_db_manager_obj(
        redis_port, output_dir=output_dir, start_redis_server=False
    )
    profiles = database.get_profiles_len()
    # expected_profiles is more than 50 because we're using direction = all
    assert profiles > expected_profiles
    print("Checking for a random evidence")
    log_file = os.path.join(output_dir, alerts_file)

    # testing disabled_detections param in the configuration file
    disabled_evidence = "a connection without DNS resolution"
    assert is_evidence_present(log_file, disabled_evidence) is False
    print("Testing time_window_width param.")
    # testing time_window_width param in the configuration file
    assert check_for_text("115740 days 17 hrs 46 mins 39 seconds", output_dir)

    print("Make sure slips didn't delete zeek files.")
    # test delete_zeek_files param
    zeek_output_dir = database.get_zeek_output_dir()[2:]
    assert zeek_output_dir not in os.listdir()
    print("Test storing a copy of zeek files.")
    # test store_a_copy_of_zeek_files
    assert "zeek_files" in os.listdir(output_dir)
    print("Checking metadata directory")
    # test metadata_dir
    assert "metadata" in os.listdir(output_dir)
    metadata_path = os.path.join(output_dir, "metadata")
    for file in ("test.yaml", "whitelist.conf", "info.txt"):
        print(f"checking if {file} in the metadata path {metadata_path}")
        assert file in os.listdir(metadata_path)

    print("Checking malicious label count")
    # test label=malicious
    assert int(database.get_label_count("malicious")) > 370
    # test disable
    for module in ["template", "Flow ML Detection"]:
        print(f"Checking if {module} is disabled")
        assert module in database.get_disabled_modules()
    print("Deleting the output directory")
    shutil.rmtree(output_dir)
    os.remove(config_file)


@pytest.mark.parametrize(
    "pcap_path, expected_profiles, output_dir, redis_port",
    [
        (
            "dataset/test8-malicious.pcap ",
            1,
            "pcap_test_conf2/",
            6668,
        )
    ],
)
def test_conf_file2(pcap_path, expected_profiles, output_dir, redis_port):
    """
    In this test we're using tests/test2.conf
    """
    config_file = "tests/integration_tests/test2.yaml"
    modify_yaml_config(
        output_filename=config_file,
        changes={
            "detection": {"evidence_detection_threshold": 0.1},
            "parameters": {
                "metadata_dir": False,
                "store_zeek_files_in_the_output_dir": False,
            },
            "modules": {
                "disable": [
                    "template",
                    "ensembling",
                    "Flow ML Detection",
                    "Update Manager",
                ]
            },
        },
    )

    output_dir = create_output_dir(output_dir)
    output_file = os.path.join(output_dir, "slips_output.txt")
    command = (
        f"./slips.py "
        f"-t  -e 1 "
        f"-f {pcap_path} "
        f"-o {output_dir} "
        f"-c {config_file} "
        f"-P {redis_port} "
        f"> {output_file} 2>&1"
    )
    print("running slips ...")
    os.system(command)
    print("Slip is done, checking for errors in the output dir.")
    assert_no_errors(output_dir)
    print("Deleting the output directory")
    shutil.rmtree(output_dir)
    os.remove(config_file)
