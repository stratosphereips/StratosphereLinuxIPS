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
            "dataset/test7-malicious.pcap",
            15,
            "test7/",
            # Detected A device changing IPs. IP 192.168.2.12 was found with MAC address
            # 68:5b:35:b1:55:93 but the MAC belongs originally to IP: 169.254.242.182
            "A device changing IPs",
            6666,
        ),
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
    command = f"./slips.py  -e 1 -t -f {pcap_path} -o {output_dir}  -P {redis_port} > {output_file} 2>&1"
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
