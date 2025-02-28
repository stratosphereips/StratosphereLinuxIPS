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

#
# @pytest.mark.parametrize(
#     "zeek_dir_path,expected_profiles, expected_evidence,  output_dir, redis_port",
#     [
#         (
#             "dataset/test9-mixed-zeek-dir",
#             4,
#             [
#                 "Malicious JA3s: (possible C&C server): "
#                 "e7d705a3286e19ea42f587b344ee6865 to server 123.33.22.11. "
#                 "description: Standard tor client.",
#                 "sending ARP packet to a destination address outside of "
#                 "local network",
#                 "broadcasting unsolicited ARP",
#             ],
#             "test9-mixed-zeek-dir/",
#             6661,
#         ),
#         (
#             "dataset/test16-malicious-zeek-dir",
#             0,
#             [
#                 "sending ARP packet to a destination address outside of local"
#                 " network",
#                 "broadcasting unsolicited ARP",
#             ],
#             "test16-malicious-zeek-dir/",
#             6671,
#         ),
#         (
#             "dataset/test14-malicious-zeek-dir",
#             2,
#             [
#                 "bad SMTP login to 80.75.42.226",
#                 "SMTP login bruteforce to 80.75.42.226. 3 logins in 10 seconds",
#                 # "Multiple empty HTTP connections to google.com",
#                 "Suspicious user-agent:",
#                 "Download of an executable",
#                 "GRE tunnel",
#                 "Multiple reconnection attempts to Destination IP: "
#                 "123.22.123.22 from IP: 10.0.2.15",
#             ],
#             "test14-malicious-zeek-dir/",
#             6670,
#         ),
#         (
#             "dataset/test15-malicious-zeek-dir",
#             2,
#             [
#                 "SSH client version changing",
#                 "Incompatible certificate CN to IP: 52.0.131.132 domain: "
#                 "netflix.com. The certificate is claiming to belong "
#                 "to Google",
#                 "Detected Malicious JA3: 6734f37431670b3ab4292b8f60f29984 "
#                 "from source address 10.0.2.15 to 22.33.22.33. "
#                 "description: Trickbot Malware.",
#             ],
#             "test15-malicious-zeek-dir",
#             2345,
#         ),
#         (
#             "dataset/test10-mixed-zeek-dir",
#             20,
#             "DNS TXT answer with high entropy",
#             "test10-mixed-zeek-dir/",
#             6660,
#         ),
#     ],
# )
# def test_zeek_dir(
#     zeek_dir_path,
#     expected_profiles,
#     expected_evidence,
#     output_dir,
#     redis_port,
# ):
#     output_dir = create_output_dir(output_dir)
#
#     output_file = os.path.join(output_dir, "slips_output.txt")
#     command = (
#         f"./slips.py  -e 1 -t -f {zeek_dir_path}  -o {output_dir}"
#         f" -P {redis_port} > {output_file} 2>&1"
#     )
#     # this function returns when slips is done
#     run_slips(command)
#     assert_no_errors(output_dir)
#
#     database = ModuleFactory().create_db_manager_obj(
#         redis_port, output_dir=output_dir
#     )
#     profiles = database.get_profiles_len()
#     assert profiles > expected_profiles
#
#     log_file = os.path.join(output_dir, alerts_file)
#     if isinstance(expected_evidence, list):
#         # make sure all the expected evidence are there
#         for evidence in expected_evidence:
#             assert is_evidence_present(log_file, evidence) is True
#     else:
#         assert is_evidence_present(log_file, expected_evidence) is True
#     shutil.rmtree(output_dir)
#


@pytest.mark.parametrize(
    "conn_log_path, expected_profiles, expected_evidence,  output_dir, redis_port",
    [
        (
            "dataset/test9-mixed-zeek-dir/conn.log",
            4,
            "non-HTTP established connection to port 80. "
            "destination IP: 194.132.197.198",  # the flows with uid
            # CAwUdr34dVnyOwbUuj should trigger this
            "test9-conn_log_only/",
            6659,
        ),
        (
            "dataset/test10-mixed-zeek-dir/conn.log",
            5,
            "non-SSL established connection",
            "test10-conn_log_only/",
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

    output_file = os.path.join(output_dir, "slips_output.txt")
    command = (
        f"./slips.py -e 1 -t -f {conn_log_path} -o {output_dir} "
        f"-P {redis_port} > {output_file} 2>&1"
    )
    # this function returns when slips is done
    run_slips(command)
    assert_no_errors(output_dir)

    database = ModuleFactory().create_db_manager_obj(
        redis_port, output_dir=output_dir
    )
    profiles = database.get_profiles_len()
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)
    assert is_evidence_present(log_file, expected_evidence) is True
    shutil.rmtree(output_dir)
