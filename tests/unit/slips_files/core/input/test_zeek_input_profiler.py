# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from unittest.mock import Mock

from slips_files.core.input_profilers.zeek import ZeekJSON


def test_zeek_json_maps_software_type_and_banner_fields():
    parser = ZeekJSON(Mock())
    flow, err = parser.process_line(
        {
            "type": "software.log",
            "interface": "default",
            "data": {
                "ts": 1774173495.641272,
                "host": "147.32.80.40",
                "host_p": 40422,
                "software_type": "SSH::CLIENT",
                "name": "libssh",
                "version.major": 2,
                "version.minor": 1,
                "version.minor2": 11,
                "version.minor3": 0,
                "unparsed_version": "libssh2_1.11.0",
            },
        }
    )

    assert err == ""
    assert flow.software == "SSH::CLIENT"
    assert flow.software_name == "libssh"
    assert flow.unparsed_version == "libssh2_1.11.0"


def test_zeek_json_maps_ssh_ports_and_auth_attempts():
    parser = ZeekJSON(Mock())
    flow, err = parser.process_line(
        {
            "type": "ssh.log",
            "interface": "default",
            "data": {
                "ts": 1774173495.641272,
                "uid": "CpUMTT6FJDsiSlCre",
                "id.orig_h": "147.32.80.40",
                "id.orig_p": 40422,
                "id.resp_h": "147.32.80.37",
                "id.resp_p": 902,
                "version": 2,
                "auth_attempts": 3,
                "auth_success": "F",
                "client": "SSH-2.0-libssh2_1.11.0",
                "server": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.11",
                "cipher_alg": "",
                "mac_alg": "",
                "compression_alg": "",
                "kex_alg": "",
                "host_key_alg": "",
                "host_key": "",
            },
        }
    )

    assert err == ""
    assert flow.sport == 40422
    assert flow.dport == 902
    assert flow.auth_attempts == 3
