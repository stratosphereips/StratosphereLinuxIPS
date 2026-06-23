# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from unittest.mock import Mock

import pytest

from slips_files.core.input_profilers.zeek import ZeekJSON, ZeekTabs
from tests.module_factory import ModuleFactory


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


def test_zeek_json_maps_login_log_fields():
    """Test login.log JSON fields are converted to a Login flow."""
    module_factory = ModuleFactory()
    parser = ZeekJSON(module_factory.logger)
    flow, err = parser.process_line(
        {
            "type": "login.log",
            "interface": "default",
            "data": {
                "ts": 1774173495.641272,
                "uid": "CpUMTT6FJDsiSlCre",
                "id.orig_h": "147.32.80.40",
                "id.orig_p": 40422,
                "id.resp_h": "147.32.80.37",
                "id.resp_p": 23,
                "proto": "telnet",
                "success": "T",
                "confused": "F",
                "user": "root",
                "client_user": "",
                "password": "secret",
            },
        }
    )

    assert err == ""
    assert flow.type_ == "login"
    assert flow.success is True
    assert flow.confused is False
    assert flow.saddr == "147.32.80.40"
    assert flow.daddr == "147.32.80.37"


@pytest.mark.parametrize(
    "src_mac,dst_mac",
    [("00:0c:29:66:c7:82", "00:90:0b:7a:15:eb")],
)
def test_zeek_json_maps_conn_l2_addresses_to_mac_fields(
    src_mac: str, dst_mac: str
) -> None:
    """
    Test conn.log JSON l2 address fields are converted to MAC fields.

    :param src_mac: Source layer-2 address from Zeek conn.log.
    :param dst_mac: Destination layer-2 address from Zeek conn.log.
    :return: None.
    """
    module_factory = ModuleFactory()
    parser = ZeekJSON(module_factory.logger)

    flow, err = parser.process_line(
        {
            "type": "conn.log",
            "interface": "default",
            "data": {
                "ts": 279.103822,
                "uid": "CNybJS33LDUfyyg1Pi",
                "id.orig_h": "10.0.2.15",
                "id.orig_p": 44927,
                "id.resp_h": "1.1.1.1",
                "id.resp_p": 80,
                "proto": "tcp",
                "service": "http",
                "duration": 0.5273809432983398,
                "orig_bytes": 656,
                "resp_bytes": 12310,
                "conn_state": "SF",
                "history": "ShADadFf",
                "orig_pkts": 7,
                "resp_pkts": 14,
                "orig_l2_addr": src_mac,
                "resp_l2_addr": dst_mac,
            },
        }
    )

    assert err == ""
    assert flow.smac == src_mac
    assert flow.dmac == dst_mac


@pytest.mark.parametrize(
    "src_mac,dst_mac",
    [("08:00:27:ef:ee:34", "52:54:00:12:35:02")],
)
def test_zeek_tabs_maps_conn_l2_addresses_to_mac_fields(
    src_mac: str, dst_mac: str
) -> None:
    """
    Test conn.log tab l2 address fields are converted to MAC fields.

    :param src_mac: Source layer-2 address from Zeek conn.log.
    :param dst_mac: Destination layer-2 address from Zeek conn.log.
    :return: None.
    """
    module_factory = ModuleFactory()
    db = module_factory.logger
    db.channels.NEW_ZEEK_FIELDS_LINE = "new_zeek_fields_line"
    parser = ZeekTabs(db)
    fields_line = (
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
        "proto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\t"
        "history\torig_pkts\tresp_pkts\torig_l2_addr\tresp_l2_addr"
    )

    flow, err = parser.process_line(
        {"type": "conn.log", "interface": "default", "data": fields_line}
    )
    assert flow is False
    assert err == "Field line processed"

    flow, err = parser.process_line(
        {
            "type": "conn.log",
            "interface": "default",
            "data": (
                "904728.025376\tCIhV323VBG6udE1Ho3\t10.0.2.19\t"
                "1701\t78.6.164.6\t2928\tudp\t-\t0.11151099996641278\t"
                "196\t118\tSF\tDd\t1\t1\t"
                f"{src_mac}\t{dst_mac}"
            ),
        }
    )

    assert err == ""
    assert flow.smac == src_mac
    assert flow.dmac == dst_mac
