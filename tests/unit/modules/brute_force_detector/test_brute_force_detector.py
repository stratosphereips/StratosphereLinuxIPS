# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from slips_files.core.flows.zeek import Notice, SSH, Software
from slips_files.core.structures.evidence import ThreatLevel
from tests.module_factory import ModuleFactory


PROFILEID = "profile_147.32.80.40"
TWID = "timewindow1"
SRCIP = "147.32.80.40"
DSTIP = "147.32.80.37"
DPORT = "902"


def make_ssh_flow(
    uid: str,
    client: str = "SSH-2.0-OpenSSH_9.6p1",
    auth_success="F",
    auth_attempts=1,
):
    return SSH(
        starttime="1726655400.0",
        uid=uid,
        saddr=SRCIP,
        daddr=DSTIP,
        version=2,
        auth_success=auth_success,
        auth_attempts=auth_attempts,
        client=client,
        server="SSH-2.0-OpenSSH_9.6p1",
        cipher_alg="",
        mac_alg="",
        compression_alg="",
        kex_alg="",
        host_key_alg="",
        host_key="",
        sport="40422",
        dport=DPORT,
    )


def make_software_flow():
    return Software(
        starttime="1726655400.0",
        uid="software-uid",
        saddr=SRCIP,
        sport=40422,
        software="SSH::CLIENT",
        software_name="libssh",
        unparsed_version="libssh2_1.11.0",
        version_major="2",
        version_minor="1",
    )


def make_notice_flow():
    return Notice(
        starttime="1726655400.0",
        saddr=SRCIP,
        daddr="",
        sport="",
        dport="",
        note="SSH::Password_Guessing",
        msg=(
            f"{SRCIP} appears to be guessing SSH passwords "
            f"(seen in 30 connections)."
        ),
        scanned_port="",
        dst="",
        scanning_ip=SRCIP,
        uid="notice-uid",
    )


def drive_threshold(module, client_banner="SSH-2.0-OpenSSH_9.6p1"):
    module.db.get_port_info.return_value = "SSH"
    for i in range(module.ssh_attempt_threshold):
        module._handle_ssh(
            PROFILEID,
            TWID,
            make_ssh_flow(uid=f"uid-{i}", client=client_banner),
        )
    return module.db.set_evidence.call_args[0][0]


def test_software_banner_increases_brute_force_detector_confidence():
    plain_module = ModuleFactory().create_brute_force_detector_obj()
    plain_evidence = drive_threshold(plain_module)

    banner_module = ModuleFactory().create_brute_force_detector_obj()
    banner_module._handle_software(make_software_flow())
    banner_evidence = drive_threshold(
        banner_module, client_banner="SSH-2.0-libssh2_1.11.0"
    )

    assert banner_evidence.confidence > plain_evidence.confidence
    assert plain_evidence.threat_level == ThreatLevel.MEDIUM
    assert "libssh" in banner_evidence.description
    assert banner_evidence.dst_port == 902


def test_brute_force_detector_uses_sparse_bucketed_reporting():
    brute_force_detector = ModuleFactory().create_brute_force_detector_obj()
    brute_force_detector.db.get_port_info.return_value = "SSH"

    for attempt in range(1, 25):
        brute_force_detector._handle_ssh(
            PROFILEID,
            TWID,
            make_ssh_flow(uid=f"uid-{attempt}"),
        )

    assert brute_force_detector.db.set_evidence.call_count == 5
    observed_attempt_counts = [
        len(call_args[0][0].uid)
        for call_args in brute_force_detector.db.set_evidence.call_args_list
    ]
    assert observed_attempt_counts == [9, 10, 12, 16, 24]


def test_confidence_reaches_full_at_30_attempts():
    brute_force_detector = ModuleFactory().create_brute_force_detector_obj()
    threshold_confidence = brute_force_detector._calculate_confidence(
        brute_force_detector.ssh_attempt_threshold,
        "SSH-2.0-OpenSSH_9.6p1",
        "ssh.log",
    )
    full_confidence = brute_force_detector._calculate_confidence(
        brute_force_detector.ssh_full_confidence_attempts,
        "SSH-2.0-OpenSSH_9.6p1",
        "ssh.log",
    )

    assert threshold_confidence < 1.0
    assert full_confidence == 1.0

    evidence = drive_threshold(brute_force_detector)
    assert evidence.threat_level == ThreatLevel.MEDIUM


def test_notice_confirmation_emits_zeek_evidence_and_confirms_future_alerts():
    brute_force_detector = ModuleFactory().create_brute_force_detector_obj()
    drive_threshold(brute_force_detector)
    brute_force_detector.db.set_evidence.reset_mock()

    brute_force_detector._handle_notice(PROFILEID, TWID, make_notice_flow())
    zeek_evidence = brute_force_detector.db.set_evidence.call_args[0][0]
    assert zeek_evidence.confidence == 1.0
    assert zeek_evidence.threat_level == ThreatLevel.MEDIUM
    assert "Confirmed by Zeek notice.log." in zeek_evidence.description

    brute_force_detector.db.set_evidence.reset_mock()
    brute_force_detector._handle_ssh(
        PROFILEID, TWID, make_ssh_flow(uid="uid-10")
    )
    confirmed_evidence = brute_force_detector.db.set_evidence.call_args[0][0]
    assert confirmed_evidence.confidence == 1.0
    assert "Confirmed by Zeek notice.log." in confirmed_evidence.description


def test_repeated_ssh_sessions_without_auth_attempts_still_trigger_detection():
    brute_force_detector = ModuleFactory().create_brute_force_detector_obj()
    brute_force_detector.db.get_port_info.return_value = "SSH"

    for attempt in range(20):
        brute_force_detector._handle_ssh(
            PROFILEID,
            TWID,
            make_ssh_flow(
                uid=f"uid-{attempt}",
                auth_success="",
                auth_attempts=0,
            ),
        )

    assert brute_force_detector.db.set_evidence.call_count == 4
