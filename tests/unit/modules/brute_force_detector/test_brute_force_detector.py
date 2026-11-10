# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from slips_files.core.flows.zeek import Notice, SSH, Software
from slips_files.core.structures.evidence import ThreatLevel
from tests.module_factory import ModuleFactory
from slips_files.core.input_profilers.zeek import ZeekJSON

import pytest

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


def test_notice_without_zeek_uid_keeps_a_retrievable_record() -> None:
    """Assign a stable link to notices lacking a Zeek connection UID."""
    brute_force_detector = ModuleFactory().create_brute_force_detector_obj()
    notice = make_notice_flow()
    notice.uid = ""
    notice.__post_init__()

    brute_force_detector._handle_notice(PROFILEID, TWID, notice)

    assert notice.uid
    evidence = brute_force_detector.db.set_evidence.call_args[0][0]
    assert evidence.uid == [notice.uid]


@pytest.mark.parametrize(
    "auth_success", ["", None, "-", "unknown", True, "T", "true"]
)
@pytest.mark.parametrize("auth_attempts", [0, 1, 30, None, ""])
def test_successful_and_unknown_sessions_do_not_count_as_password_guesses(
    auth_success: object,
    auth_attempts: object,
) -> None:
    """Ignore login outcomes without failure evidence regardless of attempt count.

    Parameters:
        auth_success: Successful or unknown Zeek authentication result.
        auth_attempts: Reported attempts, which alone do not prove failures.
    """
    brute_force_detector = ModuleFactory().create_brute_force_detector_obj()
    brute_force_detector.db.get_port_info.return_value = "SSH"

    for attempt in range(20):
        brute_force_detector._handle_ssh(
            PROFILEID,
            TWID,
            make_ssh_flow(
                uid=f"uid-{attempt}",
                auth_success=auth_success,
                auth_attempts=auth_attempts,
            ),
        )

    brute_force_detector.db.set_evidence.assert_not_called()
    assert not brute_force_detector.campaigns


def test_maintenance_ssh_json_without_auth_result_does_not_trigger() -> None:
    """Replay encrypted administrative sessions with the observed missing result."""
    factory = ModuleFactory()
    module = factory.create_brute_force_detector_obj()
    parser = ZeekJSON(factory.logger)
    for index in range(40):
        raw = {
            "ts": 1793701998.695367 + index,
            "uid": f"maintenance-{index}",
            "id.orig_h": SRCIP,
            "id.orig_p": 64788 + index,
            "id.resp_h": DSTIP,
            "id.resp_p": 902,
            "version": 2,
            "auth_attempts": 0,
            "client": "SSH-2.0-OpenSSH_10.3",
            "server": "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u2",
            "cipher_alg": "chacha20-poly1305@openssh.com",
            "mac_alg": "umac-64-etm@openssh.com",
            "compression_alg": "none",
            "kex_alg": "mlkem768x25519-sha256",
            "host_key_alg": "ssh-ed25519",
        }
        flow, error = parser.process_line(
            {"type": "ssh.log", "interface": "en0", "data": raw}
        )
        assert not error
        module._handle_ssh(PROFILEID, TWID, flow)
    module.db.set_evidence.assert_not_called()
    assert not module.campaigns


@pytest.mark.parametrize("auth_success", [False, "F", "false"])
def test_explicit_failures_still_count_and_emit(auth_success: object) -> None:
    """Retain detection when repeated sessions explicitly failed authentication.

    Parameters:
        auth_success: Supported representation of an observed failure.
    """
    module = ModuleFactory().create_brute_force_detector_obj()
    for index in range(3):
        module._handle_ssh(
            PROFILEID,
            TWID,
            make_ssh_flow(
                uid=f"failed-{index}",
                auth_success=auth_success,
                auth_attempts=3,
            ),
        )
    evidence = module.db.set_evidence.call_args.args[0]
    assert (
        "Authentication attempts in failed sessions: 9."
        in evidence.description
    )
    assert set(evidence.uid) == {"failed-0", "failed-1", "failed-2"}


@pytest.mark.parametrize("auth_attempts", [0, None, "", "invalid"])
def test_explicit_failure_without_attempt_count_counts_one_session(
    auth_attempts: object,
) -> None:
    """Count an observed failed login once when its attempt count is unavailable.

    Parameters:
        auth_attempts: Missing or unusable counter accompanying explicit failure.
    """
    module = ModuleFactory().create_brute_force_detector_obj()
    for index in range(module.ssh_attempt_threshold):
        module._handle_ssh(
            PROFILEID,
            TWID,
            make_ssh_flow(
                uid=f"failed-{index}",
                auth_success=False,
                auth_attempts=auth_attempts,
            ),
        )
    assert module.db.set_evidence.call_count == 1
    assert len(module.db.set_evidence.call_args.args[0].uid) == 9


def test_normal_sessions_do_not_pad_or_clear_real_failed_login_campaign() -> (
    None
):
    """Keep real failures detectable while ignoring successful and unknown traffic."""
    module = ModuleFactory().create_brute_force_detector_obj()
    for index in range(8):
        module._handle_ssh(
            PROFILEID, TWID, make_ssh_flow(uid=f"failed-{index}")
        )
    for index in range(40):
        module._handle_ssh(
            PROFILEID,
            TWID,
            make_ssh_flow(
                uid=f"normal-{index}",
                auth_success="" if index % 2 else True,
                auth_attempts=30,
            ),
        )
    module.db.set_evidence.assert_not_called()
    module._handle_ssh(PROFILEID, TWID, make_ssh_flow(uid="failed-8"))
    evidence = module.db.set_evidence.call_args.args[0]
    assert set(evidence.uid) == {f"failed-{index}" for index in range(9)}


def test_zeek_failure_notice_remains_actionable_with_unknown_session_results() -> (
    None
):
    """Keep independent Zeek password-guessing notices after ignoring unknown sessions."""
    module = ModuleFactory().create_brute_force_detector_obj()
    for index in range(30):
        module._handle_ssh(
            PROFILEID,
            TWID,
            make_ssh_flow(
                uid=f"unknown-{index}",
                auth_success="",
                auth_attempts=0,
            ),
        )
    module.db.set_evidence.assert_not_called()
    module._handle_notice(PROFILEID, TWID, make_notice_flow())
    assert module.db.set_evidence.call_count == 1
    assert module.db.set_evidence.call_args.args[0].confidence == 1.0
