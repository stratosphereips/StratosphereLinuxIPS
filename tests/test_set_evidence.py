from unittest.mock import Mock
import pytest
import datetime
from slips_files.core.evidence_structure.evidence import (
    ThreatLevel,
    EvidenceType,
    IDEACategory,
    Tag,
)
from modules.flowalerts.set_evidence import SetEvidnceHelper


@pytest.fixture
def set_evidence_helper(db_mock):
    """Create an instance of SetEvidenceHelper with the mocked database."""
    return SetEvidnceHelper(db_mock)


@pytest.fixture
def db_mock():
    """Mock the database object."""
    db_mock = Mock()
    db_mock.get_local_network.return_value = "192.168.0.0/16"
    db_mock.get_ip_identification.return_value = "Example Identification"
    start_time = datetime.datetime(2023, 5, 6, 12, 0, 0)
    db_mock.get_slips_start_time.return_value = start_time.timestamp()
    db_mock.is_growing_zeek_dir.return_value = False
    return db_mock


def test_young_domain(set_evidence_helper, db_mock):
    """Testing the young_domain method."""
    set_evidence_helper.young_domain(
        domain="example.com",
        age=10,
        stime="2023-05-06T12:00:00Z",
        profileid="profile_192.168.0.1",
        twid="timewindow1",
        uid="unique_id",
        answers=["192.168.0.2", "192.168.0.3"],
    )

    assert db_mock.set_evidence.call_count == 3
    args, _ = db_mock.set_evidence.call_args_list[0]
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.YOUNG_DOMAIN
    assert evidence.attacker.value == "192.168.0.2"
    assert evidence.threat_level == ThreatLevel.LOW
    assert evidence.category == IDEACategory.ANOMALY_TRAFFIC
    assert evidence.profile.ip == "192.168.0.2"
    assert evidence.timewindow.number == 1
    assert evidence.uid == ["unique_id"]


def test_multiple_ssh_versions(set_evidence_helper, db_mock):
    """Testing the multiple_ssh_versions method."""
    set_evidence_helper.multiple_ssh_versions(
        srcip="192.168.0.1",
        cached_versions="7.2",
        current_versions="8.0",
        timestamp="2023-05-06T12:00:00Z",
        twid="timewindow2",
        uid=["unique_id1", "unique_id2"],
        role="SSH::CLIENT",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.MULTIPLE_SSH_VERSIONS
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.MEDIUM
    assert evidence.category == IDEACategory.ANOMALY_TRAFFIC
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 2
    assert sorted(evidence.uid) == sorted(["unique_id1", "unique_id2"])
    assert evidence.source_target_tag == Tag.RECON


def test_different_localnet_usage(set_evidence_helper, db_mock):
    """Testing the different_localnet_usage method."""
    set_evidence_helper.different_localnet_usage(
        daddr="10.0.0.1",
        portproto="80",
        profileid="profile_192.168.0.1",
        timestamp="2023-05-06T12:00:00Z",
        twid="timewindow3",
        uid="unique_id",
        ip_outside_localnet="srcip",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.DIFFERENT_LOCALNET
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.LOW
    assert evidence.category == IDEACategory.ANOMALY_TRAFFIC
    assert evidence.victim.value == "10.0.0.1"
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 3
    assert evidence.uid == ["unique_id"]


def test_device_changing_ips(set_evidence_helper, db_mock):
    """Testing the device_changing_ips method."""
    set_evidence_helper.device_changing_ips(
        smac="00:11:22:33:44:55",
        old_ip="10.0.0.1",
        profileid="profile_192.168.0.1",
        twid="timewindow4",
        uid="unique_id",
        timestamp="2023-05-06T12:00:00Z",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.DEVICE_CHANGING_IP
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.MEDIUM
    assert evidence.category == IDEACategory.ANOMALY_TRAFFIC
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 4
    assert evidence.uid == ["unique_id"]


def test_non_ssl_port_443_conn(set_evidence_helper, db_mock):
    """Testing the non_ssl_port_443_conn method."""
    set_evidence_helper.non_ssl_port_443_conn(
        daddr="10.0.0.1",
        profileid="profile_192.168.0.1",
        timestamp="2023-05-06T12:00:00Z",
        twid="timewindow6",
        uid="unique_id",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.NON_SSL_PORT_443_CONNECTION
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.victim.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.MEDIUM
    assert evidence.category == IDEACategory.ANOMALY_TRAFFIC
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 6
    assert evidence.uid == ["unique_id"]


def test_incompatible_CN(set_evidence_helper, db_mock):
    """Testing the incompatible_CN method."""
    set_evidence_helper.incompatible_CN(
        org="example",
        timestamp="2023-05-06T12:00:00Z",
        daddr="10.0.0.1",
        profileid="profile_192.168.0.1",
        twid="timewindow1",
        uid="unique_id",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.INCOMPATIBLE_CN
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.victim.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.MEDIUM
    assert evidence.category == IDEACategory.ANOMALY_TRAFFIC
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 1
    assert evidence.uid == ["unique_id"]
    assert evidence.confidence == 0.9


def test_DGA(set_evidence_helper, db_mock):
    """Testing the DGA method."""
    set_evidence_helper.DGA(
        nxdomains=150,
        stime="2023-05-06T12:00:00Z",
        profileid="profile_192.168.0.1",
        twid="timewindow2",
        uid=["unique_id"],
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.DGA_NXDOMAINS
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.HIGH
    assert evidence.category == IDEACategory.ANOMALY_BEHAVIOUR
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 2
    assert evidence.uid == ["unique_id"]
    assert evidence.conn_count == 150
    assert evidence.confidence == 1.5
    assert evidence.source_target_tag == Tag.ORIGIN_MALWARE


def test_pastebin_download(set_evidence_helper, db_mock):
    """Testing the pastebin_download method."""
    set_evidence_helper.pastebin_download(
        bytes_downloaded=1024 * 1024,
        timestamp="2023-05-06T12:00:00Z",
        profileid="profile_192.168.0.1",
        twid="timewindow2",
        uid="unique_id",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.PASTEBIN_DOWNLOAD
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.INFO
    assert evidence.category == IDEACategory.ANOMALY_BEHAVIOUR
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 2
    assert evidence.uid == ["unique_id"]
    assert evidence.confidence == 1.0
    assert evidence.source_target_tag == Tag.MALWARE


def test_dns_without_conn(set_evidence_helper, db_mock):
    """Testing the dns_without_conn method."""
    result = set_evidence_helper.dns_without_conn(
        domain="example.com",
        timestamp="2023-05-06T12:00:00Z",
        profileid="profile_192.168.0.1",
        twid="timewindow1",
        uid="unique_id",
    )

    if result is True:
        assert db_mock.set_evidence.call_count == 1
        args, _ = db_mock.set_evidence.call_args
        evidence = args[0]
        assert evidence.evidence_type == EvidenceType.DNS_WITHOUT_CONNECTION
        assert evidence.attacker.value == "192.168.0.1"
        assert evidence.victim.value == "example.com"
        assert evidence.threat_level == ThreatLevel.LOW
        assert evidence.category == IDEACategory.ANOMALY_TRAFFIC
        assert evidence.profile.ip == "192.168.0.1"
        assert evidence.timewindow.number == 1
        assert evidence.uid == ["unique_id"]
        assert evidence.confidence == 0.8
    else:
        assert result is None


def test_dns_arpa_scan(set_evidence_helper, db_mock):
    """Testing the dns_arpa_scan method."""
    result = set_evidence_helper.dns_arpa_scan(
        arpa_scan_threshold=150,
        stime="2023-05-06T12:00:00Z",
        profileid="profile_192.168.0.1",
        twid="timewindow2",
        uid=["unique_id"],
    )

    assert result is True
    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.DNS_ARPA_SCAN
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.MEDIUM
    assert evidence.category == IDEACategory.RECON_SCANNING
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 2
    assert evidence.uid == ["unique_id"]
    assert evidence.conn_count == 150
    assert evidence.confidence == 0.7


def test_conn_without_dns(set_evidence_helper, db_mock):
    """Testing the conn_without_dns method."""
    set_evidence_helper.conn_without_dns(
        daddr="10.0.0.1",
        timestamp="2023-05-06T12:00:00Z",
        profileid="profile_192.168.0.1",
        twid="timewindow1",
        uid="unique_id",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.CONNECTION_WITHOUT_DNS
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.INFO
    assert evidence.category == IDEACategory.ANOMALY_CONNECTION
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 1
    assert evidence.uid == ["unique_id"]
    assert evidence.confidence == 0.8
    assert evidence.source_target_tag == Tag.MALWARE


def test_unknown_port(set_evidence_helper, db_mock):
    """Testing the unknown_port method."""
    set_evidence_helper.unknown_port(
        daddr="10.0.0.1",
        dport=12345,
        proto="tcp",
        timestamp="2023-05-06T12:00:00Z",
        profileid="profile_192.168.0.1",
        twid="timewindow1",
        uid="unique_id",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.UNKNOWN_PORT
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.victim.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.HIGH
    assert evidence.category == IDEACategory.ANOMALY_CONNECTION
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 1
    assert evidence.uid == ["unique_id"]


def test_pw_guessing(set_evidence_helper, db_mock):
    """Testing the pw_guessing method."""
    set_evidence_helper.pw_guessing(
        msg="192.168.0.1 appears to be guessing SSH passwords (seen in 30 connections)",
        timestamp="2023-05-06T12:00:00Z",
        twid="timewindow2",
        uid="unique_id",
        by="detection_model",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.PASSWORD_GUESSING
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.HIGH
    assert evidence.category == IDEACategory.ATTEMPT_LOGIN
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 2
    assert evidence.uid == ["unique_id"]
    assert evidence.conn_count == 30
    assert evidence.source_target_tag == Tag.MALWARE


def test_horizontal_portscan(set_evidence_helper, db_mock):
    """Testing the horizontal_portscan method."""
    set_evidence_helper.horizontal_portscan(
        msg="Seen at least 10 unique hosts scanned on 80/tcp",
        timestamp="2023-05-06T12:00:00Z",
        profileid="profile_192.168.0.1",
        twid="timewindow3",
        uid="unique_id",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.HORIZONTAL_PORT_SCAN
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.HIGH
    assert evidence.category == IDEACategory.RECON_SCANNING
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 3
    assert evidence.uid == ["unique_id"]
    assert evidence.conn_count == 10
    assert evidence.source_target_tag == Tag.RECON


def test_conn_to_private_ip(set_evidence_helper, db_mock):
    """Testing the conn_to_private_ip method."""
    set_evidence_helper.conn_to_private_ip(
        proto="tcp",
        daddr="192.168.1.100",
        dport=80,
        saddr="192.168.0.1",
        twid="timewindow4",
        uid="unique_id",
        timestamp="2023-05-06T12:00:00Z",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.CONNECTION_TO_PRIVATE_IP
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.victim.value == "192.168.1.100"
    assert evidence.threat_level == ThreatLevel.INFO
    assert evidence.category == IDEACategory.RECON
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 4
    assert evidence.uid == ["unique_id"]


def test_gre_tunnel(set_evidence_helper, db_mock):
    """Testing the GRE_tunnel method."""
    tunnel_info = {
        "profileid": "profile_192.168.0.1",
        "twid": "timewindow5",
        "flow": {
            "action": "TUNNEL",
            "daddr": "10.0.0.1",
            "starttime": "2023-05-06T12:00:00Z",
            "uid": "unique_id",
        },
    }

    set_evidence_helper.GRE_tunnel(tunnel_info)

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.GRE_TUNNEL
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.victim.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.INFO
    assert evidence.category == IDEACategory.INFO
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 5
    assert evidence.uid == ["unique_id"]


def test_ssh_successful(set_evidence_helper, db_mock):
    """Testing the ssh_successful method."""
    set_evidence_helper.ssh_successful(
        twid="timewindow7",
        saddr="192.168.0.1",
        daddr="10.0.0.1",
        size=1024,
        uid="unique_id",
        timestamp="2023-05-06T12:00:00Z",
        by="detection_model",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.SSH_SUCCESSFUL
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.victim.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.INFO
    assert evidence.confidence == 0.8
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 7
    assert evidence.uid == ["unique_id"]
    assert evidence.category == IDEACategory.INFO


def test_long_connection(set_evidence_helper, db_mock):
    """Testing the long_connection method."""
    set_evidence_helper.long_connection(
        daddr="10.0.0.1",
        duration=7200,
        profileid="profile_192.168.0.1",
        twid="timewindow8",
        uid="unique_id",
        timestamp="2023-05-06T12:00:00Z",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.LONG_CONNECTION
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.victim.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.LOW
    assert evidence.confidence == 0.08
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 8
    assert evidence.uid == ["unique_id"]
    assert evidence.category == IDEACategory.ANOMALY_CONNECTION


def test_self_signed_certificates(set_evidence_helper, db_mock):
    """Testing the self_signed_certificates method."""
    set_evidence_helper.self_signed_certificates(
        profileid="profile_192.168.0.1",
        twid="timewindow1",
        daddr="10.0.0.1",
        uid="unique_id",
        timestamp="2023-05-06T12:00:00Z",
        server_name="example.com",
    )

    assert db_mock.set_evidence.call_count == 2
    args, _ = db_mock.set_evidence.call_args_list[0]
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.SELF_SIGNED_CERTIFICATE
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.LOW
    assert evidence.confidence == 0.5
    assert evidence.category == IDEACategory.ANOMALY_BEHAVIOUR
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 1
    assert evidence.uid == ["unique_id"]
    args, _ = db_mock.set_evidence.call_args_list[1]
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.SELF_SIGNED_CERTIFICATE
    assert evidence.attacker.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.LOW
    assert evidence.confidence == 0.5
    assert evidence.category == IDEACategory.ANOMALY_BEHAVIOUR
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 1
    assert evidence.uid == ["unique_id"]


def test_multiple_reconnection_attempts(set_evidence_helper, db_mock):
    """Testing the multiple_reconnection_attempts method."""
    set_evidence_helper.multiple_reconnection_attempts(
        profileid="profile_192.168.0.1",
        twid="timewindow2",
        daddr="10.0.0.1",
        uid=["unique_id1", "unique_id2"],
        timestamp="2023-05-06T12:00:00Z",
        reconnections=10,
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert (
            evidence.evidence_type == EvidenceType.MULTIPLE_RECONNECTION_ATTEMPTS
    )
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.victim.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.MEDIUM
    assert evidence.confidence == 0.5
    assert evidence.category == IDEACategory.ANOMALY_TRAFFIC
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 2
    assert sorted(evidence.uid) == sorted(["unique_id1", "unique_id2"])


def test_connection_to_multiple_ports(set_evidence_helper, db_mock):
    """Testing the connection_to_multiple_ports method."""
    set_evidence_helper.connection_to_multiple_ports(
        profileid="profile_192.168.0.1",
        twid="timewindow3",
        uid=["unique_id"],
        timestamp="2023-05-06T12:00:00Z",
        dstports=[80, 8080, 8000],
        victim="192.168.0.2",
        attacker="192.168.0.1",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.CONNECTION_TO_MULTIPLE_PORTS
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.victim.value == "192.168.0.2"
    assert evidence.threat_level == ThreatLevel.INFO
    assert evidence.confidence == 0.5
    assert evidence.category == IDEACategory.ANOMALY_CONNECTION
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 3
    assert evidence.uid == ["unique_id"]


def test_suspicious_dns_answer(set_evidence_helper, db_mock):
    """Testing the suspicious_dns_answer method."""
    set_evidence_helper.suspicious_dns_answer(
        query="example.com",
        answer="aBcDeFgHiJkLmNoPqRsTuVwXyZ",
        entropy=4.5,
        daddr="10.0.0.1",
        profileid="profile_192.168.0.1",
        twid="timewindow4",
        stime="2023-05-06T12:00:00Z",
        uid="unique_id",
    )

    assert db_mock.set_evidence.call_count == 2
    args, _ = db_mock.set_evidence.call_args_list[0]
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.HIGH_ENTROPY_DNS_ANSWER
    assert evidence.attacker.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.MEDIUM
    assert evidence.confidence == 0.6
    assert evidence.category == IDEACategory.ANOMALY_TRAFFIC
    assert evidence.profile.ip == "10.0.0.1"
    assert evidence.timewindow.number == 4
    assert evidence.uid == ["unique_id"]
    args, _ = db_mock.set_evidence.call_args_list[1]
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.HIGH_ENTROPY_DNS_ANSWER
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.LOW
    assert evidence.confidence == 0.6
    assert evidence.category == IDEACategory.ANOMALY_TRAFFIC
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 4
    assert evidence.uid == ["unique_id"]


def test_invalid_dns_answer(set_evidence_helper, db_mock):
    """Testing the invalid_dns_answer method."""
    set_evidence_helper.invalid_dns_answer(
        query="example.com",
        answer="127.0.0.1",
        profileid="profile_192.168.0.1",
        twid="timewindow5",
        stime="2023-05-06T12:00:00Z",
        uid="unique_id",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.INVALID_DNS_RESOLUTION
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.INFO
    assert evidence.confidence == 0.7
    assert evidence.category == IDEACategory.ANOMALY_BEHAVIOUR
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 5
    assert evidence.uid == ["unique_id"]


def test_for_port_0_connection(set_evidence_helper, db_mock):
    """Testing the for_port_0_connection method."""
    set_evidence_helper.for_port_0_connection(
        saddr="192.168.0.1",
        daddr="10.0.0.1",
        sport=12345,
        dport=0,
        profileid="profile_192.168.0.1",
        twid="timewindow6",
        uid="unique_id",
        timestamp="2023-05-06T12:00:00Z",
        victim="192.168.0.1",
        attacker="10.0.0.1",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.PORT_0_CONNECTION
    assert evidence.attacker.value == "10.0.0.1"
    assert evidence.victim.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.HIGH
    assert evidence.confidence == 0.8
    assert evidence.category == IDEACategory.ANOMALY_CONNECTION
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 6
    assert evidence.uid == ["unique_id"]
    assert evidence.source_target_tag == Tag.RECON


def test_malicious_ja3s(set_evidence_helper, db_mock):
    """Testing the malicious_ja3s method."""
    malicious_ja3_dict = {
        "ja3_hash_1": '{"threat_level": "high", "description": "Potential malware", "tags": "malware"}',
        "ja3_hash_2": '{"threat_level": "medium", "description": "Suspicious activity", "tags": "suspicious"}',
    }

    set_evidence_helper.malicious_ja3s(
        malicious_ja3_dict=malicious_ja3_dict,
        twid="timewindow9",
        uid="unique_id",
        timestamp="2023-05-06T12:00:00Z",
        saddr="192.168.0.1",
        daddr="10.0.0.1",
        ja3="ja3_hash_1",
    )

    assert db_mock.set_evidence.call_count == 2
    args, _ = db_mock.set_evidence.call_args_list[0]
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.MALICIOUS_JA3S
    assert evidence.attacker.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.HIGH
    assert evidence.category == IDEACategory.INTRUSION_BOTNET
    assert evidence.profile.ip == "10.0.0.1"
    assert evidence.timewindow.number == 9
    assert evidence.uid == ["unique_id"]
    assert evidence.source_target_tag == Tag.CC


def test_malicious_ja3(set_evidence_helper, db_mock):
    """Testing the malicious_ja3 method."""
    malicious_ja3_dict = {
        "ja3_hash_1": '{"threat_level": "high", "description": "Potential malware", "tags": "malware"}',
        "ja3_hash_2": '{"threat_level": "medium", "description": "Suspicious activity", "tags": "suspicious"}',
    }

    set_evidence_helper.malicious_ja3(
        malicious_ja3_dict=malicious_ja3_dict,
        twid="timewindow10",
        uid="unique_id",
        timestamp="2023-05-06T12:00:00Z",
        daddr="10.0.0.1",
        saddr="192.168.0.1",
        ja3="ja3_hash_2",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.MALICIOUS_JA3
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.victim.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.MEDIUM
    assert evidence.category == IDEACategory.INTRUSION_BOTNET
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 10
    assert evidence.uid == ["unique_id"]
    assert evidence.source_target_tag == Tag.BOTNET


def test_data_exfiltration(set_evidence_helper, db_mock):
    """Testing the data_exfiltration method."""
    set_evidence_helper.data_exfiltration(
        daddr="10.0.0.1",
        src_mbs=100.0,
        profileid="profile_192.168.0.1",
        twid="timewindow11",
        uid=["unique_id"],
        timestamp="2023-05-06T12:00:00Z",
    )

    assert db_mock.set_evidence.call_count == 2
    args, _ = db_mock.set_evidence.call_args_list[0]
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.DATA_UPLOAD
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.threat_level == ThreatLevel.INFO
    assert evidence.category == IDEACategory.MALWARE
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 11
    assert evidence.uid == ["unique_id"]
    assert evidence.source_target_tag == Tag.ORIGIN_MALWARE


def test_bad_smtp_login(set_evidence_helper, db_mock):
    """Testing the bad_smtp_login method."""
    set_evidence_helper.bad_smtp_login(
        saddr="192.168.0.1",
        daddr="10.0.0.1",
        stime="2023-05-06T12:00:00Z",
        twid="timewindow12",
        uid="unique_id",
    )

    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.BAD_SMTP_LOGIN
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.victim.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.HIGH
    assert evidence.category == IDEACategory.ATTEMPT_LOGIN
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 12
    assert evidence.uid == ["unique_id"]


def test_smtp_bruteforce(set_evidence_helper, db_mock):
    """Testing the smtp_bruteforce method."""
    flow = {
        "saddr": "192.168.0.1",
        "daddr": "10.0.0.1",
        "starttime": "2023-05-06T12:00:00Z",
    }
    twid = "timewindow13"
    uid = ["unique_id1", "unique_id2"]
    smtp_bruteforce_threshold = 10
    set_evidence_helper.smtp_bruteforce(
        flow=flow,
        twid=twid,
        uid=uid,
        smtp_bruteforce_threshold=smtp_bruteforce_threshold,
    )
    assert db_mock.set_evidence.call_count == 1
    args, _ = db_mock.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.SMTP_LOGIN_BRUTEFORCE
    assert evidence.attacker.value == "192.168.0.1"
    assert evidence.victim.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.HIGH
    assert evidence.category == IDEACategory.ATTEMPT_LOGIN
    assert evidence.profile.ip == "192.168.0.1"
    assert evidence.timewindow.number == 13
    assert sorted(evidence.uid) == sorted(uid)
    assert evidence.conn_count == smtp_bruteforce_threshold


def test_malicious_ssl(set_evidence_helper, db_mock):
    """Testing the malicious_ssl method."""
    ssl_info = {
        "flow": {
            "starttime": "2023-05-06T12:00:00Z",
            "daddr": "10.0.0.1",
            "saddr": "192.168.0.1",
            "uid": "unique_id",
        },
        "twid": "timewindow14",
    }
    ssl_info_from_db = '{"tags": "malware", "description": "Potential malware", "threat_level": "high"}'

    set_evidence_helper.malicious_ssl(ssl_info, ssl_info_from_db)

    assert db_mock.set_evidence.call_count == 2
    args, _ = db_mock.set_evidence.call_args_list[0]
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.MALICIOUS_SSL_CERT
    assert evidence.attacker.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.HIGH
    assert evidence.category == IDEACategory.INTRUSION_BOTNET
    assert evidence.profile.ip == "10.0.0.1"
    assert evidence.timewindow.number == 14
    assert evidence.uid == ["unique_id"]
    assert evidence.source_target_tag == Tag.CC
