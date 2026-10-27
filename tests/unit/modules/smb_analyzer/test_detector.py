"""SMB behavior decisions, confidence and bounded-state regressions."""

import pytest

from modules.smb_analyzer.settings import RULES
from tests.module_factory import ModuleFactory

BASE = 1700000000.0


def event(index: int = 0, kind: str = "conn", **changes: object) -> dict:
    """Build a normalized metadata record.

    :param index: Distinct event and destination number.
    :param kind: Zeek record type.
    :param changes: Record field overrides.
    :return: Independent metadata dictionary without payload bytes.
    """
    result = dict(
        starttime=BASE + index / 10,
        uid=f"C{index}",
        record_id=f"R{kind}{index}" if kind != "conn" else "",
        saddr="192.168.1.120",
        daddr=f"10.0.0.{index % 250 + 1}",
        sport=50000,
        dport=445,
        interface="eth0",
        type_=kind,
        proto="tcp",
        state="S0",
        history="S",
        appproto="",
        sbytes=0,
        dbytes=0,
        dur=1,
        path="",
        action="",
        name="",
        username="",
        success="",
    )
    result.update(changes)
    return result


@pytest.mark.parametrize(
    "history,state,expected",
    [
        ("S", "S0", True),
        ("Sr", "REJ", True),
        ("ShADadfF", "SF", False),
        ("DdAa", "OTH", False),
        ("^ShAD", "SF", False),
    ],
)
def test_scan_requires_distinct_fresh_failed_probes(
    history: str, state: str, expected: bool
) -> None:
    """Session tails, successful copies and reversed flows are not scan probes.

    :param history: Zeek packet history.
    :param state: TCP result.
    :param expected: Whether a scan is supported.
    """
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = [
        f
        for i in range(20)
        for f in module.detector.process(
            event(i, history=history, state=state)
        )
    ]
    assert ("SMB_SCAN" in {f.kind for f in findings}) is expected


def test_scan_retries_and_old_observations_do_not_inflate_hosts() -> None:
    """Count distinct destinations inside the window, rather than packets or retries."""
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = []
    for i in range(100):
        findings += module.detector.process(
            event(i, daddr="10.0.0.1", starttime=BASE + i * 10)
        )
    assert not findings


def test_generic_mismatched_paths_and_propagation() -> None:
    """Detect repeated wrong path addresses without malware-specific indicators."""
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = []
    for i in range(25):
        findings += module.detector.process(event(i))
        findings += module.detector.process(
            event(
                i,
                "smb_mapping",
                path=r"\\10.123.45.67\IPC$",
                starttime=BASE + i / 10 + 0.01,
            )
        )
    kinds = {f.kind for f in findings}
    assert {
        "SMB_SCAN",
        "SMB_SHARE_SWEEP",
        "SMB_SHARE_PATH_MISMATCH",
        "SMB_SUSPECTED_PROPAGATION",
    } <= kinds
    assert all("WannaCry" not in f.description for f in findings)


@pytest.mark.parametrize(
    "path", [r"\\10.0.0.1\IPC$", r"\\server.example\IPC$"]
)
def test_normal_single_share_has_no_attack_finding(path: str) -> None:
    """An IPC share, DNS alias or one mismatched address is insufficient.

    :param path: Normal SMB path or server alias.
    """
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = module.detector.process(event(0, "smb_mapping", path=path))
    assert findings == []


@pytest.mark.parametrize(
    "approved,expected", [([], True), (["8.8.8.0/24"], False)]
)
def test_external_smb_exceptions(approved: list[str], expected: bool) -> None:
    """An external-server exception applies only to the external-connection rule.

    :param approved: Explicit external SMB networks.
    :param expected: Whether the external finding should be emitted.
    """
    module = ModuleFactory().create_smb_analyzer_obj(
        external_allowed_networks=approved
    )
    findings = module.detector.process(
        event(0, "smb_mapping", daddr="8.8.8.8", path=r"\\server\IPC$")
    )
    assert (
        "SMB_EXTERNAL_CONNECTION" in {f.kind for f in findings}
    ) is expected


@pytest.mark.parametrize("order", ["conn-first", "mapping-first"])
def test_suspicious_large_transfer_joins_both_arrival_orders(
    order: str,
) -> None:
    """A large upload plus scanning and SMB confirmation is stronger than size alone.

    :param order: Arrival ordering of connection summary and share mapping.
    """
    module = ModuleFactory().create_smb_analyzer_obj()
    for i in range(20):
        module.detector.process(event(i))
    conn = event(
        100,
        uid="Cbig",
        daddr="36.239.158.54",
        sbytes=5410965,
        dbytes=50910,
        history="ShADdaFr",
        state="RSTR",
        dur=435,
    )
    mapping = event(
        100,
        "smb_mapping",
        uid="Cbig",
        daddr="36.239.158.54",
        path=r"\\server\IPC$",
    )
    rows = [conn, mapping] if order == "conn-first" else [mapping, conn]
    findings = [f for row in rows for f in module.detector.process(row)]
    assert {"SMB_LARGE_TRANSFER", "SMB_SUSPICIOUS_TRANSFER"} <= {
        f.kind for f in findings
    }
    suspicious = next(
        f for f in findings if f.kind == "SMB_SUSPICIOUS_TRANSFER"
    )
    assert suspicious.details["sent_bytes"] == 5410965
    assert "not proven" in suspicious.description


def test_large_normal_copy_is_informational_and_tcp_port_alone_is_insufficient() -> (
    None
):
    """Neither normal size nor an unrecognized TCP/445 stream establishes an attack."""
    module = ModuleFactory().create_smb_analyzer_obj()
    large = event(1, state="SF", history="ShADadfF", sbytes=10**7, dbytes=1000)
    assert not module.detector.process(large)
    kinds = {
        f.kind
        for f in module.detector.process(
            event(1, "smb_mapping", path=r"\\server\data")
        )
    }
    assert kinds == {"SMB_LARGE_TRANSFER"}
    assert module.settings.rule("SMB_LARGE_TRANSFER")[1] == "info"


@pytest.mark.parametrize(
    "success,expected",
    [
        (False, True),
        ("F", True),
        (True, False),
        ("T", False),
        ("", False),
        (None, False),
    ],
)
def test_authentication_requires_explicit_failures(
    success: object, expected: bool
) -> None:
    """Unknown, missing and successful NTLM results are never failed passwords.

    :param success: Recorded optional NTLM result.
    :param expected: Whether repeated failures/spraying should match.
    """
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = [
        f
        for i in range(10)
        for f in module.detector.process(
            event(i, "ntlm", username=f"account{i}", success=success)
        )
    ]
    assert ("SMB_PASSWORD_GUESSING" in {f.kind for f in findings}) is expected
    assert ("SMB_PASSWORD_SPRAYING" in {f.kind for f in findings}) is expected


def test_same_failed_login_not_counted_twice_across_logs() -> None:
    """SMB session-setup and NTLM reports for one connection are one attempt."""
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = []
    for i in range(5):
        findings += module.detector.process(
            event(i, "ntlm", username="user", success=False)
        )
        findings += module.detector.process(
            event(
                i,
                "smb_cmd",
                username="user",
                command="SESSION_SETUP_ANDX",
                status="LOGON_FAILURE",
            )
        )
    assert not findings


@pytest.mark.parametrize(
    "written,operation,expected",
    [
        (True, "StartServiceW", True),
        (False, "StartServiceW", False),
        (True, "OpenSCManagerW", False),
    ],
)
def test_executable_write_then_service_request(
    written: bool, operation: str, expected: bool
) -> None:
    """An executable open alone or a service query does not establish this sequence.

    :param written: Whether a write was observed.
    :param operation: Requested RPC operation.
    :param expected: Whether the sequence should be reported.
    """
    module = ModuleFactory().create_smb_analyzer_obj()
    module.detector.process(
        event(
            1,
            "smb_files",
            path=r"\\server\ADMIN$",
            name="agent.exe",
            action="SMB::FILE_WRITE" if written else "SMB::FILE_OPEN",
        )
    )
    findings = module.detector.process(
        event(
            2,
            "dce_rpc",
            daddr="10.0.0.2",
            dport=49155,
            endpoint="svcctl",
            operation=operation,
        )
    )
    assert ("SMB_REMOTE_EXECUTION" in {f.kind for f in findings}) is expected


@pytest.mark.parametrize(
    "distinct,renames,expected",
    [(True, True, True), (False, True, False), (True, False, False)],
)
def test_ransomware_requires_distinct_renames_and_other_changes(
    distinct: bool, renames: bool, expected: bool
) -> None:
    """Repeated chunks and mass writes alone cannot claim ransomware behavior.

    :param distinct: Whether changes affect distinct filenames.
    :param renames: Whether both renames and writes are present.
    :param expected: Whether the stronger ransomware rule should match.
    """
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = []
    for i in range(30):
        for action in (
            ["FILE_RENAME", "FILE_WRITE"] if renames else ["FILE_WRITE"]
        ):
            findings += module.detector.process(
                event(
                    i,
                    "smb_files",
                    daddr="10.0.0.1",
                    record_id=f"{action}{i}",
                    path=r"\\server\data",
                    name=f"document{i if distinct else 0}.doc",
                    action="SMB::" + action,
                )
            )
    assert (
        "SMB_RANSOMWARE_BEHAVIOR" in {f.kind for f in findings}
    ) is expected


def test_state_limits_and_network_isolation() -> None:
    """Unique source floods, sessions and deduplication cannot grow state forever."""
    module = ModuleFactory().create_smb_analyzer_obj(
        max_sources=4,
        max_events_per_source=40,
        max_total_events=80,
        max_sessions=16,
        max_cooldowns=8,
    )
    for i in range(200):
        module.detector.process(
            event(i, saddr=f"192.168.1.{i % 20 + 1}"), scope="network1"
        )
    assert len(module.detector.sources) <= 4
    assert module.detector.total_events <= 80
    assert len(module.detector.sessions) <= 16
    assert len(module.detector.seen) <= 80
    assert len(module.detector.cooldowns) <= 8
    isolated = [
        f
        for i in range(10)
        for f in module.detector.process(
            event(i, starttime=BASE + 100), scope="network2"
        )
    ]
    assert not isolated


@pytest.mark.parametrize(
    "changes",
    [
        {"window_seconds": 0},
        {"scan_min_hosts": 1},
        {"ports": [0]},
        {"max_sources": True},
        {"scan_min_failure_ratio": 2},
        {"external_allowed_networks": ["bad"]},
        {"rules": {"BAD": {}}},
        {"rules": {"SMB_SCAN": {"confidence": 2}}},
    ],
)
def test_invalid_configuration_fails_before_processing(changes: dict) -> None:
    """Reject invalid configuration instead of silently running unsafe thresholds.

    :param changes: Invalid settings overrides.
    """
    factory = ModuleFactory()
    with pytest.raises(ValueError):
        factory.create_smb_analyzer_obj(**changes)


def test_every_rule_supports_disabling_and_confidence_overrides() -> None:
    """Severity is separate from observation confidence and every rule is configurable."""
    module = ModuleFactory().create_smb_analyzer_obj(
        rules={
            name: {"enabled": False, "threat_level": "info", "confidence": 0.3}
            for name in RULES
        }
    )
    for i in range(50):
        assert not module.detector.process(event(i))
    assert all(
        module.settings.rule(name) == (False, "info", 0.3) for name in RULES
    )


def test_single_mismatch_and_large_copy_do_not_claim_propagation() -> None:
    """A translated SMB path and a large legitimate copy need additional context."""
    module = ModuleFactory().create_smb_analyzer_obj()
    module.detector.process(event(1, "smb_mapping", path=r"\\10.8.8.8\data"))
    findings = module.detector.process(
        event(1, state="SF", history="ShADdfF", sbytes=10**7, dbytes=1000)
    )
    assert {f.kind for f in findings} == {"SMB_LARGE_TRANSFER"}


def test_rpc_correlation_handles_late_file_record_without_reversing_sequence() -> (
    None
):
    """Arrival order can differ, but the executable write must precede the RPC call."""
    module = ModuleFactory().create_smb_analyzer_obj()
    rpc = event(
        10,
        "dce_rpc",
        daddr="10.0.0.2",
        dport=49155,
        endpoint="svcctl",
        operation="StartServiceW",
    )
    assert not module.detector.process(rpc)
    findings = module.detector.process(
        event(
            1,
            "smb_files",
            path=r"\\server\ADMIN$",
            name="agent.exe",
            action="SMB::FILE_WRITE",
        )
    )
    assert "SMB_REMOTE_EXECUTION" in {f.kind for f in findings}
    future = ModuleFactory().create_smb_analyzer_obj()
    future.detector.process(rpc)
    findings = future.detector.process(
        event(
            11,
            "smb_files",
            daddr="10.0.0.2",
            path=r"\\server\ADMIN$",
            name="agent.exe",
            action="SMB::FILE_WRITE",
        )
    )
    assert not findings


@pytest.mark.parametrize("stable_id", [True, False])
def test_repeated_renames_of_one_file_are_not_many_files(
    stable_id: bool,
) -> None:
    """Follow an observed handle or rename chain rather than counting filenames.

    :param stable_id: Whether Zeek supplied an explicit file-handle identifier.
    """
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = []
    for i in range(30):
        for action in ("FILE_RENAME", "FILE_WRITE"):
            findings += module.detector.process(
                event(
                    i,
                    "smb_files",
                    daddr="10.0.0.1",
                    record_id=f"{action}{i}",
                    file_id="one-handle" if stable_id else "",
                    path=r"\\server\data",
                    name=f"name{i+1}",
                    prev_name=f"name{i}",
                    action="SMB::" + action,
                )
            )
    assert "SMB_RANSOMWARE_BEHAVIOR" not in {f.kind for f in findings}


def test_out_of_order_probes_still_use_the_capture_window() -> None:
    """Parallel profiler arrival cannot hide a complete burst of failed probes."""
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = [
        f
        for i in reversed(range(20))
        for f in module.detector.process(event(i))
    ]
    assert "SMB_SCAN" in {f.kind for f in findings}


def test_large_file_uses_reported_size_without_claiming_bytes_transferred() -> (
    None
):
    """An individual file observation has different meaning from session volume."""
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = module.detector.process(
        event(
            1,
            "smb_files",
            action="SMB::FILE_CLOSE",
            path=r"\\server\data",
            name="backup.zip",
            size=200000000,
        )
    )
    assert {f.kind for f in findings} == {"SMB_LARGE_FILE"}
    assert "not a measurement" in findings[0].description


@pytest.mark.parametrize(
    "state",
    ["SUCCESS", "MORE_PROCESSING_REQUIRED", "PENDING", "ACCESS_DENIED", ""],
)
def test_non_failure_authentication_status_is_not_password_guessing(
    state: str,
) -> None:
    """Progress, missing results and generic permission denial are not bad passwords.

    :param state: SMB session setup reply status.
    """
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = [
        f
        for i in range(30)
        for f in module.detector.process(
            event(
                i,
                "smb_cmd",
                status=state,
                command="SESSION_SETUP",
                username="alice",
            )
        )
    ]
    assert not findings


def test_reopening_one_path_does_not_make_many_changed_files() -> None:
    """Different handles writing the same path do not inflate distinct-file counts."""
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = [
        f
        for i in range(50)
        for f in module.detector.process(
            event(
                i,
                "smb_files",
                daddr="10.0.0.1",
                file_id=f"handle{i}",
                action="SMB::FILE_WRITE",
                path=r"\\server\data",
                name="one-file.doc",
            )
        )
    ]
    assert not findings


def test_smb_scan_compacts_and_keeps_logarithmic_growth() -> None:
    """Large scans stop retaining each probe but still report their growth."""
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = []
    for i in range(12000):
        findings += module.detector.process(event(i, daddr=f"198.18.{i//256}.{i%256}", starttime=BASE+i/10000))
    scans = [f for f in findings if f.kind == "SMB_SCAN"]
    assert [f.details["scan_confidence"] for f in scans] == [.85, .95, 1, 1, 1]
    assert len([f for f in scans if f.details.get("approximate")]) == 2
    context = next(iter(module.detector.sources.values()))
    assert not context.events
    assert module.detector.total_events == 0
    assert len(module.detector.seen) == 200
    assert module.detector.evictions == 0
    assert len(context.growth["SMB_SCAN"].counter.registers) == 1024
    for finding in scans:
        module.emit(finding, 1)
    assert module.db.set_evidence.call_args.args[0].confidence == 1
    assert all(len(f.uids) <= 20 for f in scans)
    transfer = module.detector.process(event(13000, starttime=BASE+2, daddr="198.18.99.1", appproto="smb", state="SF", history="ShADadFf", sbytes=5000000, dbytes=100))
    assert "SMB_SUSPICIOUS_TRANSFER" in {f.kind for f in transfer}


@pytest.mark.parametrize("axis", ["hosts", "names"])
def test_share_sweeps_compact_the_confirmed_distinct_axis(axis: str) -> None:
    """Count hosts or share names without converting ordinary single-share use.

    Parameters:
        axis: Broad share activity supported by the capture.
    """
    module = ModuleFactory().create_smb_analyzer_obj()
    findings = []
    for i in range(1200):
        findings += module.detector.process(event(i, "smb_mapping", starttime=BASE+i/10000,
            daddr=f"198.18.{i//256}.{i%256}" if axis == "hosts" else "10.0.0.1",
            path=f"\\\\server.example\\{'IPC$' if axis == 'hosts' else 'share'+str(i)}"))
    sweeps = [f for f in findings if f.kind == "SMB_SHARE_SWEEP"]
    assert [f.details["scan_confidence"] for f in sweeps] == [.8, .95, 1, 1]
    assert sweeps[-1].details["approximate"]
    context = next(iter(module.detector.sources.values()))
    assert not any(k[0] == "share" for k in context.events)
    assert len(context.growth["SMB_SHARE_SWEEP"].counter.registers) == 1024


def test_smb_missing_history_cannot_promote_confidence_and_quiet_resets() -> None:
    """Preserve uncertainty and require fresh confirmation after a probe-free gap."""
    module = ModuleFactory().create_smb_analyzer_obj()
    for i in range(200):
        module.detector.process(event(i, history="", starttime=BASE+i/10000))
    context = next(iter(module.detector.sources.values()))
    assert not context.growth
    for i in range(200):
        module.detector.process(event(i+500, daddr=f"198.18.0.{i+1}", starttime=BASE+100+i/10000))
    assert "SMB_SCAN" in context.growth
    module.detector.process(event(1000, starttime=BASE+500))
    assert "SMB_SCAN" not in context.growth
    assert len([k for k in context.events if k[0] == "probe"]) == 1
