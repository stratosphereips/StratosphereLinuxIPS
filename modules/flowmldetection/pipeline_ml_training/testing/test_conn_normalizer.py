import pytest
from pipeline_ml_training.conn_normalizer import (
    ConnToSlipsConverter,
    CANONICAL_FIELDS,
)


class TestConnToSlipsConverter:
    """Comprehensive test suite for ConnToSlipsConverter class."""

    @pytest.fixture
    def converter(self):
        """Create a converter instance for testing."""
        return ConnToSlipsConverter(default_label="Benign")

    @pytest.fixture
    def basic_flow(self):
        """Create a basic Zeek flow dict."""
        return {
            "ts": "1234567890.123",
            "uid": "uid-123",
            "id.orig_h": "192.168.1.1",
            "id.orig_p": "12345",
            "id.resp_h": "10.0.0.1",
            "id.resp_p": "443",
            "proto": "tcp",
            "service": "https",
            "duration": "10.5",
            "orig_bytes": "1024",
            "resp_bytes": "2048",
            "conn_state": "SF",
            "history": "ShADaFf",
            "orig_pkts": "15",
            "resp_pkts": "14",
            "label": "Benign",
        }

    # ========== Tests for safe conversion functions ==========
    def test_safe_int_conversions(self, converter):
        """Test _safe_int with various inputs."""
        test_cases = [
            ("123", 123),
            ("123.456", 123),  # float string truncates
            ("invalid", 0),  # invalid returns default
            ("", 0),  # empty string
            (None, 0),  # None
            (456, 456),  # integer input
            (789.5, 789),  # float input
        ]
        for input_val, expected in test_cases:
            assert (
                converter._safe_int(input_val) == expected
            ), f"Failed for {input_val}"

    def test_safe_int_custom_default(self, converter):
        """Test _safe_int respects custom default."""
        assert converter._safe_int("invalid", default=99) == 99
        assert converter._safe_int("", default=-1) == -1

    def test_safe_float_conversions(self, converter):
        """Test _safe_float with various inputs."""
        test_cases = [
            ("123.456", 123.456),
            ("123", 123.0),
            ("invalid", 0.0),
            ("", 0.0),
            (None, 0.0),
            (456.789, 456.789),
            (100, 100.0),
        ]
        for input_val, expected in test_cases:
            assert (
                converter._safe_float(input_val) == expected
            ), f"Failed for {input_val}"

    def test_safe_float_custom_default(self, converter):
        """Test _safe_float respects custom default."""
        assert converter._safe_float("invalid", default=99.5) == 99.5
        assert converter._safe_float("bad", default=-1.5) == -1.5

    # ========== Tests for _infer_state ==========
    def test_infer_state_keyword_based(self, converter):
        """Test _infer_state with keyword-based patterns."""
        test_cases = [
            ({"state": "new", "spkts": "5", "dpkts": "5"}, 1.0),
            (
                {"state": "NEW", "spkts": "5", "dpkts": "5"},
                1.0,
            ),  # case insensitive
            ({"state": "established", "spkts": "10", "dpkts": "10"}, 1.0),
            ({"state": "ESTABLISHED", "spkts": "10", "dpkts": "10"}, 1.0),
            ({"state": "closed", "spkts": "5", "dpkts": "5"}, 0.0),
            ({"state": "not established", "spkts": "1", "dpkts": "1"}, 0.0),
        ]
        for flow, expected in test_cases:
            assert (
                converter._infer_state(flow) == expected
            ), f"Failed for {flow['state']}"

    def test_infer_state_closed_states(self, converter):
        """Test _infer_state with closed connection states."""
        closed_states = ["S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"]
        for state in closed_states:
            flow = {"state": state, "spkts": "1", "dpkts": "0"}
            assert (
                converter._infer_state(flow) == 0.0
            ), f"State {state} should return 0.0"

    def test_infer_state_established_states(self, converter):
        """Test _infer_state with established connection states."""
        established_states = ["S1", "SF", "S2", "S3", "RSTO", "RSTP", "OTH"]
        for state in established_states:
            flow = {"state": state, "spkts": "5", "dpkts": "5"}
            assert (
                converter._infer_state(flow) == 1.0
            ), f"State {state} should return 1.0"

    def test_infer_state_pattern_based(self, converter):
        """Test _infer_state with pattern-based detection."""
        # S and A together -> 1.0
        assert (
            converter._infer_state({"state": "SA", "spkts": "2", "dpkts": "2"})
            == 1.0
        )
        # PA pattern -> 1.0
        assert (
            converter._infer_state({"state": "PA", "spkts": "5", "dpkts": "5"})
            == 1.0
        )
        # ECO/ECR/URH/URP patterns -> 1.0
        for pattern in ["ECO", "ECR", "URH", "URP"]:
            assert (
                converter._infer_state(
                    {"state": pattern, "spkts": "1", "dpkts": "1"}
                )
                == 1.0
            )
        # EST pattern -> 1.0
        assert (
            converter._infer_state(
                {"state": "EST", "spkts": "10", "dpkts": "9"}
            )
            == 1.0
        )

    def test_infer_state_rst_fin_packet_dependent(self, converter):
        """Test _infer_state RST/FIN depends on packet count."""
        # RST/FIN with <=3 packets -> 0.0
        assert (
            converter._infer_state(
                {"state": "RST", "spkts": "1", "dpkts": "1"}
            )
            == 0.0
        )
        assert (
            converter._infer_state(
                {"state": "FIN", "spkts": "2", "dpkts": "1"}
            )
            == 0.0
        )
        # RST/FIN with >3 packets -> 1.0
        assert (
            converter._infer_state(
                {"state": "RST", "spkts": "3", "dpkts": "2"}
            )
            == 1.0
        )
        assert (
            converter._infer_state(
                {"state": "FIN", "spkts": "2", "dpkts": "3"}
            )
            == 1.0
        )

    def test_infer_state_unknown_and_missing(self, converter):
        """Test _infer_state with unknown states and missing fields."""
        assert (
            converter._infer_state(
                {"state": "UNKNOWN", "spkts": "10", "dpkts": "10"}
            )
            == 0.0
        )
        assert converter._infer_state({}) == 0.0  # empty flow
        assert (
            converter._infer_state({"state": "SF"}) == 1.0
        )  # missing packets (defaults to 0)

    # ========== Tests for normalize (single flow) ==========
    def test_normalize_zeek_to_slips_mapping(self, converter, basic_flow):
        """Test normalize correctly maps Zeek fields to SLIPS fields."""
        result = converter.normalize(basic_flow)

        # Check Zeek -> SLIPS field mapping
        assert result["starttime"] == "1234567890.123"  # ts
        assert result["uid"] == "uid-123"
        assert result["saddr"] == "192.168.1.1"  # id.orig_h
        assert result["sport"] == 12345  # id.orig_p (converted to int)
        assert result["daddr"] == "10.0.0.1"  # id.resp_h
        assert result["dport"] == 443  # id.resp_p (converted to int)
        assert result["proto"] == "tcp"
        assert result["appproto"] == "https"  # service
        assert result["dur"] == 10.5  # duration (converted to float)
        assert result["sbytes"] == 1024  # orig_bytes (converted to int)
        assert result["dbytes"] == 2048  # resp_bytes (converted to int)
        assert result["spkts"] == 15  # orig_pkts (converted to int)
        assert result["dpkts"] == 14  # resp_pkts (converted to int)
        assert result["ground_truth_label"] == "Benign"  # label

    def test_normalize_state_inference(self, converter, basic_flow):
        """Test normalize correctly infers state."""
        result = converter.normalize(basic_flow)
        # SF state should convert to 1.0
        assert result["state"] == 1.0

    def test_normalize_canonical_fields_present(self, converter, basic_flow):
        """Test normalize includes all canonical fields."""
        result = converter.normalize(basic_flow)
        for field in CANONICAL_FIELDS:
            assert field in result, f"Missing canonical field: {field}"

    def test_normalize_default_values(self, converter):
        """Test normalize fills missing fields with appropriate defaults."""
        minimal_flow = {"uid": "test-uid"}
        result = converter.normalize(minimal_flow)

        # Check default values
        assert result["sport"] == 0  # int field
        assert result["dport"] == 0
        assert result["dur"] == 0.0  # float field
        assert result["state"] == 0.0
        assert result["ground_truth_label"] == "Benign"  # default label
        assert result["module_labels"] == {}  # dict field
        assert result["saddr"] == ""  # string field

    def test_normalize_default_label(self, converter):
        """Test normalize uses default label when missing."""
        flow_no_label = {
            "uid": "test",
            "id.orig_h": "192.168.1.1",
        }
        result = converter.normalize(flow_no_label)
        assert result["ground_truth_label"] == "Benign"

    def test_normalize_custom_default_label(self):
        """Test normalize with custom default label."""
        converter = ConnToSlipsConverter(default_label="Malicious")
        flow = {"uid": "test"}
        result = converter.normalize(flow)
        assert result["ground_truth_label"] == "Malicious"

    def test_normalize_different_column_order(self, converter):
        """Test normalize works with different column order."""
        flow_reordered = {
            "label": "Benign",
            "conn_state": "SF",
            "resp_pkts": "14",
            "orig_pkts": "15",
            "resp_bytes": "2048",
            "orig_bytes": "1024",
            "duration": "10.5",
            "service": "https",
            "proto": "tcp",
            "id.resp_p": "443",
            "id.resp_h": "10.0.0.1",
            "id.orig_p": "12345",
            "id.orig_h": "192.168.1.1",
            "uid": "uid-123",
            "ts": "1234567890.123",
        }
        result = converter.normalize(flow_reordered)
        assert result["saddr"] == "192.168.1.1"
        assert result["daddr"] == "10.0.0.1"
        assert result["sport"] == 12345
        assert result["dport"] == 443
        assert result["state"] == 1.0

    def test_normalize_already_canonical_fields(self, converter):
        """Test normalize accepts already-canonical SLIPS field names."""
        flow_canonical = {
            "starttime": "1234567890.123",
            "uid": "uid-123",
            "saddr": "192.168.1.1",
            "sport": "12345",
            "daddr": "10.0.0.1",
            "dport": "443",
        }
        result = converter.normalize(flow_canonical)
        assert result["starttime"] == "1234567890.123"
        assert result["saddr"] == "192.168.1.1"
        assert result["sport"] == 12345

    def test_normalize_unknown_fields_ignored(self, converter):
        """Test normalize ignores unknown fields."""
        flow_with_unknown = {
            "uid": "test-uid",
            "unknown_field": "some_value",
            "another_unknown": "value",
            "saddr": "192.168.1.1",
        }
        result = converter.normalize(flow_with_unknown)
        assert "unknown_field" not in result
        assert "another_unknown" not in result
        assert result["saddr"] == "192.168.1.1"
        assert result["uid"] == "test-uid"

    def test_normalize_numeric_string_conversion(self, converter):
        """Test normalize converts numeric strings correctly."""
        flow = {
            "uid": "test",
            "id.orig_p": "8080",
            "id.resp_p": "443",
            "orig_pkts": "100",
            "resp_pkts": "99",
            "orig_bytes": "50000",
            "resp_bytes": "75000",
            "duration": "123.456",
        }
        result = converter.normalize(flow)
        assert result["sport"] == 8080
        assert result["dport"] == 443
        assert result["spkts"] == 100
        assert result["dpkts"] == 99
        assert result["sbytes"] == 50000
        assert result["dbytes"] == 75000
        assert result["dur"] == 123.456

    # ========== Tests for normalize_batch ==========
    def test_normalize_batch_consistency_with_single(
        self, converter, basic_flow
    ):
        """Test normalize_batch produces same results as individual normalize calls."""
        flows = [basic_flow, basic_flow, basic_flow]

        # Normalize individually
        individual_results = [converter.normalize(f) for f in flows]

        # Normalize as batch
        batch_results = converter.normalize_batch(flows)

        # Results should be identical
        assert batch_results == individual_results

    def test_normalize_batch_multiple_flows(self, converter):
        """Test normalize_batch with multiple different flows."""
        flows = [
            {"uid": "flow-1", "id.orig_p": "80", "conn_state": "SF"},
            {"uid": "flow-2", "id.orig_p": "443", "conn_state": "S0"},
            {"uid": "flow-3", "id.orig_p": "22", "conn_state": "established"},
        ]

        results = converter.normalize_batch(flows)

        # Check results structure
        assert len(results) == 3
        assert results[0]["uid"] == "flow-1"
        assert results[0]["sport"] == 80
        assert results[0]["state"] == 1.0

        assert results[1]["uid"] == "flow-2"
        assert results[1]["sport"] == 443
        assert results[1]["state"] == 0.0

        assert results[2]["uid"] == "flow-3"
        assert results[2]["sport"] == 22
        assert results[2]["state"] == 1.0

    def test_normalize_batch_empty(self, converter):
        """Test normalize_batch with empty list."""
        results = converter.normalize_batch([])
        assert results == []

    def test_normalize_batch_single_flow(self, converter, basic_flow):
        """Test normalize_batch with single flow."""
        results = converter.normalize_batch([basic_flow])
        assert len(results) == 1
        assert results[0]["uid"] == "uid-123"

    def test_integration_whole_process(self, converter):
        """Test full process: Zeek format -> normalized SLIPS format."""
        zeek_flows = [
            {
                "ts": "1609459200.001",
                "uid": "zeek-1",
                "id.orig_h": "10.0.0.10",
                "id.orig_p": "54321",
                "id.resp_h": "8.8.8.8",
                "id.resp_p": "53",
                "proto": "udp",
                "service": "dns",
                "duration": "0.1",
                "orig_bytes": "60",
                "resp_bytes": "140",
                "conn_state": "SF",
                "history": "Dd",
                "orig_pkts": "1",
                "resp_pkts": "1",
                "label": "Benign",
            },
            {
                "ts": "1609459201.001",
                "uid": "zeek-2",
                "id.orig_h": "10.0.0.20",
                "id.orig_p": "48373",
                "id.resp_h": "192.168.1.100",
                "id.resp_p": "445",
                "proto": "tcp",
                "service": "smb",
                "duration": "300.5",
                "orig_bytes": "5000",
                "resp_bytes": "10000",
                "conn_state": "S0",
                "history": "S",
                "orig_pkts": "1",
                "resp_pkts": "0",
                "detailedlabel": "SMB-ScanningAttempt",
            },
        ]

        results = converter.normalize_batch(zeek_flows)

        # Verify first flow (DNS)
        assert results[0]["saddr"] == "10.0.0.10"
        assert results[0]["daddr"] == "8.8.8.8"
        assert results[0]["proto"] == "udp"
        assert results[0]["state"] == 1.0
        assert results[0]["ground_truth_label"] == "Benign"

        # Verify second flow (SMB scan attempt)
        assert results[1]["saddr"] == "10.0.0.20"
        assert results[1]["daddr"] == "192.168.1.100"
        assert results[1]["proto"] == "tcp"
        assert results[1]["state"] == 0.0
        assert results[1]["ground_truth_label"] == "Benign"  # default, not set
        assert (
            results[1]["detailed_ground_truth_label"] == "SMB-ScanningAttempt"
        )
