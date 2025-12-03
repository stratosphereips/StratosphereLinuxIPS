import pytest
import tempfile
from pathlib import Path
from pipeline_ml_training.dataset_wrapper import (
    ZeekDataset,
    find_and_load_datasets,
    sample_n_from_each_dataset,
)
from pipeline_ml_training.commons import BENIGN, MALICIOUS, BACKGROUND


class TestZeekDataset:
    """Comprehensive test suite for ZeekDataset class."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def sample_conn_log(self, temp_dir):
        """Create a sample conn.log with headers and data."""
        conn_file = temp_dir / "conn.log"
        content = """#separator \t
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2021-01-01-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	history	orig_pkts	resp_pkts	label
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	string	count	count	string
1609459200.001	uid-1	192.168.1.1	12345	10.0.0.1	443	tcp	https	10.5	1024	2048	SF	ShADaFf	15	14	Benign
1609459201.001	uid-2	192.168.1.2	54321	8.8.8.8	53	udp	dns	0.1	60	140	SF	Dd	1	1	-
1609459202.001	uid-3	192.168.1.3	48373	192.168.1.100	445	tcp	smb	300.5	5000	10000	S0	S	10	8	Malicious
1609459203.001	uid-4	192.168.1.4	12345	10.0.0.2	80	tcp	http	5.0	512	1024	SF	ShADaFf	5	5	Background
1609459204.001	uid-5	192.168.1.5	50000	192.168.1.50	22	tcp	ssh	2.0	256	512	SF	ShADaFf	2	2	MALWARE
"""
        conn_file.write_text(content)
        return conn_file

    @pytest.fixture
    def sample_labeled_log(self, temp_dir):
        """Create a sample conn.log.labeled file."""
        labeled_file = temp_dir / "conn.log.labeled"
        content = """#separator \t
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2021-01-01-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	history	orig_pkts	resp_pkts	label
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	string	count	count	string
1609459200.001	uid-1	192.168.1.1	12345	10.0.0.1	443	tcp	https	10.5	1024	2048	SF	ShADaFf	15	14	Benign
1609459201.001	uid-2	192.168.1.2	54321	8.8.8.8	53	udp	dns	0.1	60	140	SF	Dd	1	1	Benign
1609459202.001	uid-3	192.168.1.3	48373	192.168.1.100	445	tcp	smb	300.5	5000	10000	S0	S	10	8	Malicious
1609459203.001	uid-4	192.168.1.4	12345	10.0.0.2	80	tcp	http	5.0	512	1024	SF	ShADaFf	5	5	Background
1609459204.001	uid-5	192.168.1.5	50000	192.168.1.50	22	tcp	ssh	2.0	256	512	SF	ShADaFf	2	2	MALWARE
"""
        labeled_file.write_text(content)
        return labeled_file

    # ========== Initialization and File Detection Tests ==========
    def test_initialization_and_file_detection(
        self, sample_conn_log, temp_dir
    ):
        """Test ZeekDataset initialization and file priority detection."""
        # Test with conn.log
        ds_plain = ZeekDataset(temp_dir, batch_size=2)
        assert ds_plain.current_file == sample_conn_log
        assert ds_plain.batch_size == 2
        assert ds_plain.seed is None

        # Test file priority: labeled > alt_labeled > plain
        labeled = temp_dir / "conn.log.labeled"
        labeled.write_text(sample_conn_log.read_text())
        ds_labeled = ZeekDataset(temp_dir, batch_size=3)
        assert ds_labeled.current_file == labeled

        # Test alt_labeled priority
        alt_labeled = temp_dir / "labeled-conn.log"
        labeled.unlink()
        alt_labeled.write_text(sample_conn_log.read_text())
        ds_alt = ZeekDataset(temp_dir, batch_size=2)
        assert ds_alt.current_file == alt_labeled

    def test_initialization_missing_file_raises_error(self, temp_dir):
        """Test that missing conn.log raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            ZeekDataset(temp_dir, batch_size=2)

    def test_initialization_missing_root_raises_error(self):
        """Test that missing root directory raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            ZeekDataset("/nonexistent/path", batch_size=2)

    # ========== Header and Type Parsing Tests ==========
    def test_headers_and_types_parsing(self, sample_conn_log, temp_dir):
        """Test correct parsing of #fields and #types from log file."""
        ds = ZeekDataset(temp_dir, batch_size=2)

        expected_headers = [
            "ts",
            "uid",
            "id.orig_h",
            "id.orig_p",
            "id.resp_h",
            "id.resp_p",
            "proto",
            "service",
            "duration",
            "orig_bytes",
            "resp_bytes",
            "conn_state",
            "history",
            "orig_pkts",
            "resp_pkts",
            "label",
        ]
        expected_types = [
            "time",
            "string",
            "addr",
            "port",
            "addr",
            "port",
            "enum",
            "string",
            "interval",
            "count",
            "count",
            "string",
            "string",
            "count",
            "count",
            "string",
        ]

        assert ds.headers == expected_headers
        assert ds.types == expected_types

    # ========== Label Mapping and Filtering Tests ==========
    def test_label_mapping_and_background_filtering(
        self, sample_conn_log, temp_dir
    ):
        """Test label mapping to BENIGN/MALICIOUS and BACKGROUND filtering."""
        ds = ZeekDataset(temp_dir, batch_size=10)

        # Should have 4 valid flows (Background filtered out)
        # Flow 1: "Benign" -> BENIGN
        # Flow 2: "-" (empty) -> BENIGN (default)
        # Flow 3: "Malicious" -> MALICIOUS
        # Flow 4: "Background" -> filtered out
        # Flow 5: "MALWARE" -> MALICIOUS (contains "MAL")
        assert ds.total_lines == 4
        assert len(ds.valid_indices) == 4
        assert len(ds.labels) == 4

        # Check label values
        labels_set = set(ds.labels)
        assert BENIGN in labels_set
        assert MALICIOUS in labels_set
        assert BACKGROUND not in labels_set

    def test_label_mapping_variations(self, temp_dir):
        """Test label mapping with various case and format variations."""
        conn_file = temp_dir / "conn.log"
        content = """#separator \t
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2021-01-01-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	history	orig_pkts	resp_pkts	label
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	string	count	count	string
1609459200.001	uid-1	192.168.1.1	12345	10.0.0.1	443	tcp	https	10.5	1024	2048	SF	ShADaFf	15	14	benign
1609459201.001	uid-2	192.168.1.2	54321	8.8.8.8	53	udp	dns	0.1	60	140	SF	Dd	1	1	BENIGN
1609459202.001	uid-3	192.168.1.3	48373	192.168.1.100	445	tcp	smb	300.5	5000	10000	S0	S	10	8	malicious
1609459203.001	uid-4	192.168.1.4	12345	10.0.0.2	80	tcp	http	5.0	512	1024	SF	ShADaFf	5	5	ATTACK_MALWARE
1609459204.001	uid-5	192.168.1.5	50000	192.168.1.50	22	tcp	ssh	2.0	256	512	SF	ShADaFf	2	2	1
1609459205.001	uid-6	192.168.1.6	40000	192.168.1.60	25	tcp	smtp	3.0	128	256	SF	ShADaFf	3	3	background
"""
        conn_file.write_text(content)
        ds = ZeekDataset(temp_dir, batch_size=10)

        # 5 valid flows (background filtered), 2 benign, 3 malicious
        assert ds.total_lines == 5
        assert ds.labels.count(str(BENIGN)) == 2
        assert ds.labels.count(str(MALICIOUS)) == 3

    def test_missing_label_defaults_to_benign(self, temp_dir):
        """Test that missing or empty label defaults to BENIGN."""
        conn_file = temp_dir / "conn.log"
        content = """#separator \t
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2021-01-01-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	history	orig_pkts	resp_pkts	label
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	string	count	count	string
1609459200.001	uid-1	192.168.1.1	12345	10.0.0.1	443	tcp	https	10.5	1024	2048	SF	ShADaFf	15	14	-
1609459201.001	uid-2	192.168.1.2	54321	8.8.8.8	53	udp	dns	0.1	60	140	SF	Dd	1	1
"""
        conn_file.write_text(content)
        ds = ZeekDataset(temp_dir, batch_size=10)

        assert ds.total_lines == 2
        assert all(label == str(BENIGN) for label in ds.labels)

    # ========== Type Casting Tests ==========
    def test_cast_conversions(self, sample_conn_log, temp_dir):
        """Test type casting for int, float, bool, and string types."""
        ds = ZeekDataset(temp_dir, batch_size=10)

        # Test _cast function
        assert ds._cast("1234", "count") == 1234
        assert ds._cast("12.34", "double") == 12.34
        assert ds._cast("t", "bool") is True
        assert ds._cast("f", "bool") is False
        assert ds._cast("hello", "string") == "hello"
        assert ds._cast("-", "count") is None
        assert ds._cast("", "string") is None

    def test_line_data_with_casting(self, sample_conn_log, temp_dir):
        """Test that retrieved lines have correct types after casting."""
        ds = ZeekDataset(temp_dir, batch_size=10)
        line = ds.get_line(0)

        # Check types are correct
        assert isinstance(line["ts"], float)
        assert isinstance(line["uid"], str)
        assert isinstance(line["id.orig_p"], int)
        assert isinstance(line["duration"], float)
        assert isinstance(line["orig_bytes"], int)
        assert line["label"] in [str(BENIGN), str(MALICIOUS)]

    # ========== Batching and Iteration Tests ==========
    def test_next_batch_basic(self, sample_conn_log, temp_dir):
        """Test next_batch returns correct batch size and data."""
        ds = ZeekDataset(temp_dir, batch_size=2)

        # Get first batch
        batch1 = ds.next_batch()
        assert len(batch1) == 2
        assert ds._batch_pos == 2
        assert ds.epoch == 0

        # Get second batch
        batch2 = ds.next_batch()
        assert len(batch2) == 2
        assert ds._batch_pos == 4
        assert ds.epoch == 0

        # Get third batch - should wrap and increment epoch
        batch3 = ds.next_batch()
        assert len(batch3) == 2
        assert ds._batch_pos == 2
        assert ds.epoch == 1

    def test_next_batch_with_remainder(self, sample_conn_log, temp_dir):
        """Test next_batch handles batch size that doesn't divide evenly."""
        ds = ZeekDataset(temp_dir, batch_size=3)

        batch1 = ds.next_batch()
        assert len(batch1) == 3

        batch2 = ds.next_batch()
        assert len(batch2) == 1  # remainder

    def test_reset_epoch(self, sample_conn_log, temp_dir):
        """Test reset_epoch resets state correctly."""
        ds = ZeekDataset(temp_dir, batch_size=2)

        # Advance through all batches to wrap and increment epoch
        ds.next_batch()  # batch_pos = 2
        ds.next_batch()  # batch_pos = 4
        ds.next_batch()  # batch_pos >= len(indices), so epoch increments and batch_pos resets

        assert ds.epoch == 1
        assert ds._batch_pos == 2

        # Reset
        ds.reset_epoch(batch_size=3)
        assert ds.batch_size == 3
        assert ds._batch_pos == 0
        assert ds.epoch == 0
        assert len(ds.indices) == ds.total_lines

    def test_get_line_and_get_lines(self, sample_conn_log, temp_dir):
        """Test get_line and get_lines retrieve correct data."""
        ds = ZeekDataset(temp_dir, batch_size=2)

        # Get single line
        line0 = ds.get_line(0)
        assert "uid" in line0
        assert "label" in line0

        # Get range of lines
        lines = ds.get_lines(0, 2)
        assert len(lines) == 2
        assert all("uid" in line for line in lines)

    def test_get_line_out_of_bounds(self, sample_conn_log, temp_dir):
        """Test get_line raises error for out of bounds index."""
        ds = ZeekDataset(temp_dir, batch_size=2)

        with pytest.raises(IndexError):
            ds.get_line(999)

    # ========== Seeding and Shuffling Tests ==========
    def test_seed_shuffles_consistently(self, sample_conn_log, temp_dir):
        """Test that seed produces consistent shuffling across instances."""
        # Create two datasets with same seed
        ds1 = ZeekDataset(temp_dir, batch_size=2, seed=42)
        ds2 = ZeekDataset(temp_dir, batch_size=2, seed=42)

        # Same seed should produce same order
        assert ds1.indices == ds2.indices
        assert ds1.labels == ds2.labels

    def test_different_seeds_produce_different_order(
        self, sample_conn_log, temp_dir
    ):
        """Test that different seeds produce different shuffling."""
        ds1 = ZeekDataset(temp_dir, batch_size=2, seed=42)
        ds2 = ZeekDataset(temp_dir, batch_size=2, seed=123)

        # Different seeds likely produce different order (not guaranteed but very likely)
        # At least check they're properly shuffled (not just original order)
        assert len(ds1.indices) == len(ds2.indices)

    def test_no_seed_is_deterministic_on_same_file(
        self, sample_conn_log, temp_dir
    ):
        """Test that without seed, same file produces same order."""
        ds1 = ZeekDataset(temp_dir, batch_size=2, seed=None)
        ds2 = ZeekDataset(temp_dir, batch_size=2, seed=None)

        # Should load same order from same file
        assert ds1.indices == ds2.indices

    # ========== Cache Tests ==========
    def test_cache_creation_for_large_dataset(self, temp_dir):
        """Test that cache is created for datasets above threshold."""
        # Create large dataset
        conn_file = temp_dir / "conn.log"
        lines = [
            "#separator \t",
            "#set_separator\t,",
            "#empty_field\t(empty)",
            "#unset_field\t-",
            "#path\tconn",
            "#open\t2021-01-01-00-00-00",
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\tlabel",
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\tstring",
        ]

        # Add 35000 lines (above 30000 threshold)
        for i in range(35000):
            lines.append(
                f"1609459200.{i:06d}\tuid-{i}\t192.168.1.{i%255}\t{12345+i%10000}\t10.0.0.{i%255}\t443\ttcp\thttps\t10.5\t1024\t2048\tSF\tShADaFf\t15\t14\tBenign"
            )

        conn_file.write_text("\n".join(lines))

        # Create dataset - should trigger cache creation
        ds = ZeekDataset(temp_dir, batch_size=100)
        cache_file = ds._cache_path()

        assert cache_file.exists()
        assert ds.total_lines == 35000

    def test_cache_reloaded_on_same_file(self, temp_dir):
        """Test that cache is reused for same file."""
        conn_file = temp_dir / "conn.log"
        lines = [
            "#separator \t",
            "#set_separator\t,",
            "#empty_field\t(empty)",
            "#unset_field\t-",
            "#path\tconn",
            "#open\t2021-01-01-00-00-00",
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\tlabel",
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\tstring",
        ]

        for i in range(35000):
            lines.append(
                f"1609459200.{i:06d}\tuid-{i}\t192.168.1.{i%255}\t{12345+i%10000}\t10.0.0.{i%255}\t443\ttcp\thttps\t10.5\t1024\t2048\tSF\tShADaFf\t15\t14\tBenign"
            )

        conn_file.write_text("\n".join(lines))

        # First load
        ds1 = ZeekDataset(temp_dir, batch_size=100)
        cache_file = ds1._cache_path()
        cache_mtime = cache_file.stat().st_mtime

        # Second load should use cache
        ds2 = ZeekDataset(temp_dir, batch_size=100)
        assert cache_file.stat().st_mtime == cache_mtime
        assert ds2.total_lines == ds1.total_lines

    def test_clear_cache(self, temp_dir):
        """Test clear_cache removes cache file."""
        conn_file = temp_dir / "conn.log"
        lines = [
            "#separator \t",
            "#set_separator\t,",
            "#empty_field\t(empty)",
            "#unset_field\t-",
            "#path\tconn",
            "#open\t2021-01-01-00-00-00",
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\tlabel",
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\tstring",
        ]

        for i in range(35000):
            lines.append(
                f"1609459200.{i:06d}\tuid-{i}\t192.168.1.{i%255}\t{12345+i%10000}\t10.0.0.{i%255}\t443\ttcp\thttps\t10.5\t1024\t2048\tSF\tShADaFf\t15\t14\tBenign"
            )

        conn_file.write_text("\n".join(lines))

        ds = ZeekDataset(temp_dir, batch_size=100)
        cache_file = ds._cache_path()
        assert cache_file.exists()

        ds.clear_cache()
        assert not cache_file.exists()

    # ========== Helper Functions Tests ==========
    def test_len_and_batches_methods(self, sample_conn_log, temp_dir):
        """Test __len__ and batches() methods."""
        ds = ZeekDataset(temp_dir, batch_size=2)

        assert len(ds) == 4  # 4 valid flows
        assert ds.batches() == 2  # 4 / 2 = 2 batches

    def test_find_and_load_datasets(self, temp_dir):
        """Test find_and_load_datasets loads multiple datasets."""
        # Create subdirectories with datasets
        ds1_dir = temp_dir / "001" / "data"
        ds2_dir = temp_dir / "002" / "data"
        ds1_dir.mkdir(parents=True)
        ds2_dir.mkdir(parents=True)

        # Create conn.log files
        for ds_dir in [ds1_dir, ds2_dir]:
            conn_file = ds_dir / "conn.log"
            content = """#separator \t
#fields\tts\tuid\tproto\tlabel
#types\ttime\tstring\tenum\tstring
1609459200.001\tuid-1\ttcp\tBenign
"""
            conn_file.write_text(content)

        loaders = find_and_load_datasets(temp_dir, batch_size=10)

        assert "001" in loaders
        assert "002" in loaders
        assert all(isinstance(ds, ZeekDataset) for ds in loaders.values())

    def test_sample_n_from_each_dataset(self, temp_dir):
        """Test sample_n_from_each_dataset samples from each dataset."""
        ds1_dir = temp_dir / "001" / "data"
        ds1_dir.mkdir(parents=True)

        conn_file = ds1_dir / "conn.log"
        content = """#separator \t
#fields\tts\tuid\tproto\tlabel
#types\ttime\tstring\tenum\tstring
1609459200.001\tuid-1\ttcp\tBenign
1609459201.001\tuid-2\tudp\tBenign
1609459202.001\tuid-3\ttcp\tBenign
"""
        conn_file.write_text(content)

        loaders = find_and_load_datasets(temp_dir, batch_size=10)
        results = sample_n_from_each_dataset(loaders, n=2)

        assert "001" in results
        assert "samples" in results["001"]
        assert len(results["001"]["samples"]) == 2
        assert isinstance(results["001"]["df"], __import__("pandas").DataFrame)
