# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from unittest.mock import (
    patch,
    MagicMock,
    call,
    Mock,
)
from slips_files.common.slips_utils import utils
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "enable_metadata, expected_open_calls, expected_end_date",
    [
        # testcase1: Metadata enabled, info path exists
        (True, [call("/path/to/info.txt", "a")], "2023-06-01 12:00:00"),
        # testcase2: Metadata disabled
        (False, [], None),
    ],
)
def test_set_analysis_end_date(
    enable_metadata,
    expected_open_calls,
    expected_end_date,
):
    metadata_manager = ModuleFactory().create_metadata_manager_obj()
    metadata_manager.info_path = "/path/to/info.txt"
    metadata_manager.main.conf.add_metadata_if_enabled.return_value = (
        enable_metadata
    )

    utils.convert_format = Mock(return_value=expected_end_date)

    with patch("builtins.open", create=True) as mock_open:
        result = metadata_manager.set_analysis_end_date("dummy_end_date")

        assert result == expected_end_date

    if enable_metadata:
        metadata_manager.main.db.set_input_metadata.assert_called_once_with(
            {"analysis_end": expected_end_date}
        )

        assert mock_open.call_args_list == expected_open_calls


@pytest.mark.parametrize(
    "enable_metadata, expected_info_path, info_path_value_set, "
    "expected_call_count",
    [
        # testcase1: Metadata enabled
        (True, "/path/to/metadata/info.txt", True, 1),
        # testcase2: Metadata disabled
        (False, None, False, 0),
    ],
)
def test_enable_metadata(
    enable_metadata,
    expected_info_path,
    info_path_value_set,
    expected_call_count,
):
    metadata_manager = ModuleFactory().create_metadata_manager_obj()
    metadata_manager.enable_metadata = enable_metadata
    metadata_manager._add_metadata = Mock(return_value=expected_info_path)

    metadata_manager.add_metadata_if_enabled()

    if info_path_value_set:
        assert hasattr(metadata_manager, "info_path")
        assert metadata_manager.info_path == expected_info_path
    assert metadata_manager._add_metadata.call_count == expected_call_count


@pytest.mark.parametrize(
    "port, connections, expected_pid",
    [
        # testcase1: Process found using the port
        (80, [MagicMock(laddr=MagicMock(port=80), pid=1234)], 1234),
        # testcase2: No process found using the port
        (8080, [MagicMock(laddr=MagicMock(port=80), pid=1234)], None),
        # testcase3: Multiple connections, one matching
        (
            443,
            [
                MagicMock(laddr=MagicMock(port=80), pid=1234),
                MagicMock(laddr=MagicMock(port=443), pid=5678),
                MagicMock(laddr=MagicMock(port=8080), pid=9012),
            ],
            5678,
        ),
    ],
)
def test_get_pid_using_port(port, connections, expected_pid):
    metadata_manager = ModuleFactory().create_metadata_manager_obj()
    with patch("psutil.net_connections", return_value=connections), patch(
        "psutil.Process"
    ) as mock_process:
        mock_process.return_value.pid = expected_pid
        result = metadata_manager.get_pid_using_port(port)
        assert result == expected_pid


@pytest.mark.parametrize(
    "output_dir, config_file, whitelist_path,"
    "version, input_info, branch, commit, expected_result",
    [
        (
            "/tmp/output",
            "config/slips.yaml",
            "/path/to/whitelist.conf",
            "1.0",
            "test_input",
            "main",
            "abc123",
            "/tmp/output/metadata/info.txt",
        ),
    ],
)
def test_add_metadata(
    output_dir,
    config_file,
    whitelist_path,
    version,
    input_info,
    branch,
    commit,
    expected_result,
):
    metadata_manager = ModuleFactory().create_metadata_manager_obj()
    metadata_manager.main.args.output = output_dir
    metadata_manager.main.args.config = config_file
    metadata_manager.main.conf.local_whitelist_path.return_value = (
        whitelist_path
    )
    metadata_manager.main.version = version
    metadata_manager.main.input_information = input_info
    metadata_manager.main.db.get_branch.return_value = branch
    metadata_manager.main.db.get_commit.return_value = commit

    with patch("os.mkdir"), patch("shutil.copy"), patch(
        "builtins.open", create=True
    ), patch.object(
        utils, "convert_format", return_value="2023-01-01 00:00:00"
    ):
        result = metadata_manager._add_metadata()
        assert result == expected_result


@pytest.mark.parametrize(
    "slips_internal_time, modified_profiles,"
    "last_modified_tw_time, expected_modified_ips, "
    "expected_set_slips_internal_time_call_args",
    [
        # testcase1: Some profiles modified
        (100.0, {"profile1", "profile2"}, 101.0, 2, [call(101.0)]),
        # testcase2: No profiles modified
        (200.0, set(), 0, 0, []),
        # testcase3: Many profiles modified
        (
            300.0,
            set(f"profile{i}" for i in range(100)),
            301.0,
            100,
            [call(301.0)],
        ),
    ],
)
def test_update_slips_stats_in_the_db(
    slips_internal_time,
    modified_profiles,
    last_modified_tw_time,
    expected_modified_ips,
    expected_set_slips_internal_time_call_args,
):
    metadata_manager = ModuleFactory().create_metadata_manager_obj()
    metadata_manager.main.db.getSlipsInternalTime.return_value = str(
        slips_internal_time
    )
    metadata_manager.main.db.get_modified_profiles_since.return_value = (
        modified_profiles,
        last_modified_tw_time,
    )

    modified_ips, returned_modified_profiles = (
        metadata_manager.update_slips_stats_in_the_db()
    )

    assert modified_ips == expected_modified_ips
    assert returned_modified_profiles == modified_profiles

    metadata_manager.main.db.set_input_metadata.assert_called_once_with(
        {"modified_ips_in_the_last_tw": expected_modified_ips}
    )

    assert (
        metadata_manager.main.db.set_slips_internal_time.call_args_list
        == expected_set_slips_internal_time_call_args
    )
