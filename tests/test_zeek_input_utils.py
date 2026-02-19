# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import pytest
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "contents,expected",
    [
        ("#separator \x09\n", True),
        ("field1\tfield2\n", True),
        (json.dumps({"ts": 1}), False),
    ],
)
def test_is_zeek_tabs_file_detects_format(tmp_path, contents, expected):
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    test_file = tmp_path / "conn.log"
    test_file.write_text(contents, encoding="utf-8")

    assert (
        input_process.zeek_utils.is_zeek_tabs_file(str(test_file)) == expected
    )


def test_get_ts_from_line_returns_timestamp_for_tabs():
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    input_process.is_zeek_tabs = True

    ts, line = input_process.zeek_utils.get_ts_from_line("1.5\tfield\n")
    assert ts == 1.5
    assert line == "1.5\tfield\n"
