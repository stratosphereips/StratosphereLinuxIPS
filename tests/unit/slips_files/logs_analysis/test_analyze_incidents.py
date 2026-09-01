import json
from pathlib import Path

import pytest

from slips_files.logs_analysis.analyze_incidents import (
    load_jsonl,
    parse_note_uids,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "note, expected",
    [
        (json.dumps({"uids": ["C1", "C2"]}), ["C1", "C2"]),
        ("not-json", []),
    ],
)
def test_parse_note_uids_returns_note_uid_list(
    note: str, expected: list[str]
) -> None:
    """Verify Event Note UID extraction handles valid and invalid JSON.

    Parameters:
        note: Event Note value to parse.
        expected: Expected UID list.

    Return value:
        None.
    """
    module_factory = ModuleFactory()

    assert module_factory
    assert parse_note_uids(note) == expected


def test_load_jsonl_skips_comments_and_invalid_lines(tmp_path: Path) -> None:
    """Verify JSONL loader yields valid objects and ignores bad lines.

    Parameters:
        tmp_path: Pytest temporary directory fixture.

    Return value:
        None.
    """
    module_factory = ModuleFactory()
    alerts_path = tmp_path / "alerts.jsonl"
    alerts_path.write_text(
        '# comment\n{"ID": "event-1"}\nnot-json\n\n{"ID": "event-2"}\n',
        encoding="utf-8",
    )

    assert module_factory
    assert list(load_jsonl(alerts_path)) == [
        {"ID": "event-1"},
        {"ID": "event-2"},
    ]
