from pathlib import Path

from scripts.regex_prune_benign_threshold import (
    RegexAuditResult,
    build_summary,
)
from tests.module_factory import ModuleFactory


def test_build_summary_counts_flagged_and_timed_out_regexes() -> None:
    """Verify prune audit summaries aggregate per-type counts.

    Return value:
        None.
    """
    module_factory = ModuleFactory()
    flagged = RegexAuditResult(
        id=1,
        regex_type="domain",
        regex="evil\\.example",
        regex_hash="abc",
        created_at=0.0,
        strongest_benign_score=88.0,
        strongest_benign_value="evil.example",
    )

    summary = build_summary(
        regex_db_path=Path("regex.sqlite"),
        benign_db_path=Path("benign.sqlite"),
        threshold=75.0,
        regex_types=["domain"],
        accepted_by_type={"domain": [{"id": 1}]},
        flagged_by_type={"domain": [flagged]},
        timed_out_by_type={"domain": [{"id": 2, "created_at": 0.0}]},
        limit=5,
        deleted=0,
        backup_path=None,
        match_timeout_seconds=0.5,
    )

    assert module_factory
    assert summary["totals"]["accepted_count"] == 1
    assert summary["totals"]["flagged_count"] == 1
    assert summary["types"]["domain"]["timed_out_count"] == 1
