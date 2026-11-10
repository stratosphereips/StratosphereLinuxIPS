"""Small per-source status records written only by feed-loading workers."""

import time
from typing import Any


def record_feed_status(db: Any, source: str, **fields: Any) -> None:
    """Merge source metadata without losing counts or download validators.

    Parameters:
        db: Slips database facade.
        source: Existing TI source key.
        fields: Status fields to replace in the source's current record.
    """
    previous = db.get_ti_feed_info(source)
    info = dict(previous) if isinstance(previous, dict) else {}
    info.update(fields)
    db.set_ti_feed_info(source, info)


def record_feed_load(
    db: Any, source: str, counts: dict[str, int], **fields: Any
) -> None:
    """Record accepted entries using counts already available to the parser.

    Parameters:
        db: Slips database facade.
        source: Existing TI source key.
        counts: Accepted entries per indicator or supporting-data type.
        fields: Additional metadata for the completed load.
    """
    now = time.time()
    record_feed_status(
        db,
        source,
        counts=counts,
        loaded_at=now,
        checked_at=now,
        status="ready",
        error="",
        **fields,
    )
