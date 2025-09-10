"""
ZeekDataset loader specialized for conn.log.labeled files with caching.

Behavior:
 - Only reads conn.log.labeled (or falls back to conn.log).
 - Casts columns according to Zeek #types header.
 - Skips flows with BACKGROUND label.
 - Defaults unlabeled flows to BENIGN.
 - Supports batching with shuffle/reset at epoch boundaries.
 - For large files (>50k valid flows), stores index in cache/ directory and reloads it automatically.
"""

from commons import BENIGN, MALICIOUS, BACKGROUND
import random
from pathlib import Path
from typing import Dict, List, Optional, Union
import pandas as pd
import hashlib
import json


class ZeekDataset:
    def __init__(self, root: Union[str, Path], seed: Optional[int] = None):
        self.root = Path(root)
        self.seed = seed
        self.rng = random.Random(seed)

        if not self.root.exists():
            raise FileNotFoundError(f"Root path {self.root} does not exist")

        labeled = self.root / "conn.log.labeled"
        plain = self.root / "conn.log"
        if labeled.exists():
            self.current_file = labeled
        elif plain.exists():
            self.current_file = plain
        else:
            raise FileNotFoundError(
                f"No conn.log.labeled or conn.log in {self.root}"
            )

        self._index_file()

        self.indices: List[int] = []
        self.batch_size: int = 0
        self._batch_pos: int = 0
        self.epoch: int = 0

    def _cache_path(self):
        base = Path(__file__).parent / "cache"
        base.mkdir(exist_ok=True)
        file_hash = hashlib.sha1(str(self.current_file).encode()).hexdigest()[
            :16
        ]
        return base / f"{file_hash}.json"

    def _index_file(self):
        cache_file = self._cache_path()
        file_stat = self.current_file.stat()

        # try loading from cache
        if cache_file.exists():
            with open(cache_file, "r") as f:
                data = json.load(f)
            if (
                data["__file_size"] == file_stat.st_size
                and data["__mtime"] == file_stat.st_mtime
            ):
                self.headers = data["headers"]
                self.types = data["types"]
                self.valid_indices = data["valid_indices"]
                self.labels = data["labels"]
                self.total_lines = len(self.valid_indices)
                return

        # else build fresh index
        headers, types = [], []
        valid_indices, labels = [], []

        with open(
            self.current_file, "r", encoding="utf-8", errors="ignore"
        ) as fh:
            idx = 0
            for line in fh:
                if line.startswith("#fields"):
                    headers = line.strip().split()[1:]
                elif line.startswith("#types"):
                    types = line.strip().split()[1:]
                elif line.startswith("#"):
                    continue
                else:
                    parts = line.strip().split("\t")
                    label_val = None
                    if "label" in headers:
                        try:
                            label_val = parts[headers.index("label")]
                        except Exception:
                            label_val = None
                    if not label_val:
                        label_val = str(BENIGN)

                    lab_up = label_val.upper()
                    if (
                        lab_up == str(BACKGROUND).upper()
                        or "BACKGROUND" in lab_up
                    ):
                        idx += 1
                        continue
                    if (
                        lab_up == str(MALICIOUS).upper()
                        or "MAL" in lab_up
                        or lab_up == "1"
                    ):
                        mapped = MALICIOUS
                    else:
                        mapped = BENIGN

                    valid_indices.append(idx)
                    labels.append(str(mapped))
                    idx += 1

        self.headers = headers
        self.types = types
        self.valid_indices = valid_indices
        self.labels = labels
        self.total_lines = len(valid_indices)

        # persist if large enough
        if len(valid_indices) > 50000:
            with open(cache_file, "w") as f:
                json.dump(
                    {
                        "__file_size": file_stat.st_size,
                        "__mtime": file_stat.st_mtime,
                        "headers": headers,
                        "types": types,
                        "valid_indices": valid_indices,
                        "labels": labels,
                    },
                    f,
                )

    def __len__(self):
        return self.total_lines

    def _iter_lines(self):
        headers, types = self.headers, self.types
        valid_set = set(self.valid_indices)
        labels = {
            idx: label for idx, label in zip(self.valid_indices, self.labels)
        }

        with open(
            self.current_file, "r", encoding="utf-8", errors="ignore"
        ) as fh:
            idx = 0
            for line in fh:
                if line.startswith("#"):
                    continue
                if idx not in valid_set:
                    idx += 1
                    continue
                parts = line.strip().split("\t")
                record = {
                    h: self._cast(
                        parts[i], types[i] if i < len(types) else None
                    )
                    for i, h in enumerate(headers)
                }
                record["label"] = labels.get(idx, str(BENIGN))
                yield record
                idx += 1

    def _cast(self, value: str, typ: Optional[str]):
        if value in ("-", ""):
            return None
        if typ in ("int", "count", "port"):
            return int(value)
        if typ in ("double", "float"):
            return float(value)
        if typ == "bool":
            return value.lower() == "t"
        return value

    def get_line(self, idx: int):
        for i, rec in enumerate(self._iter_lines()):
            if i == idx:
                return rec
        raise IndexError("Line index out of range")

    def get_lines(self, start: int, stop: int):
        return [
            rec
            for i, rec in enumerate(self._iter_lines())
            if start <= i < stop
        ]

    def reset_epoch(
        self, batch_size: int, train_val_split: Optional[float] = None
    ):
        self.indices = list(range(self.total_lines))
        self.rng.shuffle(self.indices)
        self.batch_size = batch_size
        self._batch_pos = 0
        self.epoch = 0

        if train_val_split is not None:
            split_idx = int(self.total_lines * train_val_split)
            train_idx = self.indices[:split_idx]
            val_idx = self.indices[split_idx:]
            return train_idx, val_idx

    def next_batch(self):
        if self._batch_pos >= len(self.indices):
            self.epoch += 1
            self.rng.shuffle(self.indices)
            self._batch_pos = 0

        batch_idx = self.indices[
            self._batch_pos : self._batch_pos + self.batch_size
        ]
        self._batch_pos += self.batch_size

        records = []
        for i, rec in enumerate(self._iter_lines()):
            if i in batch_idx:
                records.append(rec)
                if len(records) == len(batch_idx):
                    break
        return records


# -------------------
# Helper functions
# -------------------


def find_and_load_datasets(
    root_dir: Union[str, Path],
    prefix_regex: str = r"^\d{3}",
    data_subdir: str = "data",
    seed: Optional[int] = None,
) -> Dict[str, ZeekDataset]:
    import re

    root = Path(root_dir)
    if not root.exists():
        raise FileNotFoundError(f"root_dir {root} does not exist")

    pattern = re.compile(prefix_regex)
    loaders: Dict[str, ZeekDataset] = {}

    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        if not pattern.match(entry.name):
            continue
        data_path = entry / data_subdir
        if not data_path.is_dir():
            continue
        ds = ZeekDataset(data_path, seed=seed)
        loaders[entry.name] = ds

    return loaders


def sample_n_from_each_dataset(
    loaders: Dict[str, ZeekDataset], n: int = 5
) -> Dict[str, dict]:
    results: Dict[str, dict] = {}
    for name, ds in loaders.items():
        ds.reset_epoch(batch_size=n)
        batch = ds.next_batch()
        results[name] = {
            "file": str(ds.current_file),
            "samples": batch,
            "df": pd.DataFrame(batch),
        }
    return results
