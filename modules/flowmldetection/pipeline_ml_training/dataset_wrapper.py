# Author: Jan Svoboda
# functionality: ZeekDataset loader specialized for conn.log.labeled files with caching. Handles casting, label mapping, batching, and efficient indexing for large files.
# behavior:
#   - Reads conn.log.labeled (or falls back to conn.log).
#   - Casts columns according to Zeek #types header.
#   - Skips flows with BACKGROUND label.
#   - Defaults unlabeled flows to BENIGN.
#   - Stores index in cache/ directory for large files (>50k valid flows) and reloads automatically.

from .commons import BENIGN, MALICIOUS, BACKGROUND
import random
from pathlib import Path
from typing import Dict, List, Optional, Union
import pandas as pd
import hashlib
import json


class ZeekDataset:
    def __init__(
        self,
        root,
        batch_size,
        seed=None,
        persist_cache_threshold=30000,
        cache_dir=None,
        labeled_filenames=None,
        file_encoding="utf-8",
        file_errors="ignore",
        shuffle_per_epoch=False,
    ):
        self.root = Path(root)
        self.seed = seed
        self.rng = random.Random(seed)
        self.persist_cache_threshold = persist_cache_threshold
        self.file_encoding = file_encoding
        self.file_errors = file_errors
        self.shuffle_per_epoch = shuffle_per_epoch

        # cache dir
        if cache_dir is None:
            self.cache_dir = Path(__file__).parent / "cache"
        else:
            self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

        if labeled_filenames is None:
            self.labeled_filenames = [
                "conn.log.labeled",
                "labeled-conn.log",
                "conn.log",
            ]
        else:
            self.labeled_filenames = list(labeled_filenames)

        if not self.root.exists():
            raise FileNotFoundError(f"Root path {self.root} does not exist")

        self.find_labeled_logfile()

        self._index_file()

        self.indices: List[int] = []
        self.batch_size: int = batch_size
        self._batch_pos: int = 0
        self.epoch: int = 0
        self.reset_epoch(batch_size=batch_size)

    def find_labeled_logfile(self) -> Path:
        for fname in self.labeled_filenames:
            candidate = self.root / fname
            if candidate.exists():
                self.current_file = candidate
                return candidate
        raise FileNotFoundError(
            f"No conn.log.labeled, labeled-conn.log or conn.log in {self.root}"
        )

    def __len__(self):
        return self.total_lines

    def batches(self):
        return (self.total_lines + self.batch_size - 1) // self.batch_size

    def _cache_path(self):
        base = self.cache_dir
        base.mkdir(exist_ok=True)
        file_hash = hashlib.sha1(str(self.current_file).encode()).hexdigest()[
            :16
        ]
        return base / f"{file_hash}.json"

    def clear_cache(self):
        """Remove the cache file for this dataset only."""
        cache_file = self._cache_path()
        if cache_file.exists():
            cache_file.unlink()

    def _index_file(self):
        cache_file = self._cache_path()
        file_stat = self.current_file.stat()

        # try loading from cache
        if cache_file.exists():
            with open(
                cache_file,
                "r",
                encoding=self.file_encoding,
                errors=self.file_errors,
            ) as f:
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
            self.current_file,
            "r",
            encoding=self.file_encoding,
            errors=self.file_errors,
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
            # Shuffle valid_indices and labels together with fixed seed (if provided)
            if self.seed is not None:
                combined = list(zip(valid_indices, labels))
                rng = random.Random(self.seed)
                rng.shuffle(combined)
                valid_indices, labels = zip(*combined)
                valid_indices = list(valid_indices)
                labels = list(labels)

        self.headers = headers
        self.types = types
        self.valid_indices = valid_indices
        self.labels = labels
        self.total_lines = len(valid_indices)

        # persist if large enough
        if len(valid_indices) > self.persist_cache_threshold:
            with open(
                cache_file,
                "w",
                encoding=self.file_encoding,
                errors=self.file_errors,
            ) as f:
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

    def _iter_lines(self):
        headers, types = self.headers, self.types
        valid_set = set(self.valid_indices)
        labels = {
            index: label
            for index, label in zip(self.valid_indices, self.labels)
        }

        with open(
            self.current_file,
            "r",
            encoding=self.file_encoding,
            errors=self.file_errors,
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

                if idx == 1:
                    print(record)
                    print(types)

    def _cast(self, value: str, typ: Optional[str]):
        if value in ("-", ""):
            return None
        if typ in ("int", "count", "port"):
            return int(value)
        if typ in ("double", "float"):
            return float(value)
        if typ == "bool":
            return value.lower() == "t"
        if typ == "time":
            return float(value)
        if typ == "interval":
            return float(value)
        if typ == "string" or typ == "str":
            try:
                return float(value)
            except ValueError:
                return value
        if typ == "":
            return float(value)
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

    def reset_epoch(self, batch_size: int):
        self.indices = list(range(self.total_lines))
        if self.shuffle_per_epoch:
            self.rng.shuffle(self.indices)
        self.batch_size = batch_size
        self._batch_pos = 0
        self.epoch = 0

    def next_batch(self):
        # ensure index built
        if not hasattr(self, "valid_indices") or self.total_lines == 0:
            raise RuntimeError("Dataset empty or not indexed")

        # If we finished an epoch, and start a new one
        if self._batch_pos >= len(self.indices):
            self.epoch += 1
            self._batch_pos = 0

        # get the *relative* valid-flow indices for this batch (values 0..total_lines-1)
        rel_inds = self.indices[
            self._batch_pos : self._batch_pos + self.batch_size
        ]
        self._batch_pos += self.batch_size

        # if nothing requested, return empty (shouldn't happen normally)
        if not rel_inds:
            return []

        # Map relative indices -> actual file data-line positions
        # (self.valid_indices stores file positions for each relative index)
        target_positions = {self.valid_indices[r] for r in rel_inds}
        # map position -> relative index label (for label lookup)
        pos_to_label = {
            self.valid_indices[r]: self.labels[r] for r in rel_inds
        }

        records = []
        found = 0
        with open(
            self.current_file,
            "r",
            encoding=self.file_encoding,
            errors=self.file_errors,
        ) as fh:
            file_idx = 0  # counts data lines (non-# lines)
            for line in fh:
                if line.startswith("#"):
                    continue
                if file_idx in target_positions:
                    parts = line.strip().split("\t")
                    record = {
                        h: self._cast(
                            parts[i],
                            self.types[i] if i < len(self.types) else None,
                        )
                        for i, h in enumerate(self.headers)
                    }
                    record["label"] = pos_to_label.get(file_idx, str(BENIGN))
                    records.append(record)
                    found += 1
                    if found == len(target_positions):
                        break
                file_idx += 1

        # defensive: if we didn't find all expected records, warn (shouldn't happen)
        if found != len(target_positions):
            # optional: raise or log; for now we print a short warning
            print(
                f"Warning: expected {len(target_positions)} records in batch but found {found}"
            )

        return records

    def next_n(self, n: int):
        """
        Return exactly up to `n` records from this dataset (using the same
        indexing logic as next_batch). Advances the internal pointer by n.
        If the epoch wraps, increments epoch and continues from start.
        Returns a list of records (possibly empty).
        """
        if not hasattr(self, "valid_indices") or self.total_lines == 0:
            raise RuntimeError("Dataset empty or not indexed")

        if n <= 0:
            return []

        # If we finished an epoch and start a new one
        if self._batch_pos >= len(self.indices):
            self.epoch += 1
            self._batch_pos = 0

        # compute relative indices for requested n samples
        rel_inds = self.indices[self._batch_pos : self._batch_pos + n]
        self._batch_pos += len(rel_inds)

        if not rel_inds:
            return []

        # Map relative indices -> actual file data-line positions
        target_positions = {self.valid_indices[r] for r in rel_inds}
        pos_to_label = {
            self.valid_indices[r]: self.labels[r] for r in rel_inds
        }

        records = []
        found = 0
        with open(
            self.current_file,
            "r",
            encoding=self.file_encoding,
            errors=self.file_errors,
        ) as fh:
            file_idx = 0  # counts data lines (non-# lines)
            for line in fh:
                if line.startswith("#"):
                    continue
                if file_idx in target_positions:
                    parts = line.strip().split("\t")
                    record = {
                        h: self._cast(
                            parts[i],
                            self.types[i] if i < len(self.types) else None,
                        )
                        for i, h in enumerate(self.headers)
                    }
                    record["label"] = pos_to_label.get(file_idx, str(BENIGN))
                    records.append(record)
                    found += 1
                    if found == len(target_positions):
                        break
                file_idx += 1

        if found != len(target_positions):
            # warn but continue (shouldn't normally happen)
            print(
                f"Warning: expected {len(target_positions)} records but found {found}"
            )

        return records


# -------------------
# Helper functions
# -------------------


def find_and_load_datasets(
    root_dir: Union[str, Path],
    batch_size: int = 1000,
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
        try:
            ds = ZeekDataset(data_path, batch_size=batch_size, seed=seed)
        except FileNotFoundError:
            # Skip datasets without conn.log/conn.log.labeled instead of failing the whole run
            continue
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
