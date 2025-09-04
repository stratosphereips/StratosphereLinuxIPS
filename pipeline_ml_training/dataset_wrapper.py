import random
from pathlib import Path
from typing import (
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
    Union,
)

import re
import pandas as pd


class ZeekDataset:
    """
    Memory-efficient loader and sampler for Zeek logs with lazy parsing / casting.

    Important new features:
      - reads #types header (if present) and keeps it in metadata
      - set_field_types(filename, mapping) to supply a schema manually
      - infer_field_types(filename, sample=1000) to guess types from data
      - get_line/get_lines/reservoir_sample/shuffled_batches/get_train_val_batches
        accept cast:bool (default False). When cast=True values are converted to Python types.
    """

    # ---------------------
    # init + discovery
    # ---------------------
    def __init__(
        self,
        root: Union[str, Path],
        allowed_exts: Optional[List[str]] = None,
        index_lazy: bool = True,
    ):
        self.root = Path(root)
        if allowed_exts is None:
            allowed_exts = [".log"]
        self.allowed_exts = set(allowed_exts)
        self.index_lazy = index_lazy

        self.files: Dict[str, Path] = {}
        # meta: per-file dict: path, fields, types, separator, header_lines, offsets
        self._meta: Dict[str, Dict] = {}

        self._discover_files()
        if not index_lazy:
            for fname in list(self.files.keys()):
                self.index_file(fname)

    def _discover_files(self):
        if not self.root.exists():
            raise FileNotFoundError(f"{self.root} not found")
        for p in self.root.rglob("*"):
            if p.is_file() and p.suffix in self.allowed_exts:
                self.files[p.name] = p

    def list_files(self) -> List[str]:
        return sorted(self.files.keys())

    # ---------------------
    # header reading (now includes #types)
    # ---------------------
    def _read_header(self, path: Path) -> Dict:
        meta = {
            "fields": None,
            "types": None,
            "separator": None,
            "header_lines": [],
        }
        with path.open("rb") as fh:
            while True:
                pos = fh.tell()
                raw = fh.readline()
                if not raw:
                    break
                try:
                    line = raw.decode("utf-8").rstrip("\n")
                except UnicodeDecodeError:
                    line = raw.decode(errors="replace").rstrip("\n")
                if not line.startswith("#"):
                    fh.seek(pos)
                    break
                meta["header_lines"].append(line)
                if line.startswith("#separator"):
                    parts = line.split(" ", 1)
                    if len(parts) > 1:
                        sep_val = parts[1]
                        # handle escape sequences like \x09 or \t
                        sep_val = sep_val.encode("utf-8").decode(
                            "unicode_escape"
                        )
                        meta["separator"] = sep_val
                elif line.startswith("#fields"):
                    fields = line.split()[1:]
                    meta["fields"] = fields
                elif line.startswith("#types"):
                    types = line.split()[1:]
                    meta["types"] = types
        return meta

    # ---------------------
    # indexing (unchanged aside from storing types)
    # ---------------------
    def index_file(self, filename: str, force: bool = False) -> None:
        if filename not in self.files:
            raise KeyError(f"{filename} not found in dataset")
        if (
            filename in self._meta
            and self._meta[filename].get("offsets")
            and not force
        ):
            return

        path = self.files[filename]
        meta = self._read_header(path)
        offsets: List[int] = []
        with path.open("rb") as fh:
            fh.seek(0)
            # move to first data line
            while True:
                pos = fh.tell()
                raw = fh.readline()
                if not raw:
                    break
                try:
                    line = raw.decode("utf-8")
                except UnicodeDecodeError:
                    line = raw.decode(errors="replace")
                if not line.startswith("#"):
                    offsets.append(pos)
                    break
            for raw in fh:
                pos = fh.tell() - len(raw)
                try:
                    line = raw.decode("utf-8")
                except UnicodeDecodeError:
                    line = raw.decode(errors="replace")
                if not line.startswith("#"):
                    offsets.append(pos)

        self._meta[filename] = {
            "path": path,
            "fields": meta.get("fields"),
            "types": meta.get("types"),
            "separator": meta.get("separator", "\t"),
            "header_lines": meta.get("header_lines", []),
            "offsets": offsets,
            # allow user-provided overrides for types
            "user_types": None,
        }

    def length(self, filename: str) -> int:
        if filename not in self.files:
            raise KeyError(f"{filename} not found in dataset")
        if filename not in self._meta or "offsets" not in self._meta[filename]:
            self.index_file(filename)
        return len(self._meta[filename]["offsets"])

    # ---------------------
    # type management & lazy casting
    # ---------------------
    def set_field_types(self, filename: str, mapping: Dict[str, str]) -> None:
        """
        Set/override types for fields, mapping field_name -> type_name (string).
        Example: {"ts": "time", "id.orig_h": "addr", "duration": "double"}
        """
        if filename not in self._meta:
            self.index_file(filename)
        self._meta[filename]["user_types"] = mapping

    def get_field_types(self, filename: str) -> Optional[Dict[str, str]]:
        """
        Return the effective types mapping (field -> type_name) if available,
        combining #types header with user overrides.
        """
        if filename not in self._meta:
            self.index_file(filename)
        meta = self._meta[filename]
        fields = meta.get("fields")
        types = meta.get("types")
        user = meta.get("user_types")
        if not fields:
            return None
        if types and len(types) == len(fields):
            base = dict(zip(fields, types))
        else:
            base = {f: "string" for f in fields}
        if user:
            base.update(user)
        return base

    @staticmethod
    def _cast_value(val: str, type_name: Optional[str]):
        """
        Cast a single string value into Python object based on type_name.
        - treat Zeek missing value '-' as None
        - common Zeek types: time, count, int, double, bool, port, addr, string, enum
        """
        if val is None:
            return None
        v = val.strip()
        if v == "-" or v == "":
            return None
        if not type_name:
            return v
        t = type_name.lower()
        # numeric types
        try:
            if t in ("time", "double", "float", "real"):
                # Zeek uses floating seconds for time
                return float(v)
            if t in ("int", "count", "signed", "unsigned", "long", "uint"):
                # some Zeek counts are integers
                return int(v)
            if t in ("bool", "boolean"):
                if v in ("T", "1", "true", "True", "t"):
                    return True
                if v in ("F", "0", "false", "False", "f"):
                    return False
                # fallback: attempt int then bool
                try:
                    return bool(int(v))
                except Exception:
                    return v
            # address and port: keep as string, but cast port to int if numeric
            if t in ("port",):
                try:
                    return int(v)
                except ValueError:
                    return v
            if t in ("addr", "ip", "net"):
                return v
            # enumeration or protocol names -> keep as string
            if t in (
                "enum",
                "string",
                "subnet",
                "service",
                "digest",
                "filename",
                "signature",
            ):
                return v
            # fallback: try int then float then string
            try:
                return int(v)
            except Exception:
                pass
            try:
                return float(v)
            except Exception:
                return v
        except Exception:
            # any cast failure returns original string
            return v

    def _cast_record(
        self, rec: Dict[str, str], types_map: Dict[str, str]
    ) -> Dict[str, object]:
        """
        Cast a dict(field->string) to dict(field->typed).
        """
        out = {}
        for f, val in rec.items():
            typ = types_map.get(f) if types_map else None
            out[f] = self._cast_value(val, typ)
        return out

    def infer_field_types(
        self, filename: str, sample: int = 1000, seed: Optional[int] = None
    ) -> Dict[str, str]:
        """
        Infer types heuristically by sampling up to `sample` records.
        This is a *best-effort* heuristic: it won't be perfect but helps for lazy casting.
        Returns a mapping field->inferred_type_name.
        """
        if filename not in self._meta:
            self.index_file(filename)
        meta = self._meta[filename]
        fields = meta.get("fields")
        if not fields:
            raise RuntimeError(
                "Cannot infer types: file has no #fields header"
            )

        n = self.length(filename)
        if n == 0:
            return {f: "string" for f in fields}

        if seed is not None:
            rnd = random.Random(seed)
        else:
            rnd = random

        # pick up to `sample` random indices
        sample_count = min(sample, n)
        indices = rnd.sample(range(n), sample_count)

        # read sample lines (no casting yet)
        samples = self.get_lines(
            filename, indices, parse=True
        )  # returns dicts of strings

        # simple counters per-field for detecting numeric vs string vs bool/time
        counters: Dict[str, Dict[str, int]] = {f: {} for f in fields}
        for s in samples:
            for f in fields:
                val = s.get(f, "").strip()
                if val == "" or val == "-":
                    counters[f]["none"] = counters[f].get("none", 0) + 1
                    continue
                # heuristics
                if val in ("T", "F", "true", "false", "1", "0"):
                    counters[f]["bool_like"] = (
                        counters[f].get("bool_like", 0) + 1
                    )
                # time-like: contains '.' and digits and maybe leading epoch style
                if any(ch.isdigit() for ch in val) and (
                    "." in val and val.replace(".", "").isdigit()
                ):
                    counters[f]["float_like"] = (
                        counters[f].get("float_like", 0) + 1
                    )
                # integer-like
                if val.lstrip("+-").isdigit():
                    counters[f]["int_like"] = (
                        counters[f].get("int_like", 0) + 1
                    )
                # ip-like (contains dot or colon and digits/hex)
                if (
                    val.count(".") == 3
                    and all(p.isdigit() or p == "" for p in val.split("."))
                ) or (":" in val):
                    counters[f]["addr_like"] = (
                        counters[f].get("addr_like", 0) + 1
                    )
                # fallback assume string
                counters[f]["string_like"] = (
                    counters[f].get("string_like", 0) + 1
                )

        inferred: Dict[str, str] = {}
        for f, cnts in counters.items():
            # choose rules with a priority order
            if (
                cnts.get("float_like", 0) >= cnts.get("int_like", 0)
                and cnts.get("float_like", 0) > 0
            ):
                inferred[f] = "time"  # prefer time/float
            elif cnts.get("int_like", 0) > 0 and cnts.get(
                "int_like", 0
            ) >= cnts.get("string_like", 0):
                inferred[f] = "count"
            elif cnts.get("bool_like", 0) > 0 and cnts.get(
                "bool_like", 0
            ) >= cnts.get("string_like", 0):
                inferred[f] = "bool"
            elif cnts.get("addr_like", 0) > 0:
                inferred[f] = "addr"
            else:
                inferred[f] = "string"
        # set as user_types override so it's used for casting
        self.set_field_types(filename, inferred)
        return inferred

    # ---------------------
    # parsing raw line -> dict of strings (unchanged)
    # ---------------------
    def _parse_line_to_dict(
        self, raw_line: str, fields: Optional[List[str]], separator: str
    ) -> Dict[str, str]:
        raw_line = raw_line.rstrip("\n")
        if fields:
            parts = raw_line.split(separator)
            if len(parts) < len(fields):
                parts += [""] * (len(fields) - len(parts))
            return dict(zip(fields, parts))
        else:
            return {"raw": raw_line}

    # ---------------------
    # random access: get_line / get_lines (now with cast option)
    # ---------------------
    def get_line(
        self, filename: str, idx: int, parse: bool = True, cast: bool = False
    ) -> Union[str, Dict]:
        lines = self.get_lines(filename, [idx], parse=parse, cast=cast)
        return lines[0] if lines else None

    def get_lines(
        self,
        filename: str,
        indices: Iterable[int],
        parse: bool = True,
        cast: bool = False,
    ) -> List[Union[str, Dict]]:
        if filename not in self.files:
            raise KeyError(f"{filename} not found")
        if filename not in self._meta or "offsets" not in self._meta[filename]:
            self.index_file(filename)

        offsets: List[int] = self._meta[filename]["offsets"]
        n = len(offsets)
        idx_list = list(indices)
        if not idx_list:
            return []
        for i in idx_list:
            if i < 0 or i >= n:
                raise IndexError(
                    f"index {i} out of bounds for file {filename} with length {n}"
                )

        # order_map = {pos: i for i, pos in enumerate(idx_list)}
        results: List[Optional[Union[str, Dict]]] = [None] * len(idx_list)

        sorted_indices = sorted(enumerate(idx_list), key=lambda x: x[1])
        runs: List[Tuple[int, int, List[int]]] = []
        cur_run_start = None
        cur_run_len = 0
        cur_run_origpos = []
        prev_idx = None
        for origpos, idx in sorted_indices:
            if cur_run_start is None:
                cur_run_start = idx
                cur_run_len = 1
                cur_run_origpos = [(origpos, idx)]
            elif prev_idx is not None and idx == prev_idx + 1:
                cur_run_len += 1
                cur_run_origpos.append((origpos, idx))
            else:
                runs.append((cur_run_start, cur_run_len, cur_run_origpos))
                cur_run_start = idx
                cur_run_len = 1
                cur_run_origpos = [(origpos, idx)]
            prev_idx = idx
        if cur_run_start is not None:
            runs.append((cur_run_start, cur_run_len, cur_run_origpos))

        path = self._meta[filename]["path"]
        sep = self._meta[filename].get("separator", "\t")
        fields = self._meta[filename].get("fields")
        types_map = self.get_field_types(filename) if cast else None

        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for start_idx, run_len, origpos_list in runs:
                offset = offsets[start_idx]
                fh.seek(offset)
                for j in range(run_len):
                    raw_line = fh.readline()
                    if raw_line is None or raw_line == "":
                        break
                    idx_at_j = start_idx + j
                    matching = [
                        orig for orig, idx in origpos_list if idx == idx_at_j
                    ]
                    if parse:
                        parsed = self._parse_line_to_dict(
                            raw_line, fields, sep
                        )
                        if cast and types_map:
                            parsed = self._cast_record(parsed, types_map)
                        item = parsed
                    else:
                        item = raw_line.rstrip("\n")
                    for orig in matching:
                        results[orig] = item

        # Fill any None by direct fetch (rare)
        for i, val in enumerate(results):
            if val is None:
                results[i] = self.get_line(
                    filename, idx_list[i], parse=parse, cast=cast
                )
        return results

    # ---------------------
    # reservoir sampling (accepts cast flag)
    # ---------------------
    def reservoir_sample(
        self,
        filename: str,
        k: int,
        parse: bool = True,
        cast: bool = False,
        feature_fn: Optional[Callable[[Union[str, Dict]], object]] = None,
    ) -> List:
        path = self.files.get(filename)
        if path is None:
            raise KeyError(f"{filename} not found")

        meta = self._meta.get(filename)
        sep = meta.get("separator", "\t") if meta else "\t"
        fields = meta.get("fields")
        types_map = self.get_field_types(filename) if cast else None

        reservoir: List = []
        n = 0
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            while True:
                # pos = fh.tell()
                line = fh.readline()
                if not line:
                    break
                if not line.startswith("#"):
                    item = (
                        self._parse_line_to_dict(line, fields, sep)
                        if parse
                        else line.rstrip("\n")
                    )
                    if cast and types_map and parse:
                        item = self._cast_record(item, types_map)
                    if feature_fn:
                        item = feature_fn(item)
                    reservoir.append(item)
                    n = 1
                    break
            for line in fh:
                if line.startswith("#"):
                    continue
                n += 1
                item = (
                    self._parse_line_to_dict(line, fields, sep)
                    if parse
                    else line.rstrip("\n")
                )
                if cast and types_map and parse:
                    item = self._cast_record(item, types_map)
                if feature_fn:
                    item = feature_fn(item)
                if len(reservoir) < k:
                    reservoir.append(item)
                else:
                    s = random.randrange(n)
                    if s < k:
                        reservoir[s] = item
        return reservoir

    # ---------------------
    # shuffled batches (supports casting)
    # ---------------------
    def shuffled_batches(
        self,
        filename: str,
        batch_size: int,
        drop_last: bool = False,
        parse: bool = True,
        cast: bool = False,
        feature_fn: Optional[Callable[[Union[str, Dict]], object]] = None,
        seed: Optional[int] = None,
    ) -> Iterator[List]:
        if seed is not None:
            rnd = random.Random(seed)
        else:
            rnd = random

        n = self.length(filename)
        indices = list(range(n))
        rnd.shuffle(indices)

        for start in range(0, n, batch_size):
            end = start + batch_size
            if end > n and drop_last:
                break
            batch_indices = indices[start:end]
            records = self.get_lines(
                filename, batch_indices, parse=parse, cast=cast
            )
            if feature_fn:
                records = [feature_fn(r) for r in records]
            yield records

    # ---------------------
    # train/val split (supports casting)
    # ---------------------
    def get_train_val_batches(
        self,
        filename: str,
        batch_size: int,
        val_frac: float = 0.1,
        shuffle: bool = True,
        parse: bool = True,
        cast: bool = False,
        feature_fn: Optional[Callable[[Union[str, Dict]], object]] = None,
        seed: Optional[int] = None,
    ) -> Tuple[Iterator[List], Iterator[List]]:
        if val_frac < 0 or val_frac >= 1:
            raise ValueError("val_frac must be in [0,1)")
        if seed is not None:
            rnd = random.Random(seed)
        else:
            rnd = random

        n = self.length(filename)
        indices = list(range(n))
        if shuffle:
            rnd.shuffle(indices)

        val_count = int(round(val_frac * n))
        val_indices = indices[:val_count]
        train_indices = indices[val_count:]

        def gen_from_indices(idxs: List[int]) -> Iterator[List]:
            for start in range(0, len(idxs), batch_size):
                batch_inds = idxs[start : start + batch_size]
                records = self.get_lines(
                    filename, batch_inds, parse=parse, cast=cast
                )
                if feature_fn:
                    records = [feature_fn(r) for r in records]
                yield records

        return gen_from_indices(train_indices), gen_from_indices(val_indices)

    # ---------------------
    # multi-file shuffled batches across files (supports casting)
    # ---------------------
    def shuffled_batches_across_files(
        self,
        filenames: List[str],
        batch_size: int,
        drop_last: bool = False,
        parse: bool = True,
        cast: bool = False,
        feature_fn: Optional[Callable[[Union[str, Dict]], object]] = None,
        seed: Optional[int] = None,
    ) -> Iterator[List]:
        if seed is not None:
            rnd = random.Random(seed)
        else:
            rnd = random

        global_positions = []
        for fname in filenames:
            if fname not in self.files:
                raise KeyError(f"{fname} not found")
            L = self.length(fname)
            global_positions.extend([(fname, i) for i in range(L)])

        rnd.shuffle(global_positions)

        for start in range(0, len(global_positions), batch_size):
            block = global_positions[start : start + batch_size]
            by_file: Dict[str, List[Tuple[int, int]]] = {}
            for pos, (fname, idx) in enumerate(block):
                by_file.setdefault(fname, []).append((pos, idx))
            results = [None] * len(block)
            for fname, pos_idx_list in by_file.items():
                orig_positions, idxs = zip(*pos_idx_list)
                records = self.get_lines(
                    fname, list(idxs), parse=parse, cast=cast
                )
                if feature_fn:
                    records = [feature_fn(r) for r in records]
                for out_pos, rec in zip(orig_positions, records):
                    results[out_pos] = rec
            yield results


def find_and_load_datasets(
    root_dir: Union[str, Path],
    prefix_regex: str = r"^\d{3}",
    data_subdir: str = "data",
    allowed_exts: Optional[List[str]] = None,
    index_lazy: bool = True,
) -> Dict[str, ZeekDataset]:
    """
    Search `root_dir` for subfolders whose name matches `prefix_regex` (default: 3 digits at start)
    and which contain a subfolder named `data_subdir`.

    For each matching folder, create a ZeekDataset pointing at that folder's data_subdir.

    Returns a dict mapping the subfolder name -> ZeekDataset instance (loader).

    Example:
        loaders = find_and_load_datasets("/mnt/data/experiments", prefix_regex=r"^\d{3}")
        # then loaders is like {"001-experiment": <ZeekDataset ...>, "123-foo": <...>}
    """
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
        # instantiate loader pointing to the data/ subfolder
        ds = ZeekDataset(
            data_path, allowed_exts=allowed_exts, index_lazy=index_lazy
        )
        loaders[entry.name] = ds

    return loaders


def sample_10_from_each_dataset(
    loaders: Dict[str, ZeekDataset],
    preferred_files: Optional[List[str]] = None,
    k: int = 10,
    infer_sample: int = 500,
    seed: Optional[int] = None,
) -> Dict[str, Dict]:
    """
    For each loader in `loaders`, choose a target Zeek log file (preferentially using
    `preferred_files` order if present) and produce k random samples using reservoir sampling.

    - Parses and casts the sampled records (cast=True) after attempting to infer a type schema
      via infer_field_types (heuristic) when necessary.
    - Returns a dict keyed by dataset name. Each value is another dict with keys:
        - 'loader': the ZeekDataset instance
        - 'file': chosen filename used for sampling
        - 'samples': list of sampled records (list of dicts, typed)
        - 'df': a pandas.DataFrame of sampled records (may have many None cells)

    Example:
        results = sample_10_from_each_dataset(loaders)
        display(results['001-experiment']['df'])
    """
    if preferred_files is None:
        preferred_files = ["conn.log", "dns.log", "http.log", "files.log"]

    """ rng = None
    if seed is not None:
        import random

        rng = random.Random(seed) """

    results: Dict[str, Dict] = {}

    for name, ds in loaders.items():
        files = ds.list_files()
        if not files:
            # no log files in this dataset
            results[name] = {
                "loader": ds,
                "file": None,
                "samples": [],
                "df": pd.DataFrame(),
            }
            continue

        # choose a file using preference order
        chosen = None
        for pref in preferred_files:
            if pref in files:
                chosen = pref
                break
        if chosen is None:
            chosen = files[0]

        # try to infer types heuristically if no types are present
        try:
            types_map = ds.get_field_types(chosen)
            if types_map is None:
                # infer types (this will call index_file if needed)
                ds.infer_field_types(chosen, sample=infer_sample, seed=seed)
        except Exception:
            # inference failed; fall back to raw strings but proceed
            pass

        # reservoir sample k records (single pass) with parsing and casting
        try:
            samples = ds.reservoir_sample(chosen, k, parse=True, cast=True)
        except Exception:
            # if sampling fails (e.g., file empty), return empty
            samples = []

        # create DataFrame for nicer display in notebook
        df = pd.DataFrame(samples)

        results[name] = {
            "loader": ds,
            "file": chosen,
            "samples": samples,
            "df": df,
        }

    return results
