# pipeline_ml_training/mixers.py
"""
Compact mixer subsystem (no replacement, deterministic train/val split).

Mixers:
 - SequenceMixer
 - RandomBatchesMixer
 - BalancedByLabelMixer

Factory:
 - build_mixer(spec, loaders, rng)

API:
 - mixer.reset_epoch(batch_size, epoch_idx=0)
 - train_batch, val_batch = mixer.next_batch()   # val_batch may be None
 - mixer.get_mix_plan()
"""

import numpy as np

try:
    import pandas as pd
except Exception:
    pd = None


# -------------------------
# helpers
# -------------------------


def is_dataframe(x):
    return pd is not None and isinstance(x, pd.DataFrame)


def batch_len(batch):
    if batch is None:
        return 0
    try:
        return len(batch)
    except Exception:
        return 1


def concat_batches(parts):
    if not parts:
        return None
    first = None
    for p in parts:
        if p is not None:
            first = p
            break
    if first is None:
        return None
    if is_dataframe(first):
        return pd.concat(
            [p for p in parts if p is not None], ignore_index=True
        )
    out = []
    for p in parts:
        if p is None:
            continue
        try:
            out.extend(list(p))
        except Exception:
            out.append(p)
    return out


def slice_batch(batch, start, end):
    if batch is None:
        return None
    if is_dataframe(batch):
        return batch.iloc[start:end].reset_index(drop=True)
    try:
        return batch[start:end]
    except Exception:
        if start == 0 and end >= 1:
            return [batch]
        return []


def split_by_indices(batch, indices):
    """
    Return items at indices as same-type batch.
    indices: iterable of integer positions (order preserved).
    """
    if batch is None:
        return None
    if is_dataframe(batch):
        return batch.iloc[list(indices)].reset_index(drop=True)
    out = []
    try:
        for i in indices:
            out.append(batch[i])
    except Exception:
        # fallback: if batch is not indexable, return None
        return None
    return out


# -------------------------
# DefaultMixer (shared base)
# -------------------------


class DefaultMixer(object):
    """
    Shared utilities:
    - resolve dataset keys
    - reset loaders
    - pull up to n samples from a loader (uses loader.next_n if available)
    - deterministic splitting into train/val using self.validation_split and RNG
    """

    def __init__(self, spec, loaders, rng):
        self.spec = spec or {}
        self.loaders = loaders or {}
        self.rng = rng
        self.batch_size = None
        self.mix_plan = []
        # default validation split for this mixer (0.0 means no val)
        self.validation_split = float(self.spec.get("validation_split", 0.0))

    def resolve_key(self, key):
        if key in self.loaders:
            return key
        for k in self.loaders:
            if key in k:
                return k
        raise KeyError("Dataset '{}' not found among loaders".format(key))

    def reset_loader(self, loader, batch_size):
        try:
            loader.reset_epoch(batch_size=batch_size)
        except TypeError:
            try:
                loader.reset_epoch()
            except Exception:
                pass

    def reset_epoch(self, batch_size, epoch_idx=0):
        self.batch_size = batch_size
        self.mix_plan = []

    def get_mix_plan(self):
        return self.mix_plan

    def _pull_n_from_loader(self, key, n):
        """
        Pull up to n samples from loader identified by key.
        Prefer loader.next_n(n) if available, else accumulate from next_batch().
        NOTE: no replacement; if loader is exhausted, we stop and return what's available.
        """
        if n <= 0:
            return None
        loader = self.loaders[key]
        if hasattr(loader, "next_n"):
            try:
                return loader.next_n(n)
            except Exception:
                pass
        collected = []
        need = n
        while need > 0:
            try:
                b = loader.next_batch()
            except Exception:
                b = None
            if b is None:
                # no replacement: stop here
                break
            bn = batch_len(b)
            if bn == 0:
                continue
            if bn <= need:
                collected.append(b)
                need -= bn
            else:
                # take portion (drop remainder)
                if is_dataframe(b):
                    part = b.iloc[:need].reset_index(drop=True)
                else:
                    try:
                        part = list(b)[:need]
                    except Exception:
                        part = b
                collected.append(part)
                need = 0
        if not collected:
            return None
        return concat_batches(collected)

    def _split_batch(self, batch):
        """
        Deterministically split `batch` into (train_batch, val_batch) according to
        self.validation_split and self.rng. If val size <= 0, return (batch, None).
        The split preserves batch type (DataFrame vs list).
        """
        if batch is None:
            return None, None
        n = batch_len(batch)
        if n == 0:
            return None, None
        frac = self.validation_split
        if frac <= 0.0:
            return batch, None
        val_size = int(frac * n)
        if val_size <= 0:
            return batch, None
        # deterministic permutation using the mixer's RNG
        # derive an index permutation of length n
        perm = self.rng.permutation(n)
        val_idxs = set(perm[:val_size].tolist())
        train_idxs = [i for i in range(n) if i not in val_idxs]
        val_idxs_ordered = [i for i in range(n) if i in val_idxs]
        # build batches preserving types
        if is_dataframe(batch):
            train_batch = batch.iloc[train_idxs].reset_index(drop=True)
            val_batch = batch.iloc[val_idxs_ordered].reset_index(drop=True)
        else:
            train_batch = [batch[i] for i in train_idxs]
            val_batch = [batch[i] for i in val_idxs_ordered]
        return train_batch, val_batch

    # subclasses must implement next_batch and call _split_batch before returning
    def next_batch(self):
        raise NotImplementedError("Subclasses must implement next_batch")


# -------------------------
# SequenceMixer
# -------------------------


class SequenceMixer(DefaultMixer):
    """
    Stream datasets in sequence (drain one, then next).
    Spec:
      - type: "sequence"
      - datasets: [ ... ]   (keys or prefixes)
      - per_dataset_batch_size: optional
      - validation_split: optional float
    """

    def __init__(self, spec, loaders, rng):
        super().__init__(spec, loaders, rng)
        ds = spec.get("datasets") or []
        if not ds:
            raise ValueError("sequence spec requires 'datasets'")
        self.dataset_keys = [self.resolve_key(k) for k in ds]
        self.per_dataset_batch_size = spec.get("per_dataset_batch_size")
        self._cur_idx = 0
        self._current_loader = None
        # validation_split handled by DefaultMixer

    def reset_epoch(self, batch_size, epoch_idx=0):
        super().reset_epoch(batch_size, epoch_idx)
        self._cur_idx = 0
        self._current_loader = None
        if self.dataset_keys:
            self._prepare_current_loader()

    def _prepare_current_loader(self):
        if self._cur_idx >= len(self.dataset_keys):
            self._current_loader = None
            return
        key = self.dataset_keys[self._cur_idx]
        loader = self.loaders[key]
        bs = self.per_dataset_batch_size or self.batch_size
        self.reset_loader(loader, bs)
        self._current_loader = loader

    def next_batch(self):
        while self._cur_idx < len(self.dataset_keys):
            if self._current_loader is None:
                self._prepare_current_loader()
                if self._current_loader is None:
                    return None, None
            try:
                batch = self._current_loader.next_batch()
            except Exception:
                batch = None
            if batch is None or batch_len(batch) == 0:
                # move to next dataset
                self._cur_idx += 1
                self._current_loader = None
                continue
            key = self.dataset_keys[self._cur_idx]
            cnt = batch_len(batch)
            # record total counts before split
            self.mix_plan.append(
                {"type": "drain", "dataset": key, "counts": {key: cnt}}
            )
            train, val = self._split_batch(batch)
            # update last plan entry with split sizes
            last = self.mix_plan[-1]
            if train is None:
                last["train_count"] = 0
            else:
                last["train_count"] = batch_len(train)
            if val is None:
                last["val_count"] = 0
            else:
                last["val_count"] = batch_len(val)
            return train, val
        return None, None


# -------------------------
# RandomBatchesMixer
# -------------------------


class RandomBatchesMixer(DefaultMixer):
    """
    Produce random mixed batches from datasets.

    Spec keys:
      - type: "random_batches"
      - datasets: [list]                (required)
      - balanced: true|false            (default False)
      - weights: [list]                 (used when balanced==False)
      - validation_split: optional float (overrides DefaultMixer default if present)
    """

    def __init__(self, spec, loaders, rng):
        super().__init__(spec, loaders, rng)
        ds = spec.get("datasets") or []
        if not ds:
            raise ValueError("random_batches requires 'datasets'")
        self.datasets = [self.resolve_key(k) for k in ds]
        self.balanced = bool(spec.get("balanced", False))
        weights = spec.get("weights")
        if weights is None:
            weights = [1.0] * len(self.datasets)
        if len(weights) != len(self.datasets):
            raise ValueError("weights length must match datasets")
        self.weights = list(weights)
        # allow per-mixer validation_split override
        if "validation_split" in spec:
            self.validation_split = float(spec.get("validation_split", 0.0))

    def reset_epoch(self, batch_size, epoch_idx=0):
        super().reset_epoch(batch_size, epoch_idx)
        # reset all loaders
        for k in self.datasets:
            loader = self.loaders[k]
            self.reset_loader(loader, batch_size)

    def _pull_n_from_loader(self, key, n):
        # use DefaultMixer implementation (no replacement)
        return super()._pull_n_from_loader(key, n)

    def next_batch(self):
        if self.batch_size is None:
            raise RuntimeError("reset_epoch must be called first")
        B = int(self.batch_size)
        if self.balanced:
            k = len(self.datasets)
            base = [B // k] * k
            rem = B - sum(base)
            for i in range(rem):
                base[i] += 1
            counts = base
        else:
            probs = np.asarray(self.weights, dtype=float)
            probs = probs / probs.sum()
            counts = self.rng.multinomial(B, probs).tolist()
        parts = []
        produced = {}
        for i, key in enumerate(self.datasets):
            cnt = int(counts[i])
            if cnt <= 0:
                produced[key] = 0
                continue
            part = self._pull_n_from_loader(key, cnt)
            if part is None:
                produced[key] = 0
                continue
            produced[key] = batch_len(part)
            parts.append(part)
        if not parts:
            return None, None
        batch = concat_batches(parts)
        # record total counts before split
        self.mix_plan.append({"type": "random_batches", "counts": produced})
        train, val = self._split_batch(batch)
        last = self.mix_plan[-1]
        last["train_count"] = batch_len(train) if train is not None else 0
        last["val_count"] = batch_len(val) if val is not None else 0
        return train, val


# -------------------------
# BalancedByLabelMixer
# -------------------------
class BalancedByLabelMixer(DefaultMixer):
    """
    Produce batches balanced by label across datasets.

    Spec keys:
      - type: "balanced_by_label"
      - datasets: [list]   (required)
      - labels: optional list of label values to balance; if missing, discovered by peeking
      - micro_batch: optional int (how much to pull when searching); default 16
      - validation_split: optional float
    """

    def __init__(self, spec, loaders, rng):
        super().__init__(spec, loaders, rng)
        ds = spec.get("datasets") or []
        if not ds:
            raise ValueError("balanced_by_label requires 'datasets'")
        self.datasets = [self.resolve_key(k) for k in ds]
        self.provided_labels = spec.get("labels")
        self.micro = int(spec.get("micro_batch", 16))
        if "validation_split" in spec:
            self.validation_split = float(spec.get("validation_split", 0.0))

    def reset_epoch(self, batch_size, epoch_idx=0):
        super().reset_epoch(batch_size, epoch_idx)
        # reset all loaders
        for k in self.datasets:
            loader = self.loaders[k]
            self.reset_loader(loader, batch_size)
        # discover labels if not provided
        if self.provided_labels:
            self.labels = list(self.provided_labels)
        else:
            labels_set = set()
            for k in self.datasets:
                loader = self.loaders[k]
                b = None
                if hasattr(loader, "next_n"):
                    try:
                        b = loader.next_n(self.micro)
                    except Exception:
                        b = None
                if b is None:
                    try:
                        b = loader.next_batch()
                    except Exception:
                        b = None
                if b is None:
                    continue
                if is_dataframe(b):
                    if "label" in b.columns:
                        vals = b["label"].unique().tolist()
                        labels_set.update(vals)
                else:
                    for rec in b:
                        try:
                            labels_set.add(rec.get("label"))
                        except Exception:
                            continue
            if not labels_set:
                self.labels = ["BENIGN", "MALICIOUS"]
            else:
                self.labels = sorted(
                    [label for label in labels_set if label is not None]
                )
        # after peek, reset loaders again to start clean
        for k in self.datasets:
            loader = self.loaders[k]
            self.reset_loader(loader, batch_size)

    def _pull_until_label(self, key, label, need):
        if need <= 0:
            return None
        loader = self.loaders[key]
        collected = []
        while sum(batch_len(c) for c in collected) < need:
            chunk = None
            if hasattr(loader, "next_n"):
                try:
                    chunk = loader.next_n(
                        max(
                            self.micro,
                            need - sum(batch_len(c) for c in collected),
                        )
                    )
                except Exception:
                    chunk = None
            if chunk is None:
                try:
                    chunk = loader.next_batch()
                except Exception:
                    chunk = None
            if chunk is None:
                # no replacement: stop searching further
                break
            # filter chunk by label
            matches = None
            if is_dataframe(chunk):
                if "label" in chunk.columns:
                    sel = chunk[chunk["label"] == label]
                    matches = sel.reset_index(drop=True)
                else:
                    matches = None
            else:
                tmp = []
                for rec in chunk:
                    try:
                        if rec.get("label") == label:
                            tmp.append(rec)
                    except Exception:
                        continue
                matches = tmp
            if not matches:
                continue
            collected.append(matches)
        if not collected:
            return None
        return concat_batches(collected)

    def next_batch(self):
        if self.batch_size is None:
            raise RuntimeError("reset_epoch must be called first")
        B = int(self.batch_size)
        num_labels = len(self.labels)
        base = [B // num_labels] * num_labels
        rem = B - sum(base)
        for i in range(rem):
            base[i] += 1
        parts = []
        produced = {}
        for i, lbl in enumerate(self.labels):
            need = base[i]
            collected_for_label = []
            per_ds_need = int(np.ceil(need / float(len(self.datasets))))
            remaining = need
            ds_idx = 0
            attempts = 0
            while remaining > 0 and attempts < len(self.datasets) * 4:
                key = self.datasets[ds_idx % len(self.datasets)]
                want = min(per_ds_need, remaining)
                chunk = self._pull_until_label(key, lbl, want)
                if chunk is None:
                    ds_idx += 1
                    attempts += 1
                    continue
                collected_for_label.append(chunk)
                got = batch_len(chunk)
                remaining -= got
                ds_idx += 1
            if collected_for_label:
                part = concat_batches(collected_for_label)
                parts.append(part)
                produced[lbl] = batch_len(part)
            else:
                produced[lbl] = 0
        if not parts:
            return None, None
        batch = concat_batches(parts)
        self.mix_plan.append(
            {"type": "balanced_by_label", "counts_by_label": produced}
        )
        train, val = self._split_batch(batch)
        last = self.mix_plan[-1]
        last["train_count"] = batch_len(train) if train is not None else 0
        last["val_count"] = batch_len(val) if val is not None else 0
        return train, val
