# Author: Jan Svoboda
# functionality: Minimal converter from Zeek conn log format to canonical SLIPS flow format.
# This is used to normalize Zeek conn logs before feeding them to FeatureExtraction.
from typing import Dict, Any, Iterable, List


# Minimal mapping taken from your original map (Zeek -> SLIPS)
CONN_FIELDS_TO_SLIPS_FIELDS_MAP = {
    "ts": "starttime",
    "uid": "uid",
    "id.orig_h": "saddr",
    "id.orig_p": "sport",
    "id.resp_h": "daddr",
    "id.resp_p": "dport",
    "proto": "proto",
    "service": "appproto",
    "duration": "dur",
    "orig_bytes": "sbytes",
    "resp_bytes": "dbytes",
    "conn_state": "state",
    "history": "history",
    "orig_pkts": "spkts",
    "resp_pkts": "dpkts",
    "label": "ground_truth_label",
    "detailedlabel": "detailed_ground_truth_label",
}

# canonical SLIPS field names we will output (keeps the commonly used ones)
CANONICAL_FIELDS = [
    "starttime",
    "uid",
    "saddr",
    "sport",
    "daddr",
    "dport",
    "proto",
    "appproto",
    "dur",
    "sbytes",
    "dbytes",
    "state",
    "history",
    "spkts",
    "dpkts",
    "ground_truth_label",
    "detailed_ground_truth_label",
    "type_",
    "dir_",
    "label",
    "module_labels",
    "smac",
    "dmac",
]


class ConnToSlipsConverter:
    """
    Minimal converter: takes a single Zeek conn flow dict (or list of dicts)
    and returns a canonical SLIPS-style dict (or list of dicts).
    """

    def __init__(self, default_label: str = "Benign"):
        self.default_label = default_label

        # Build a normalized mapping that also accepts already-canonical SLIPS names
        self._map = dict(CONN_FIELDS_TO_SLIPS_FIELDS_MAP)
        # identity mapping for already-canonical slips names
        for v in set(self._map.values()):
            self._map.setdefault(v, v)
        # also accept canonical fields (map to themselves)
        for f in CANONICAL_FIELDS:
            self._map.setdefault(f, f)

        # which fields should be integers and floats
        self._int_fields = {
            "sport",
            "dport",
            "spkts",
            "dpkts",
            "sbytes",
            "dbytes",
        }
        self._float_fields = {"dur"}

    def _safe_int(self, x: Any, default: int = 0) -> int:
        try:
            # handle floats in strings too
            return int(float(x))
        except Exception:
            return default

    def _safe_float(self, x: Any, default: float = 0.0) -> float:
        try:
            return float(x)
        except Exception:
            return default

    def normalize(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a single flow dict to canonical SLIPS fields.
        """

        out: Dict[str, Any] = {}

        # First, map known keys to canonical names
        for k, v in flow.items():
            # if ts present as numeric string, let it through as starttime (string) --
            # downstream can convert to datetime if needed
            dest = self._map.get(k)
            if dest:
                out[dest] = v
            # else: ignore unknown fields

        # Ensure canonical fields exist (fill defaults)
        for f in CANONICAL_FIELDS:
            if f not in out:
                if f in self._int_fields:
                    out[f] = 0
                elif f in self._float_fields:
                    out[f] = 0.0
                elif f in ("module_labels",):
                    out[f] = {}  # module_labels is usually a dict
                else:
                    out[f] = ""

        # Ensure labels exist (use provided default if missing/empty)
        if not out.get("ground_truth_label"):
            out["ground_truth_label"] = self.default_label
        if not out.get("detailed_ground_truth_label"):
            out["detailed_ground_truth_label"] = self.default_label

        # Coerce numeric fields safely
        for i in self._int_fields:
            out[i] = self._safe_int(out.get(i, 0), default=0)
        for f in self._float_fields:
            out[f] = self._safe_float(out.get(f, 0.0), default=0.0)

        # Keep state as-is (textual conn state like 'S0' or 'Established').
        # If you prefer numeric treatment here, transform it in FeatureExtraction.
        # But ensure it's a string so processing won't crash if it's None.
        out["state"] = "" if out["state"] is None else str(out["state"])

        return out

    def normalize_batch(
        self, flows: Iterable[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        return [self.normalize(f) for f in flows]
