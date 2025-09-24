# feature_extraction.py
# Author: Jan Svoboda
# functionality: Robust feature extraction tailored for Zeek conn logs with built-in
#               "final state" inference and protocol filtering.
# Returns (X, y) where X is a label-less DataFrame and y is a pd.Series.

import pandas as pd
import traceback
from typing import Iterable, List, Optional, Tuple, Union, Any, Mapping

from commons import BENIGN, MALICIOUS


class FeatureExtraction:
    def __init__(
        self,
        protocols_to_discard: Optional[Iterable[str]] = None,
        columns_to_discard: Optional[Iterable[str]] = None,
        column_types: Optional[dict] = None,
    ):
        """
        protocols_to_discard: iterable of protocol names (strings) to remove (case-insensitive).
            If None, defaults to the list used in the old project.
        columns_to_discard: additional columns to drop (in addition to built-in drops).
        column_types: dict of {col: dtype} to enforce with astype (errors ignored).
        """
        self.protocols_to_discard = (
            list(protocols_to_discard)
            if protocols_to_discard is not None
            else ["arp", "ARP", "icmp", "igmp", "ipv6-icmp", ""]
        )
        self.columns_to_discard = (
            list(columns_to_discard) if columns_to_discard is not None else []
        )
        self.column_types = column_types if column_types is not None else {}

        self._builtin_drop = [
            "appproto",
            "daddr",
            "saddr",
            "starttime",
            "type_",
            "smac",
            "dmac",
            "history",
            "uid",
            "dir_",
            "endtime",
            "flow_source",
        ]

        self._numeric_cols = [
            "proto",
            "dport",
            "sport",
            "dur",
            "pkts",
            "spkts",
            "bytes",
            "sbytes",
            "state",
        ]

    def process_batch(
        self, data: Union[pd.DataFrame, List[dict], Iterable[dict]]
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Process a whole batch of flows and return (X, y).
        X: pd.DataFrame without label columns
        y: pd.Series with values from commons BENIGN / MALICIOUS
        """
        try:
            if isinstance(data, pd.DataFrame):
                df = data.copy()
            else:
                df = pd.DataFrame(list(data))

            if df.empty:
                return pd.DataFrame([], columns=[]), pd.Series(
                    [], dtype="object"
                )

            y = self._extract_labels(df)
            df = self._process_features(df)

            if df.empty:
                return pd.DataFrame([], columns=[]), pd.Series(
                    [], dtype="object"
                )

            df = self.drop_labels(df)

            # enforce user-specified column dtypes
            for col, dtype in self.column_types.items():
                if col in df.columns:
                    try:
                        df[col] = df[col].astype(dtype, errors="ignore")
                    except Exception:
                        pass

            # enforce numeric coercion for critical numeric cols
            for col in self._numeric_cols:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors="coerce")

            # keep y aligned
            y.index = df.index[: len(y)] if len(y) <= len(df) else y.index

            return df.reset_index(drop=True), y.loc[df.index].reset_index(
                drop=True
            )
        except Exception:
            print("Error in FeatureExtraction.process_batch():")
            print(traceback.format_exc())
            return pd.DataFrame([], columns=[]), pd.Series([], dtype="object")

    def process_item(self, flow_dict: dict) -> Optional[Tuple[dict, object]]:
        """
        Process a single flow (dict). Returns (flow_without_label_dict, label)
        or None if the flow gets dropped by filtering.
        """
        df = pd.DataFrame([flow_dict])
        X, y = self.process_batch(df)
        if X.empty or y.empty:
            return None
        return X.iloc[0].to_dict(), y.iloc[0]

    # -------------------------
    # Helpers
    # -------------------------
    def _extract_labels(self, df: pd.DataFrame) -> pd.Series:
        """
        Extract label column from df, mapping into BENIGN/MALICIOUS.
        Prefer ground_truth_label, detailed_ground_truth_label, label, module_labels.
        Default to BENIGN if missing.
        """
        label_cols = [
            "ground_truth_label",
            "detailed_ground_truth_label",
            "label",
            "module_labels",
        ]
        found = [c for c in label_cols if c in df.columns]
        if not found:
            return pd.Series(
                [BENIGN] * len(df), index=df.index, dtype="object"
            )

        col = found[0]
        raw = df[col].fillna(str(BENIGN)).astype(str)

        def map_label(val: str) -> str:
            v = val.strip().upper()
            if v == "" or v == str(BENIGN).upper():
                return BENIGN
            if v == str(MALICIOUS).upper() or "MAL" in v or v == "1":
                return MALICIOUS
            return BENIGN

        return raw.map(map_label)

    def drop_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        return df.drop(
            [
                "ground_truth_label",
                "detailed_ground_truth_label",
                "label",
                "module_labels",
            ],
            axis=1,
            errors="ignore",
        )

    def _process_features(self, dataset: pd.DataFrame) -> pd.DataFrame:
        df = dataset.copy()

        # normalize proto
        if "proto" in df.columns:
            df["proto"] = df["proto"].astype(str).str.lower()

        # drop unwanted protocols
        discard_set = {p.lower() for p in self.protocols_to_discard}
        if "proto" in df.columns:
            df = df[~df["proto"].fillna("").str.lower().isin(discard_set)]

        if df.empty:
            return df

        # drop irrelevant columns
        df = df.drop(
            columns=[
                c
                for c in self._builtin_drop + self.columns_to_discard
                if c in df.columns
            ],
            errors="ignore",
        )

        # compute bytes & pkts
        sbytes = pd.to_numeric(df.get("sbytes", 0), errors="coerce").fillna(0)
        dbytes = pd.to_numeric(df.get("dbytes", 0), errors="coerce").fillna(0)
        df["bytes"] = sbytes + dbytes

        spkts = pd.to_numeric(df.get("spkts", 0), errors="coerce").fillna(0)
        dpkts = pd.to_numeric(df.get("dpkts", 0), errors="coerce").fillna(0)
        df["pkts"] = spkts + dpkts

        # state inference
        def _safe_int(x, default=0):
            try:
                return int(float(x))
            except Exception:
                return default

        def _infer_state(row: Mapping[str, Any]) -> float:
            state = row.get("state", "")
            pkts = _safe_int(row.get("pkts", 0))
            pre = str(state).split("_")[0]

            st = str(state).lower()
            if "new" in st or st == "established":
                return 1.0
            if "closed" in st or st == "not established":
                return 0.0
            if state in ("S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"):
                return 0.0
            if state in ("S1", "SF", "S2", "S3", "RSTO", "RSTP", "OTH"):
                return 1.0
            if "S" in pre and "A" in pre:
                return 1.0
            if "PA" in pre:
                return 1.0
            if "ECO" in pre or "ECR" in pre or "URH" in pre or "URP" in pre:
                return 1.0
            if "EST" in pre:
                return 1.0
            if "RST" in pre or "FIN" in pre:
                return 0.0 if pkts <= 3 else 1.0
            return 0.0

        if "state" in df.columns:
            df["state"] = df.apply(_infer_state, axis=1)
        else:
            df["state"] = 0.0

        # proto mapping
        if "proto" in df.columns:
            proto_series = df["proto"].astype(str).fillna("")
            mapping_patterns = [
                (r"tcp", 0.0),
                (r"udp", 1.0),
                (r"icmp-ipv6", 3.0),
                (r"icmp", 2.0),
                (r"arp", 4.0),
            ]
            mapped = pd.Series(index=proto_series.index, dtype="float64")
            for patt, val in mapping_patterns:
                mask = proto_series.str.contains(
                    patt, case=False, regex=True, na=False
                )
                mapped.loc[mask] = val
            df["proto"] = pd.to_numeric(mapped, errors="coerce").fillna(0.0)

        # enforce numeric coercion
        for c in [
            "dport",
            "sport",
            "dur",
            "pkts",
            "spkts",
            "bytes",
            "sbytes",
            "state",
        ]:
            if c in df.columns:
                df[c] = pd.to_numeric(df[c], errors="coerce")

        df = df.dropna(how="all").reset_index(drop=True)
        return df
