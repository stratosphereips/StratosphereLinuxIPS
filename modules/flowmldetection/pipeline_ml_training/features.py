# feature_extraction.py
# Author: Jan Svoboda
# functionality: Robust feature extraction tailored for Zeek conn logs with built-in
#               "final state" inference and protocol filtering.
# Class ConnToSlipsConverter, which normalizes conn flows into slips format of flows, we can then use featureExtraction we want

# Returns (X, y) where X is a label-less DataFrame and y is a pd.Series.
# Works on batcher or individual flows
# feature_extraction_v2.py
import pandas as pd
import traceback
from typing import Iterable, List, Optional, Tuple, Union

from .conn_normalizer import ConnToSlipsConverter
from .commons import BENIGN, MALICIOUS


class FeatureExtraction:
    def __init__(
        self,
        default_label: str = "Benign",
        protocols_to_discard: Optional[Iterable[str]] = None,
        columns_to_discard: Optional[Iterable[str]] = None,
        column_types: Optional[dict] = None,
    ):
        """
        Minimal FeatureExtraction that relies on ConnToSlipsConverter to
        normalize Zeek conn flows into canonical SLIPS fields.
        """
        self.converter = ConnToSlipsConverter(default_label=default_label)

        self.protocols_to_discard = (
            list(protocols_to_discard)
            if protocols_to_discard is not None
            else ["arp", "ARP", "icmp", "igmp", "ipv6-icmp", ""]
        )
        self.columns_to_discard = (
            list(columns_to_discard) if columns_to_discard is not None else []
        )
        self.column_types = column_types if column_types is not None else {}

        # fields to drop eventually (non-feature, identifiers)
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

        # core numeric columns we want to ensure are numeric for ML
        self._numeric_cols = [
            "dport",
            "sport",
            "dur",
            "pkts",
            "spkts",
            "bytes",
            "sbytes",
        ]

        # proto mapping patterns -> numeric values
        self._proto_mapping_patterns = [
            (r"tcp", 0.0),
            (r"udp", 1.0),
            (r"icmp-ipv6", 3.0),
            (r"icmp", 2.0),
            (r"arp", 4.0),
        ]

        self.slips_column_order = [
            "dur",
            "proto",
            "sport",
            "dport",
            "spkts",
            "dpkts",
            "sbytes",
            "dbytes",
            "state",
            "bytes",
            "pkts",
        ]
        self.label_cols = [
            "ground_truth_label",
            "detailed_ground_truth_label",
            "label",
            "module_labels",
            "detailed_label",
        ]

    def process_batch(
        self, data: Union[pd.DataFrame, List[dict], Iterable[dict]]
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Process a batch of flows and return (X, y).
        X: pd.DataFrame without label columns
        y: pd.Series with values from commons BENIGN / MALICIOUS
        """

        try:

            if isinstance(data, pd.DataFrame):
                df = data.copy()
                raw_zeek_field_signatures = {
                    "id.orig_p",
                    "orig_bytes",
                    "conn_state",
                    "id.resp_p",
                    "orig_pkts",
                }
                if any(col in df.columns for col in raw_zeek_field_signatures):
                    records = df.to_dict(orient="records")
                    norm = self.converter.normalize_batch(records)
                    df = pd.DataFrame(norm)
            else:
                records = list(data) if not isinstance(data, dict) else [data]
                norm = self.converter.normalize_batch(records)
                df = pd.DataFrame(norm)

            if df.empty:
                return pd.DataFrame([], columns=[]), pd.Series(
                    [], dtype="object"
                )

            # PROCESS features first (this may drop/filter rows)
            df = self._process_features(df)

            if df.empty:
                return pd.DataFrame([], columns=[]), pd.Series(
                    [], dtype="object"
                )

            # Now extract labels from the already-filtered df -> alignment is correct
            y = self._extract_labels(df)

            # remove label columns from X (keep y separately)
            df = self.drop_labels(df)

            # enforce user-specified column dtypes (best-effort)
            for col, dtype in self.column_types.items():
                if col in df.columns:
                    try:
                        df[col] = df[col].astype(dtype, errors="ignore")
                    except Exception:
                        pass

            # ensure numeric coercion on critical numeric cols
            for col in self._numeric_cols:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors="coerce")

            # Reorder as in slips (only keep existing cols)
            existing_cols = [
                col for col in self.slips_column_order if col in df.columns
            ]
            df = df[existing_cols]

            # final reset indexes for both df and y so returned objects have standard RangeIndex
            df = df.reset_index(drop=True)
            y = y.reset_index(drop=True)

            return df, y

        except Exception:
            print("Error in FeatureExtraction.process_batch():")
            print(traceback.format_exc())
            return pd.DataFrame([], columns=[]), pd.Series([], dtype="object")

    def process_item(self, flow_dict: dict) -> Optional[Tuple[dict, object]]:
        """
        Process a single flow dict. Returns (flow_without_label_dict, label)
        or None if the flow gets dropped by filtering.
        """
        X, y = self.process_batch([flow_dict])
        if X.empty or y.empty:
            return None
        return X.iloc[0].to_dict(), y.iloc[0]

    def _extract_labels(self, df: pd.DataFrame) -> pd.Series:
        """
        Extract label column from df, mapping into BENIGN/MALICIOUS.
        Prefer ground_truth_label, detailed_ground_truth_label, label, module_labels.
        Default to converter.default_label if missing.
        If gt is missing, but the detailed label is malware, we assume the whole is malware.
        """
        label_cols = self.label_cols
        found = [c for c in label_cols if c in df.columns]
        if not found:
            return pd.Series(
                [self.converter.default_label] * len(df),
                index=df.index,
                dtype="object",
            )

        def map_label(val: str) -> str:
            v = val.strip().upper()
            if v == "" or v == str(BENIGN).upper():
                return BENIGN
            if v == str(MALICIOUS).upper() or "MAL" in v or v == "1":
                return MALICIOUS
            return BENIGN

        def row_map_label(row) -> str:
            for v in row:
                if map_label(str(v)) == MALICIOUS:
                    return MALICIOUS
            return BENIGN

        df_labels = df[found]  # extract all columns with possible labels
        final_label = pd.DataFrame(
            (row_map_label(row) for _, row in df_labels.iterrows())
        )

        return final_label.iloc[:, 0]

    def drop_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        return df.drop(
            self.label_cols,
            axis=1,
            errors="ignore",
        )

    def _process_features(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()

        # normalize proto string early
        if "proto" in df.columns:
            df["proto"] = df["proto"].astype(str).str.lower()

        # drop unwanted protocols
        discard_set = {p.lower() for p in self.protocols_to_discard}
        if "proto" in df.columns:
            df = df[~df["proto"].fillna("").str.lower().isin(discard_set)]

        if df.empty:
            return df

        # ensure numeric sbytes/dbytes/spkts/dpkts exist and are numeric (safe)
        df["sbytes"] = pd.to_numeric(
            df.get("sbytes", 0), errors="coerce"
        ).fillna(0)
        df["dbytes"] = pd.to_numeric(
            df.get("dbytes", 0), errors="coerce"
        ).fillna(0)
        df["spkts"] = pd.to_numeric(
            df.get("spkts", 0), errors="coerce"
        ).fillna(0)
        df["dpkts"] = pd.to_numeric(
            df.get("dpkts", 0), errors="coerce"
        ).fillna(0)

        # compute bytes & pkts
        df["bytes"] = df["sbytes"] + df["dbytes"]
        df["pkts"] = df["spkts"] + df["dpkts"]

        # drop irrelevant columns (identifiers, etc.)
        df = df.drop(
            columns=[
                c
                for c in self._builtin_drop + self.columns_to_discard
                if c in df.columns
            ],
            errors="ignore",
        )

        # proto mapping -> numeric codes
        if "proto" in df.columns:
            proto_series = df["proto"].astype(str).fillna("")
            mapped = pd.Series(index=proto_series.index, dtype="float64")
            for patt, val in self._proto_mapping_patterns:
                mask = proto_series.str.contains(
                    patt, case=False, regex=True, na=False
                )
                mapped.loc[mask] = val
            df["proto"] = pd.to_numeric(mapped, errors="coerce").fillna(0.0)

        # numeric coercion for the defined numeric fields
        for c in self._numeric_cols:
            if c in df.columns:
                df[c] = pd.to_numeric(df[c], errors="coerce")

        df = df.dropna(how="all").reset_index(drop=True)
        return df
