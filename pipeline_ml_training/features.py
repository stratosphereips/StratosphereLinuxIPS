# Author: Jan Svoboda
# functionality: Robust feature extraction tailored for Zeek conn logs with built-in
#               "final state" inference (no external DB/callback).
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
        # defaults from your previous project
        self.protocols_to_discard = (
            list(protocols_to_discard)
            if protocols_to_discard is not None
            else ["arp", "ARP", "icmp", "igmp", "ipv6-icmp", ""]
        )
        self.columns_to_discard = (
            list(columns_to_discard) if columns_to_discard is not None else []
        )
        self.column_types = column_types if column_types is not None else {}

        # internal list of fields to drop (same as your previous to_drop list)
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

        # columns we aim to treat as numeric where possible
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

    # -------------------------
    # Public API
    # -------------------------
    def process_batch(
        self, data: Union[pd.DataFrame, List[dict], Iterable[dict]]
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Process a whole batch of flows and return (X, y).
        X: pd.DataFrame without label columns
        y: pd.Series with values from commons BENIGN / MALICIOUS
        """
        try:
            # normalize input to DataFrame
            if isinstance(data, pd.DataFrame):
                df = data.copy()
            else:
                # assume iterable of dicts
                df = pd.DataFrame(list(data))

            if df.empty:
                # Keep signature consistent: return empty X and empty y
                return pd.DataFrame([], columns=[]), pd.Series(
                    [], dtype="object"
                )

            # Apply label extraction (before dropping label columns)
            y = self._extract_labels(df)

            # Process features and clean (including state inference)
            df = self._process_features(df)

            # After processing, if df is empty return empties (but keep y aligned)
            if df.empty:
                return pd.DataFrame([], columns=[]), pd.Series(
                    [], dtype="object"
                )

            # Drop label columns from features
            df = self.drop_labels(df)

            # Ensure requested column types
            for col, dtype in self.column_types.items():
                if col in df.columns:
                    try:
                        df[col] = df[col].astype(dtype, errors="ignore")
                    except Exception:
                        # ignore conversion problems
                        pass

            # Keep index alignment with y (y was extracted from original df)
            y.index = df.index[: len(y)] if len(y) <= len(df) else y.index

            # Final X and y: ensure types for numeric columns
            for col in self._numeric_cols:
                if col in df.columns:
                    try:
                        df[col] = pd.to_numeric(df[col], errors="coerce")
                    except Exception:
                        pass

            # Return label-less X and y aligned by index (reset y index to simple RangeIndex)
            return df.reset_index(drop=True), y.loc[df.index].reset_index(
                drop=True
            )
        except Exception:
            # Best-effort debugging info — do not change other files / logging
            print("Error in FeatureExtraction.process_batch():")
            print(traceback.format_exc())
            # return empty to avoid breaking pipeline
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
        row = X.iloc[0].to_dict()
        label = y.iloc[0]
        return row, label

    # -------------------------
    # Helpers
    # -------------------------
    def _extract_labels(self, df: pd.DataFrame) -> pd.Series:
        """
        Extract label column from df, mapping into BENIGN/MALICIOUS.
        Prefer these columns if present: ground_truth_label, detailed_ground_truth_label, label, module_labels
        If none present, default to BENIGN.
        Returns a pd.Series (index preserved).
        """
        label_cols = [
            "ground_truth_label",
            "detailed_ground_truth_label",
            "label",
            "module_labels",
        ]
        found = [c for c in label_cols if c in df.columns]
        if not found:
            # default all to BENIGN
            return pd.Series(
                [BENIGN] * len(df), index=df.index, dtype="object"
            )

        # use the first available label column
        col = found[0]
        raw = df[col].fillna(str(BENIGN)).astype(str)

        def map_label(val: str) -> str:
            v = val.strip().upper()
            if v == "" or v == str(BENIGN).upper():
                return BENIGN
            if v == str(MALICIOUS).upper() or "MAL" in v or v == "1":
                return MALICIOUS
            # fallback: treat unknown as BENIGN
            return BENIGN

        mapped = raw.map(map_label)
        return pd.Series(mapped.values, index=df.index, dtype="object")

    def drop_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Drop known label columns to produce the feature-only DataFrame.
        """
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
        """
        Core cleaning pipeline adapted from your previous code:
         - numeric conversions (coerce where necessary)
         - drop unwanted protocols
         - drop builtin & user-specified fields
         - compute bytes and pkts
         - resolve/normalize state column using embedded heuristics (original implementation)
         - proto -> categorical numeric mapping
        """
        df = dataset.copy()

        # make proto lowercase string if present for consistent checks
        if "proto" in df.columns:
            try:
                df["proto"] = df["proto"].astype(str).str.lower()
            except Exception:
                pass

        # Discard flows with unwanted protocols
        if self.protocols_to_discard:
            discard_set = {p.lower() for p in self.protocols_to_discard}
            if "proto" in df.columns:
                df = df[~df["proto"].fillna("").str.lower().isin(discard_set)]

        # If the dataset got empty after protocol filtering -> return empty
        if df.empty:
            return df

        # Drop builtin fields and user requested columns
        to_drop = list(self._builtin_drop) + list(self.columns_to_discard)
        df = df.drop(
            columns=[c for c in to_drop if c in df.columns], errors="ignore"
        )

        # Compute bytes and pkts where applicable using sbytes,dbytes,spkts,dpkts
        sbytes = pd.to_numeric(
            df.get("sbytes", pd.Series([0] * len(df))), errors="coerce"
        ).fillna(0)
        dbytes = pd.to_numeric(
            df.get("dbytes", pd.Series([0] * len(df))), errors="coerce"
        ).fillna(0)
        df["bytes"] = sbytes + dbytes

        spkts = pd.to_numeric(
            df.get("spkts", pd.Series([0] * len(df))), errors="coerce"
        ).fillna(0)
        dpkts = pd.to_numeric(
            df.get("dpkts", pd.Series([0] * len(df))), errors="coerce"
        ).fillna(0)
        df["pkts"] = spkts + dpkts

        # -------------------------
        # Infer final 'state' from available info using your original logic
        # -------------------------
        def _safe_int(x, default=0):
            try:
                return int(float(x))
            except Exception:
                return default

        def _infer_established_from_flags_row(row: Mapping[str, Any]) -> float:
            """
            Implements the original get_final_state_from_flags logic.
            Returns 1.0 for 'Established', 0.0 for 'Not Established'.
            ICMP/other labels that original code sometimes returned as strings are
            treated as 'Established' when the original code indicated so.
            """
            # preserve original variables' names for clarity
            state = row.get("state", None)
            pkts_val = row.get("pkts", None)
            pkts = _safe_int(pkts_val, default=0)

            try:
                try:
                    pre = str(state).split("_")[0]
                except Exception:
                    pre = ""
                try:
                    st = "" if state is None else str(state)
                    st_lower = st.lower()
                    # Suricata-like checks
                    if "new" in st_lower or st_lower == "established":
                        return 1.0
                    elif "closed" in st_lower or st_lower == "not established":
                        return 0.0

                    # Zeek tokens => follow original mapping
                    if st in ("S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"):
                        return 0.0
                    elif st in ("S1", "SF", "S2", "S3", "RSTO", "RSTP", "OTH"):
                        return 1.0

                    # Argus-like: try to inspect suffix
                    try:
                        suf = str(state).split("_")[1]
                    except Exception:
                        suf = ""

                    # many pattern combinations indicate both sides saw SYN/ACK etc
                    if "S" in pre and "A" in pre and "S" in suf and "A" in suf:
                        return 1.0
                    elif "PA" in pre and "PA" in suf:
                        return 1.0
                    elif "ECO" in pre:
                        # ICMP Echo — original returned a string; treat as Established
                        return 1.0
                    elif "ECR" in pre:
                        return 1.0
                    elif "URH" in pre:
                        return 1.0
                    elif "URP" in pre:
                        return 1.0
                    else:
                        return 0.0
                except IndexError:
                    # suffix did not exist in original code branch — handle many heuristics
                    if "ECO" in pre:
                        return 1.0
                    elif "UNK" in pre:
                        return 1.0
                    elif "CON" in pre:
                        return 1.0
                    elif "INT" in pre:
                        return 0.0
                    elif "EST" in pre:
                        return 1.0
                    elif "RST" in pre:
                        return 0.0 if pkts <= 3 else 1.0
                    elif "FIN" in pre:
                        return 0.0 if pkts <= 3 else 1.0
                    else:
                        return 0.0
            except Exception:
                # conservative fallback if anything unexpected happens
                return 0.0

        # Apply the row-wise inference (safe even if 'state' wasn't a string)
        try:
            df["_inferred_state_num"] = df.apply(
                _infer_established_from_flags_row, axis=1
            )
            # put into 'state' numeric column (overwrite previous textual state)
            df["state"] = pd.to_numeric(
                df["_inferred_state_num"], errors="coerce"
            ).fillna(0.0)
            df = df.drop(columns=["_inferred_state_num"], errors="ignore")
        except Exception:
            # fallback if apply somehow fails: coerce existing state to numeric or zero
            try:
                df["state"] = pd.to_numeric(
                    df.get("state", 0), errors="coerce"
                ).fillna(0.0)
            except Exception:
                df["state"] = 0.0

        # -------------------------
        # Proto -> numeric mapping (explicit small mapping like old code)
        # -------------------------
        if "proto" in df.columns:
            try:
                # standard mapping used previously
                mapping_patterns = [
                    (r"tcp", 0.0),
                    (r"udp", 1.0),
                    (r"icmp-ipv6", 3.0),
                    (r"icmp", 2.0),
                    (r"arp", 4.0),
                ]
                proto_series = df["proto"].astype(str).fillna("")
                mapped = pd.Series(index=proto_series.index, dtype="float64")
                mapped[:] = pd.NA
                for patt, val in mapping_patterns:
                    mask = proto_series.str.contains(
                        patt, case=False, regex=True, na=False
                    )
                    mapped.loc[mask] = val
                # any remaining values try to coerce to numeric, otherwise set 0
                mapped = pd.to_numeric(mapped, errors="coerce").fillna(0.0)
                df["proto"] = mapped.astype("float64")
            except Exception:
                # final fallback: coerce to numeric with errors -> NaN -> fill 0
                df["proto"] = pd.to_numeric(
                    df["proto"], errors="coerce"
                ).fillna(0.0)

        # Try to coerce the main numeric fields
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
                try:
                    df[c] = pd.to_numeric(df[c], errors="coerce")
                except Exception:
                    pass

        # Remove rows that do not have numeric essential columns (optional: keep but they may be NaN)
        # We'll keep rows and let downstream transformers handle NaNs; but we can drop rows completely empty
        if df.isna().all(axis=1).any():
            # If a row is entirely NaN, drop it
            df = df[~df.isna().all(axis=1)]

        # final: reset index to preserve contiguous indices for pairing with y upstream
        df = df.reset_index(drop=True)
        return df
