import pandas as pd

# Author: Jan Svoboda
# functionality: Wrapper for feature extraction. this can differ based on the type of data, type of flows or classifier we want to apply.
# functions: save/load, fit/predict, init new classifier


class FeatureExtraction:

    def __init__(
        self,
        protocols_to_discard=None,
        columns_to_discard=None,
        column_types=None,
    ):
        self.protocols_to_discard = (
            protocols_to_discard if protocols_to_discard is not None else []
        )
        self.columns_to_discard = (
            columns_to_discard if columns_to_discard is not None else []
        )
        self.column_types = column_types if column_types is not None else {}

    def _process(self, flows_df):
        # Discard flows with unwanted protocols
        if self.protocols_to_discard:
            flows_df = flows_df[
                ~flows_df["protocol"].isin(self.protocols_to_discard)
            ]
        # Discard unwanted columns
        flows_df = flows_df.drop(
            columns=self.columns_to_discard, errors="ignore"
        )
        # Ensure columns are in the right type
        for col, dtype in self.column_types.items():
            if col in flows_df.columns:
                flows_df[col] = flows_df[col].astype(dtype, errors="ignore")
        return flows_df

    def process_batch(self, flows_df):
        return self._process(flows_df)

    def process_item(self, flow_dict):
        df = pd.DataFrame([flow_dict])
        processed_df = self._process(df)
        if not processed_df.empty:
            return processed_df.iloc[0].to_dict()
        else:
            return None
