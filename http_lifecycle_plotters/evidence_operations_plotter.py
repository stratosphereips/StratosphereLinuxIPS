#!/usr/bin/env python3
import sys
import pandas as pd
import matplotlib.pyplot as plt


def plot_growth(csv_path: str):
    max_flows = 1000
    # Load CSV
    df = pd.read_csv(csv_path)
    df = df.head(max_flows)

    # Select only the four bottleneck columns
    # bottleneck_cols = [
    #     "from_zeek_to_input",
    #     "from_input_to_profiler",
    #     "time_from_profiler_to_http_analyzer",
    #     "reach_evidence_handler",
    # ]

    evidence_handler_cols = [
        "check_whitelisted_evidence",
        "filtering_and_acc_threat_lvl_of_ev",
        "adding_to_alerts_json",
        "checking_alert",
    ]

    # Ensure only existing columns are taken (in case CSV changes)
    numeric_df = df[[c for c in evidence_handler_cols if c in df.columns]]

    # Plot
    ax = numeric_df.plot(
        figsize=(14, 7),
        logy=True,  # log scale on Y axis
        marker="",  # no markers (cleaner for large data)
        alpha=0.8,
    )

    ax.set_title("Top Bottleneck Stages Across Flows (log scale)", fontsize=16)
    ax.set_xlabel("Row Index (Flow)", fontsize=12)
    ax.set_ylabel("Time (log scale)", fontsize=12)
    plt.legend(title="Stages", bbox_to_anchor=(1.05, 1), loc="upper left")
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <csv_file>")
        sys.exit(1)

    csv_file = sys.argv[1]
    plot_growth(csv_file)
