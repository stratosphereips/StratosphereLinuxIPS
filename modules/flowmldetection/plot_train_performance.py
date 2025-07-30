import argparse
import os
import re

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import pandas as pd


def plot_log_data(file_path, experiment_number):

    # Read the log data from the file
    with open(file_path, "r") as file:
        log_data = file.read()

    # Check and create 'performance_metrics' directory if it doesn't exist
    base_dir = "performance_metrics"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    # Check and create 'testing' directory inside 'performance_metrics'
    testing_dir = os.path.join(base_dir, "training")
    if not os.path.exists(testing_dir):
        os.makedirs(testing_dir)

    saving_dir = os.path.join(testing_dir, f"{experiment_number}")
    if not os.path.exists(saving_dir):
        os.makedirs(saving_dir)

    # Regex pattern for the new log format
    pattern = (
        r"Total labels: ([\d\.]+), Background: (\d+). Benign: (\d+). Malicious: (\d+). Metrics: "
        r"FPR=([\d\.]+), TNR=([\d\.]+), TPR=([\d\.]+), FNR=([\d\.]+), "
        r"F1=([\d\.]+), Precision=([\d\.]+), Accuracy=([\d\.]+), MCC=([\d\.]+), Recall=([\d\.]+)\."
    )

    # Parse the log file
    data = re.findall(pattern, log_data)

    # Convert data to a DataFrame
    columns = [
        "Total labels",
        "Background",
        "Benign",
        "Malicious",
        "FPR",
        "TNR",
        "TPR",
        "FNR",
        "F1",
        "Precision",
        "Accuracy",
        "MCC",
        "Recall",
    ]
    df = pd.DataFrame(data, columns=columns)
    df = df.astype(
        {
            "Total labels": float,
            "Background": int,
            "Benign": int,
            "Malicious": int,
            "FPR": float,
            "TNR": float,
            "TPR": float,
            "FNR": float,
            "F1": float,
            "Precision": float,
            "Accuracy": float,
            "MCC": float,
            "Recall": float,
        }
    )

    dir_name = os.path.dirname(file_path)

    # --- Plot 1: Number of labels (linear scale, no total labels) ---
    fig1, ax1 = plt.subplots(figsize=(10, 6))
    ax1.plot(df.index, df["Background"], label="Background", color="black")
    ax1.plot(df.index, df["Benign"], label="Benign", color="cyan")
    ax1.plot(df.index, df["Malicious"], label="Malicious", color="magenta")
    ax1.set_xlabel("Index")
    ax1.set_ylabel("Label Counts")
    ax1.set_title(f"Label Counts - Experiment {experiment_number}")
    ax1.legend()
    ax1.yaxis.set_major_locator(ticker.MaxNLocator(70))
    ax1.xaxis.set_major_locator(ticker.MaxNLocator(50))
    ax1.axhline(y=0, color="black", linewidth=1)
    plt.tight_layout()
    plt.savefig(
        os.path.join(dir_name, "performance_metrics_training_labels.png")
    )
    plt.savefig(
        os.path.join(
            saving_dir,
            f"performance_metrics_training_{experiment_number}_labels.png",
        )
    )
    plt.close()

    # --- Plot 2: FNR and FPR (log scale) ---
    fig2, ax2 = plt.subplots(figsize=(10, 6))
    ax2.plot(df.index, df["FNR"], label="FNR", color="red")
    ax2.plot(df.index, df["FPR"], label="FPR", color="blue")
    ax2.set_xlabel("Index")
    ax2.set_ylabel("Rate")
    ax2.set_yscale("log")
    ax2.set_title(f"FNR and FPR - Experiment {experiment_number}")
    ax2.legend()
    ax2.yaxis.set_major_locator(ticker.MaxNLocator(100))
    ax2.xaxis.set_major_locator(ticker.MaxNLocator(50))
    plt.tight_layout()
    plt.savefig(
        os.path.join(dir_name, "performance_metrics_training_fnr_fpr.png")
    )
    plt.savefig(
        os.path.join(
            saving_dir,
            f"performance_metrics_training_{experiment_number}_fnr_fpr.png",
        )
    )
    plt.close()

    # --- Plot 3: Other metrics (log scale) ---
    fig3, ax3 = plt.subplots(figsize=(12, 7))
    metrics_rest = [
        "TNR",
        "TPR",
        "F1",
        "Precision",
        "Accuracy",
        "MCC",
        "Recall",
    ]
    colors_rest = [
        "tab:blue",
        "tab:green",
        "tab:purple",
        "tab:brown",
        "tab:gray",
        "tab:pink",
        "tab:olive",
    ]
    for metric, color in zip(metrics_rest, colors_rest):
        ax3.plot(df.index, df[metric], label=metric, color=color)
    ax3.set_xlabel("Index")
    ax3.set_ylabel("Metric Value")
    ax3.set_yscale("log")
    ax3.set_title(
        f"Performance Metrics (except FNR/FPR) - Experiment {experiment_number}"
    )
    ax3.legend()
    ax3.yaxis.set_major_locator(ticker.MaxNLocator(50))
    ax3.xaxis.set_major_locator(ticker.MaxNLocator(50))
    plt.tight_layout()
    plt.savefig(
        os.path.join(
            dir_name, "performance_metrics_training_other_metrics.png"
        )
    )
    plt.savefig(
        os.path.join(
            saving_dir,
            f"performance_metrics_training_{experiment_number}_other_metrics.png",
        )
    )
    plt.close()

    # --- Print final values in terminal and save to file ---
    print("\nFinal values at last training step:")
    final_metrics_path = os.path.join(saving_dir, "final_metrics.txt")
    with open(final_metrics_path, "w") as f:
        for col in [
            "Total labels",
            "Background",
            "Benign",
            "Malicious",
            "FPR",
            "TNR",
            "TPR",
            "FNR",
            "F1",
            "Precision",
            "Accuracy",
            "MCC",
            "Recall",
        ]:
            value = df[col].iloc[-1]
            print(f"{col}: {value}")
            f.write(f"{col}: {value}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Process a log file and plot the data with two y-axes."
    )
    parser.add_argument(
        "-f",
        "--file",
        metavar="log_file",
        type=str,
        required=True,
        help="Path to the log file",
    )
    parser.add_argument(
        "-e",
        "--experiment",
        metavar="experiment_number",
        type=str,
        required=True,
        help="Experiment number to add to the filename",
    )
    args = parser.parse_args()
    plot_log_data(args.file, args.experiment)


if __name__ == "__main__":
    main()
