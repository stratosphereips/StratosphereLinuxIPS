import pandas as pd
import matplotlib.pyplot as plt
import re
import sys
import argparse
import os
import matplotlib.ticker as ticker

def plot_log_data(file_path, experiment_number):
    # Read the log data from the file
    with open(file_path, 'r') as file:
        log_data = file.read()

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
        "Total labels", "Background", "Benign", "Malicious",
        "FPR", "TNR", "TPR", "FNR", "F1", "Precision", "Accuracy", "MCC", "Recall"
    ]
    df = pd.DataFrame(data, columns=columns)
    df = df.astype({
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
    })

    dir_name = os.path.dirname(file_path)

    # --- Plot 1: Number of labels (linear scale, no total labels) ---
    fig1, ax1 = plt.subplots(figsize=(10, 6))
    ax1.plot(df.index, df["Background"], label="Background", color='black')
    ax1.plot(df.index, df["Benign"], label="Benign", color='cyan')
    ax1.plot(df.index, df["Malicious"], label="Malicious", color='magenta')
    ax1.set_xlabel('Index')
    ax1.set_ylabel('Label Counts')
    # No log scale here
    ax1.set_title(f'Label Counts - Experiment {experiment_number}')
    ax1.legend()
    ax1.yaxis.set_major_locator(ticker.MaxNLocator(70))
    plt.tight_layout()
    plt.savefig(os.path.join(dir_name, f'performance_metrics_training_0_labels.png'))

    # --- Plot 2: FNR and FPR (log scale) ---
    fig2, ax2 = plt.subplots(figsize=(10, 6))
    ax2.plot(df.index, df["FNR"], label="FNR", color='red')
    ax2.plot(df.index, df["FPR"], label="FPR", color='blue')
    ax2.set_xlabel('Index')
    ax2.set_ylabel('Rate')
    ax2.set_yscale('log')
    ax2.set_title(f'FNR and FPR - Experiment {experiment_number}')
    ax2.legend()
    ax2.yaxis.set_major_locator(ticker.MaxNLocator(100))
    plt.tight_layout()
    plt.savefig(os.path.join(dir_name, f'performance_metrics_training_0_fnr_fpr.png'))

    # --- Plot 3: Other metrics (log scale) ---
    fig3, ax3 = plt.subplots(figsize=(12, 7))
    metrics_rest = ["TNR", "TPR", "F1", "Precision", "Accuracy", "MCC", "Recall"]
    colors_rest = [
        'tab:blue', 'tab:green', 'tab:purple', 'tab:brown',
        'tab:gray', 'tab:pink', 'tab:olive'
    ]
    for metric, color in zip(metrics_rest, colors_rest):
        ax3.plot(df.index, df[metric], label=metric, color=color)
    ax3.set_xlabel('Index')
    ax3.set_ylabel('Metric Value')
    ax3.set_yscale('log')
    ax3.set_title(f'Performance Metrics (except FNR/FPR) - Experiment {experiment_number}')
    ax3.legend()
    ax3.yaxis.set_major_locator(ticker.MaxNLocator(50))
    plt.tight_layout()
    plt.savefig(os.path.join(dir_name, f'performance_metrics_training_0_other_metrics.png'))

    plt.show()

    # --- Print final values in terminal ---
    print("\nFinal values at last training step:")
    for col in ["Total labels", "Background", "Benign", "Malicious",
                "FPR", "TNR", "TPR", "FNR", "F1", "Precision", "Accuracy", "MCC", "Recall"]:
        print(f"{col}: {df[col].iloc[-1]}")

def main():
    parser = argparse.ArgumentParser(description="Process a log file and plot the data with two y-axes.")
    parser.add_argument('-f', '--file', metavar='log_file', type=str, required=True, help="Path to the log file")
    parser.add_argument('-e', '--experiment', metavar='experiment_number', type=str, required=True, help="Experiment number to add to the filename")
    args = parser.parse_args()
    plot_log_data(args.file, args.experiment)

if __name__ == "__main__":
    main()
