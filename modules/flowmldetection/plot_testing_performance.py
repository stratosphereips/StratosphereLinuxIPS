import argparse
import os

import matplotlib.pyplot as plt
import numpy as np


def process_file(file_path):
    # Initialize the counters for the values
    FPR_values = []
    FNR_values = []
    TNR_values = []
    TPR_values = []
    F1_values = []
    accuracy_values = []
    precision_values = []
    MCC_values = []
    recall_values = []

    # Counters for error tracking
    total_lines = 0
    error_lines = 0
    unusual_lines = 0

    # Read the file and extract the data
    with open(file_path, "r") as file:
        for line in file:
            total_lines += 1
            if "TP:" in line:
                try:
                    # Extract the values from the line
                    parts = line.split(",")
                    TP = int(parts[0].split(":")[1].strip())
                    TN = int(parts[1].split(":")[1].strip())
                    FP = int(parts[2].split(":")[1].strip())
                    FN = int(parts[3].split(":")[1].strip())

                    # Calculate metrics
                    FPR = FP / (FP + TN) if (FP + TN) != 0 else 0
                    FNR = FN / (FN + TP) if (FN + TP) != 0 else 0
                    TNR = TN / (TN + FP) if (TN + FP) != 0 else 0
                    TPR = TP / (TP + FN) if (TP + FN) != 0 else 0
                    Precision = TP / (TP + FP) if (TP + FP) != 0 else 0
                    Recall = TPR  # Recall is the same as TPR
                    F1 = (
                        2 * (Precision * Recall) / (Precision + Recall)
                        if (Precision + Recall) != 0
                        else 0
                    )
                    Accuracy = (
                        (TP + TN) / (TP + TN + FP + FN)
                        if (TP + TN + FP + FN) != 0
                        else 0
                    )
                    MCC = (
                        ((TP * TN) - (FP * FN))
                        / np.sqrt(
                            (TP + FP) * (TP + FN) * (TN + FP) * (TN + FN)
                        )
                        if ((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN)) != 0
                        else 0
                    )

                    # Append the values to the respective lists
                    FPR_values.append(FPR)
                    FNR_values.append(FNR)
                    TNR_values.append(TNR)
                    TPR_values.append(TPR)
                    F1_values.append(F1)
                    accuracy_values.append(Accuracy)
                    precision_values.append(Precision)
                    MCC_values.append(MCC)
                    recall_values.append(Recall)

                except Exception as e:
                    error_lines += 1
                    print(f"Error in line {total_lines}: {e}")
                    continue

                # Check for any unusual cases
                if any(
                    np.isnan(
                        [
                            FPR,
                            FNR,
                            TNR,
                            TPR,
                            F1,
                            Accuracy,
                            Precision,
                            MCC,
                            Recall,
                        ]
                    )
                ):
                    unusual_lines += 1
                    print(
                        f"Unusual values in line {total_lines}: NaN values found"
                    )

    return (
        FPR_values,
        FNR_values,
        TNR_values,
        TPR_values,
        F1_values,
        accuracy_values,
        precision_values,
        MCC_values,
        recall_values,
        total_lines,
        error_lines,
        unusual_lines,
    )


def plot_metrics(
    FPR_values,
    FNR_values,
    TNR_values,
    TPR_values,
    F1_values,
    accuracy_values,
    precision_values,
    MCC_values,
    recall_values,
    experiment_number,
    total_lines,
    error_lines,
    unusual_lines,
    testing_dir,
):
    # Separate the values into two groups based on their proximity to 0 or 1
    close_to_0 = {"FPR": [], "FNR": []}
    close_to_1 = {
        "TNR": [],
        "TPR": [],
        "F1": [],
        "accuracy": [],
        "precision": [],
        "MCC": [],
        "recall": [],
    }

    # Check and create experiment directory inside 'testing'
    experiment_dir = os.path.join(testing_dir, experiment_number)
    if not os.path.exists(experiment_dir):
        os.makedirs(experiment_dir)

    # Categorize the metrics into two groups
    for i in range(len(FPR_values)):
        close_to_0["FPR"].append(FPR_values[i])
        close_to_0["FNR"].append(FNR_values[i])

        close_to_1["TNR"].append(TNR_values[i])
        close_to_1["TPR"].append(TPR_values[i])
        close_to_1["F1"].append(F1_values[i])
        close_to_1["accuracy"].append(accuracy_values[i])
        close_to_1["precision"].append(precision_values[i])
        close_to_1["MCC"].append(MCC_values[i])
        close_to_1["recall"].append(recall_values[i])

    # Plot metrics for values close to 0 (linear scale)
    plot_single_group(
        close_to_0,
        f"metrics_testing_to_0_experiment_{experiment_number}.png",
        experiment_number,
        experiment_dir,
        is_close_to_0=True,
    )

    # Plot metrics for values close to 1 (log scale)
    plot_single_group(
        close_to_1,
        f"metrics_testing_to_1_experiment_{experiment_number}.png",
        experiment_number,
        experiment_dir,
        is_close_to_0=False,
    )

    # Print the final values
    print("\nFinal Metric Values for Experiment", experiment_number)
    print(f"Final FPR: {FPR_values[-1]:.4f}")
    print(f"Final FNR: {FNR_values[-1]:.4f}")
    print(f"Final TNR: {TNR_values[-1]:.4f}")
    print(f"Final TPR: {TPR_values[-1]:.4f}")
    print(f"Final F1 Score: {F1_values[-1]:.4f}")
    print(f"Final Accuracy: {accuracy_values[-1]:.4f}")
    print(f"Final Precision: {precision_values[-1]:.4f}")
    print(f"Final MCC: {MCC_values[-1]:.4f}")
    print(f"Final Recall: {recall_values[-1]:.4f}")

    # Print summary statistics
    print(f"\nSummary for Experiment {experiment_number}:")
    print(f"Total lines read: {total_lines}")
    print(f"Lines with errors: {error_lines}")
    print(f"Unusual lines (NaN values): {unusual_lines}")

    # Save statistics to file (the same statistics)
    stats_path = os.path.join(experiment_dir, "final_metrics.txt")
    with open(stats_path, "w") as f:
        f.write(f"Final Metric Values for Experiment {experiment_number}\n")
        f.write(f"Final FPR: {FPR_values[-1]:.4f}\n")
        f.write(f"Final FNR: {FNR_values[-1]:.4f}\n")
        f.write(f"Final TNR: {TNR_values[-1]:.4f}\n")
        f.write(f"Final TPR: {TPR_values[-1]:.4f}\n")
        f.write(f"Final F1 Score: {F1_values[-1]:.4f}\n")
        f.write(f"Final Accuracy: {accuracy_values[-1]:.4f}\n")
        f.write(f"Final Precision: {precision_values[-1]:.4f}\n")
        f.write(f"Final MCC: {MCC_values[-1]:.4f}\n")
        f.write(f"Final Recall: {recall_values[-1]:.4f}\n\n")
        f.write(f"Summary for Experiment {experiment_number}:\n")
        f.write(f"Total lines read: {total_lines}\n")
        f.write(f"Lines with errors: {error_lines}\n")
        f.write(f"Unusual lines (NaN values): {unusual_lines}\n")


def plot_single_group(
    metrics_dict,
    output_filename,
    experiment_number,
    experiment_dir,
    is_close_to_0=False,
):
    plt.figure(figsize=(12, 8))

    output_filename = os.path.join(experiment_dir, output_filename)

    # Only plot the metrics that exist in the dictionary
    if "FPR" in metrics_dict:
        plt.plot(
            metrics_dict["FPR"], label="False Positive Rate (FPR)", marker="o"
        )
    if "FNR" in metrics_dict:
        plt.plot(
            metrics_dict["FNR"], label="False Negative Rate (FNR)", marker="o"
        )
    if "TNR" in metrics_dict:
        plt.plot(
            metrics_dict["TNR"], label="True Negative Rate (TNR)", marker="o"
        )
    if "TPR" in metrics_dict:
        plt.plot(
            metrics_dict["TPR"], label="True Positive Rate (TPR)", marker="o"
        )
    if "F1" in metrics_dict:
        plt.plot(metrics_dict["F1"], label="F1 Score", marker="o")
    if "accuracy" in metrics_dict:
        plt.plot(metrics_dict["accuracy"], label="Accuracy", marker="o")
    if "precision" in metrics_dict:
        plt.plot(metrics_dict["precision"], label="Precision", marker="o")
    if "MCC" in metrics_dict:
        plt.plot(
            metrics_dict["MCC"],
            label="Matthews Correlation Coefficient (MCC)",
            marker="o",
        )
    if "recall" in metrics_dict:
        plt.plot(metrics_dict["recall"], label="Recall (TPR)", marker="o")

    # If the plot is close to 1, apply log scale
    if not is_close_to_0:
        plt.yscale("log")

    # If the plot is close to 0, set dynamic Y-ticks based on the min/max values of the series
    if is_close_to_0:
        min_val = min(min(metrics_dict["FPR"]), min(metrics_dict["FNR"]))
        max_val = max(max(metrics_dict["FPR"]), max(metrics_dict["FNR"]))

        # Avoid log(0), so set the minimum limit a little higher than zero
        if min_val == 0:
            min_val = 1e-4  # Avoid zero values on the logarithmic scale

        plt.ylim(min_val, max_val)  # Set Y-axis limits based on the data range
        # Ensure ticks are within the valid range
        if min_val > 0 and max_val > 0:
            plt.yticks(
                np.logspace(np.log10(min_val), np.log10(max_val), num=6)
            )  # Set ticks logarithmically

    # Add the experiment number to the plot title
    plt.xlabel("Index")
    plt.ylabel("Metric Value")
    plt.title(f"Experiment {experiment_number} - Evaluation Metrics Over Time")
    plt.legend()

    # Save the plot
    plt.savefig(output_filename)
    plt.close()


def main():

    # Set up argument parsing
    parser = argparse.ArgumentParser(
        description="Plot testing performance metrics."
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        required=True,
        help="Path to the testing performance log file",
    )
    parser.add_argument(
        "-e", "--experiment", type=str, required=True, help="Experiment number"
    )

    args = parser.parse_args()

    file_path = args.file
    experiment_number = args.experiment

    # Check and create 'performance_metrics' directory if it doesn't exist
    base_dir = "performance_metrics"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    # Check and create 'testing' directory inside 'performance_metrics'
    testing_dir = os.path.join(base_dir, "testing")
    if not os.path.exists(testing_dir):
        os.makedirs(testing_dir)

    (
        FPR_values,
        FNR_values,
        TNR_values,
        TPR_values,
        F1_values,
        accuracy_values,
        precision_values,
        MCC_values,
        recall_values,
        total_lines,
        error_lines,
        unusual_lines,
    ) = process_file(file_path)
    plot_metrics(
        FPR_values,
        FNR_values,
        TNR_values,
        TPR_values,
        F1_values,
        accuracy_values,
        precision_values,
        MCC_values,
        recall_values,
        experiment_number,
        total_lines,
        error_lines,
        unusual_lines,
        testing_dir,
    )


if __name__ == "__main__":
    main()
