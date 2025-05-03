import matplotlib.pyplot as plt
import sys
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
    
    # Read the file and extract the data
    with open(file_path, 'r') as file:
        for line in file:
            if "TP:" in line:
                # Extract the values from the line
                parts = line.split(',')
                TP = int(parts[0].split(':')[1].strip())
                TN = int(parts[1].split(':')[1].strip())
                FP = int(parts[2].split(':')[1].strip())
                FN = int(parts[3].split(':')[1].strip())

                # Calculate metrics
                FPR = FP / (FP + TN) if (FP + TN) != 0 else 0
                FNR = FN / (FN + TP) if (FN + TP) != 0 else 0
                TNR = TN / (TN + FP) if (TN + FP) != 0 else 0
                TPR = TP / (TP + FN) if (TP + FN) != 0 else 0
                Precision = TP / (TP + FP) if (TP + FP) != 0 else 0
                Recall = TPR  # Recall is the same as TPR
                F1 = 2 * (Precision * Recall) / (Precision + Recall) if (Precision + Recall) != 0 else 0
                Accuracy = (TP + TN) / (TP + TN + FP + FN)
                MCC = ((TP * TN) - (FP * FN)) / np.sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN)) if ((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN)) != 0 else 0
                
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
    
    return FPR_values, FNR_values, TNR_values, TPR_values, F1_values, accuracy_values, precision_values, MCC_values, recall_values

def plot_metrics(FPR_values, FNR_values, TNR_values, TPR_values, F1_values, accuracy_values, precision_values, MCC_values, recall_values):
    # Create the plot
    plt.figure(figsize=(12, 8))
    
    # Plot each metric
    plt.plot(FPR_values, label='False Positive Rate (FPR)', marker='o')
    plt.plot(FNR_values, label='False Negative Rate (FNR)', marker='o')
    plt.plot(TNR_values, label='True Negative Rate (TNR)', marker='o')
    plt.plot(TPR_values, label='True Positive Rate (TPR)', marker='o')
    plt.plot(F1_values, label='F1 Score', marker='o')
    plt.plot(accuracy_values, label='Accuracy', marker='o')
    plt.plot(precision_values, label='Precision', marker='o')
    plt.plot(MCC_values, label='Matthews Correlation Coefficient (MCC)', marker='o')
    plt.plot(recall_values, label='Recall (TPR)', marker='o')
    
    # Set logarithmic scale on the y-axis
    plt.yscale('log')
    
    # Add labels and title
    plt.xlabel('Index')
    plt.ylabel('Metric Value (Log Scale)')
    plt.title('Evaluation Metrics Over Time (Log Scale)')
    
    # Add a legend
    plt.legend()
    
    # Save the plot as a PNG file
    plt.savefig('metrics_plot_log_scale.png')
    plt.close()

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    FPR_values, FNR_values, TNR_values, TPR_values, F1_values, accuracy_values, precision_values, MCC_values, recall_values = process_file(file_path)
    plot_metrics(FPR_values, FNR_values, TNR_values, TPR_values, F1_values, accuracy_values, precision_values, MCC_values, recall_values)

if __name__ == "__main__":
    main()
