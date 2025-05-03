import pandas as pd
import matplotlib.pyplot as plt
import re
import sys
import argparse
import os

def plot_log_data(file_path, experiment_number):
    # Read the log data from the file
    with open(file_path, 'r') as file:
        log_data = file.read()

    # Define regex pattern to extract relevant data from each line
    pattern = r"Background: (\d+). Benign: (\d+). Malicious: (\d+). Total labels: (\d+\.\d+). Score: (\d+\.\d+)"

    # Parse the log file
    data = re.findall(pattern, log_data)

    # Convert data to a DataFrame
    df = pd.DataFrame(data, columns=["Background", "Benign", "Malicious", "Total labels", "Score"])
    df = df.astype({
        "Background": int,
        "Benign": int,
        "Malicious": int,
        "Total labels": float,
        "Score": float
    })

    # Get the directory of the log file to store the plot in the same folder
    dir_name = os.path.dirname(file_path)
    # Append experiment number to the filename
    plot_file = os.path.join(dir_name, f'performance_metrics_training_{experiment_number}.png')

    # Plotting the values
    fig, ax1 = plt.subplots(figsize=(10, 6))

    # Plotting Score on the left y-axis (with proper scaling from 0 to 1)
    ax1.plot(df.index, df["Score"], label="Score", color='tab:blue')
    ax1.set_xlabel('Index')
    ax1.set_ylabel('Score', color='tab:blue')
    ax1.set_ylim(0, 1)  # Set y-axis for Score from 0 to 1
    ax1.tick_params(axis='y', labelcolor='tab:blue')

    # Create the second y-axis for the Background, Benign, Malicious
    ax2 = ax1.twinx()
    ax2.plot(df.index, df["Background"], label="Background Labels", color='tab:green', linestyle='--')
    ax2.plot(df.index, df["Benign"], label="Benign Labels", color='tab:orange', linestyle='--')
    ax2.plot(df.index, df["Malicious"], label="Malicious Labels", color='tab:pink', linestyle='--')
    ax2.set_ylabel('Background, Benign, Malicious Labels', color='tab:red')
    
    # Set appropriate scale for right y-axis based on the data
    ax2.set_ylim(0, df[["Background", "Benign", "Malicious"]].max().max())
    ax2.tick_params(axis='y', labelcolor='tab:red')

    # Annotating Total labels as text on the plot
    for i, value in enumerate(df["Total labels"]):
        ax1.text(i, value, f'{value:.1f}', color='tab:gray', fontsize=8, ha='center', va='bottom')

    # Adding title and legend with experiment number in title
    plt.title(f'Training performance - Experiment {experiment_number}')
    fig.tight_layout()

    # Move both legends further to the right
    ax1.legend(loc='upper right', bbox_to_anchor=(1.3, 1), fontsize='small', ncol=1)
    ax2.legend(loc='upper right', bbox_to_anchor=(1.3, 0.85), fontsize='small', ncol=1)

    # Increase right margin for better readability of legend
    plt.subplots_adjust(right=0.75)

    # Save plot to the same folder as the log file with experiment number in filename
    plt.savefig(plot_file)

    # Display the plot
    plt.show()

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Process a log file and plot the data with two y-axes.")
    parser.add_argument('-f', '--file', metavar='log_file', type=str, required=True, help="Path to the log file")
    parser.add_argument('-e', '--experiment', metavar='experiment_number', type=str, required=True, help="Experiment number to add to the filename")
    
    # Handle -h / --help
    args = parser.parse_args()

    # Call the function to process the log file
    plot_log_data(args.file, args.experiment)

if __name__ == "__main__":
    main()
