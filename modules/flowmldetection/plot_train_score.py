import pandas as pd
import matplotlib.pyplot as plt
import re
import sys

def plot_log_data(file_path):
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

    # Plotting the values
    fig, ax1 = plt.subplots(figsize=(10, 6))

    # Plotting Score on the left y-axis
    ax1.plot(df.index, df["Score"], label="Score", color='tab:blue')
    ax1.set_xlabel('Index')
    ax1.set_ylabel('Score', color='tab:blue')
    ax1.tick_params(axis='y', labelcolor='tab:blue')

    # Create the second y-axis for the Total labels
    ax2 = ax1.twinx()
    ax2.plot(df.index, df["Total labels"], label="Total labels", color='tab:red')
    ax2.set_ylabel('Total labels', color='tab:red')
    ax2.tick_params(axis='y', labelcolor='tab:red')

    # Adding title and legend
    plt.title('Log Data Visualization')
    fig.tight_layout()

    # Save plot to a PNG file
    plt.savefig('log_data_plot_with_two_scales.png')

    # Display the plot
    plt.show()

# Make sure the file path is passed as an argument
if len(sys.argv) < 2:
    print("Please provide the path to the log file as a parameter.")
else:
    plot_log_data(sys.argv[1])
