#!/bin/bash

# ===================== USER CONFIGURATION =========================

# Meletemodel and scaler before training (only when not using pre-trained model)
FILE_TO_DELETE_1="/path/to/first/tempfile"
FILE_TO_DELETE_2="/path/to/second/tempfile"

# Log directory (will be created if it doesn't exist)
LOG_DIR="comparison_logs"

# Dataset base directory
DATASET_DIR="private-dataset"
# use datasets 008-015

# ==================================================================

# Print script arguments
echo "Script arguments: $@"

# Validate that exactly one parameter (dataset index) is provided
if [ "$#" -ne 1 ]; then
    echo "Error: Exactly one parameter (dataset index) is required."
    echo "Usage: $0 <dataset_index>"
    exit 1
fi

# Check if the dataset directory exists
if [ ! -d "$DATASET_DIR" ]; then
    echo "Error: Dataset directory '$DATASET_DIR' does not exist."
    exit 1
fi

# Find all dataset folders in the directory
# Assuming dataset folders are structured as: private-dataset/<dataset_name>/data
DATASETS=()
for dir in "$DATASET_DIR"/*/data; do
    folder=$(basename "$(dirname "$dir")")
    DATASETS+=("$folder")
done

if [ ${#DATASETS[@]} -eq 0 ]; then
    echo "No datasets found in $DATASET_DIR"
    exit 1
fi

# Check for required argument: dataset index
if [ -z "$1" ]; then
    echo "Available datasets:"
    for i in "${!DATASETS[@]}"; do
        echo "[$i] ${DATASETS[$i]}"
    done
    exit 1
fi

choice=$1

if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -ge "${#DATASETS[@]}" ]; then
    echo "Invalid choice: $choice"
    exit 1
fi

# Create log directory if not exists
mkdir -p "$LOG_DIR"

# Delete the model and scaler
echo "Deleting pre-run files..."
rm -f "$FILE_TO_DELETE_1" "$FILE_TO_DELETE_2"
echo "Deleted: $FILE_TO_DELETE_1, $FILE_TO_DELETE_2"

TRAIN_FOLDER="${DATASETS[$choice]}"
TRAIN_DIR="$DATASET_DIR/$TRAIN_FOLDER/data"
TRAIN_ID=$choice


# Generate timestamped logfile name
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOGFILE="${LOG_DIR}/log_${TRAIN_ID}_${TIMESTAMP}"

echo "Logging to: $LOGFILE"
echo "Starting training and testing process..." > "$LOGFILE"
echo "Training on dataset: $TRAIN_FOLDER" | tee -a "$LOGFILE"

# Run training
echo "Running training on $TRAIN_DIR" | tee -a "$LOGFILE"
# TODO: run whole cmd here! "$TRAIN_DIR" >> "$LOGFILE" 2>&1

# Run testing on all other datasets
for TEST_FOLDER in "${DATASETS[@]}"; do
    if [[ "$TEST_FOLDER" == "$TRAIN_FOLDER" ]]; then
        continue
    fi

    TEST_DIR="$DATASET_DIR/$TEST_FOLDER/data"
    echo "----------------------------------------" | tee -a "$LOGFILE"
    echo "Testing on dataset: $TEST_FOLDER" | tee -a "$LOGFILE"
    echo "Running test on $TEST_DIR" | tee -a "$LOGFILE"
    # TODO: testing command here! "$TEST_DIR" >> "$LOGFILE" 2>&1
done

echo "Training and testing completed." | tee -a "$LOGFILE"
