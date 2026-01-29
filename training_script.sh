#!/usr/bin/env bash

# =========================================================
# Training & testing orchestration script (Bash version)
# =========================================================

set -e  # exit immediately if a command exits with a non-zero status
set -o pipefail

# ======== PARAMETERS ========
if [ $# -lt 1 ]; then
    echo "Usage: $0 <dataset_index>"
    exit 1
fi
dataset_index="$1"

# ======== FUNCTIONS ========
replace_line() {
    local file_path="$1"
    local line_number="$2"
    local new_text="$3"

    if [ ! -f "$file_path" ]; then
        echo "File '$file_path' not found!"
        exit 1
    fi

    # sed is 1-indexed for line numbers
    sed -i "${line_number}s|.*|${new_text}|" "$file_path"
    echo "Replaced line $line_number in '$file_path' with: $new_text"
}

cleanup_docker() {
    docker rm -f jan_slips >/dev/null 2>&1 || true
}

trap cleanup_docker EXIT

# ===================== USER CONFIGURATION =========================
FILE_TO_DELETE_1="./modules/flowmldetection/model.bin"
FILE_TO_DELETE_2="./modules/flowmldetection/scaler.bin"

LOG_DIR="./performance_metrics/comparison_logs"
DATASET_DIR="./dataset-private"

CONFIG_FILE="config/slips.yaml"
MODE_LINE_NUMBER=216  # 1-indexed for sed

# Create log directory if it does not exist
if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
    echo "Created log directory: $LOG_DIR"
fi

# ========================== CHECKS =========================
echo "Running checks..."

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Config file '$CONFIG_FILE' does not exist." >&2
    exit 1
fi

line=$(sed -n "${MODE_LINE_NUMBER}p" "$CONFIG_FILE")
if [[ "$line" != *mode* ]]; then
    echo "Config file '$CONFIG_FILE', line $MODE_LINE_NUMBER does not contain 'mode'."
    echo "Please find the correct line where ML mode is set and update MODE_LINE_NUMBER."
    exit 1
fi

# Print script arguments
echo "Script arguments: $*"

# ===================== SCRIPT STARTS HERE =========================
echo "Starting training script..."

# Find dataset folders with 'data' subdir
mapfile -t DATASETS < <(find "$DATASET_DIR" -mindepth 1 -maxdepth 1 -type d \
    -exec test -d "{}/data" \; -print | xargs -n1 basename | sort)

if [ ${#DATASETS[@]} -eq 0 ]; then
    echo "No datasets found in $DATASET_DIR" >&2
    exit 1
fi

if [ "$dataset_index" -lt 0 ] || [ "$dataset_index" -ge "${#DATASETS[@]}" ]; then
    echo "Available datasets:"
    for i in "${!DATASETS[@]}"; do
        echo "[$i] ${DATASETS[$i]}"
    done
    exit 1
fi

# Create log directory if not exists
mkdir -p "$LOG_DIR"

# Delete model and scaler
echo "Deleting pre-run files..."
for file in "$FILE_TO_DELETE_1" "$FILE_TO_DELETE_2"; do
    if [ -f "$file" ]; then
        rm -f "$file"
        echo "Deleted: $file"
    else
        echo "Warning: $file does not exist, skipping deletion."
    fi
done

TRAIN_FOLDER="${DATASETS[$dataset_index]}"
TRAIN_DIR="$DATASET_DIR/$TRAIN_FOLDER/data"
TRAIN_ID="$dataset_index"

# Generate timestamped logfile name
TIMESTAMP=$(date +"%d-%m_%H-%M")
LOGFILE="$LOG_DIR/run_on_${TRAIN_FOLDER}_${TIMESTAMP}.txt"

# Create/overwrite logfile
: > "$LOGFILE"

echo "Logging to: $LOGFILE"
echo "Starting training and testing process..." >> "$LOGFILE"
echo "Training on dataset: $TRAIN_FOLDER" | tee -a "$LOGFILE"

# Set mode to train
replace_line "$CONFIG_FILE" "$MODE_LINE_NUMBER" "  mode: train"

# Run training
echo "Running training on $TRAIN_DIR" | tee -a "$LOGFILE"
if ! docker run --rm \
        -v "${PWD}:/StratosphereLinuxIPS" \
        --name jan_slips \
        --net=host \
        --cpu-shares 700 \
        --memory=8g \
        --memory-swap=8g \
        --shm-size=512m \
     stratosphereips/slips:latest bash -c "python3 -W ignore slips.py -f '$TRAIN_DIR' -m " \
        >> "$LOGFILE" 2>&1; then
    echo "Docker training run failed:" >&2
    cleanup_docker #TODO return to -m when solved
    exit 1
fi

# After training, run the training performance plotting script on the latest slips output logfile
LATEST_SLIPS_LOG=$(ls -1t ./output/ | head -n1)
TRAIN_NUMBER=$(($TRAIN_ID+8)) # adjust to start at 008, which is our first dataset
TRAIN_ID_PADDED=$(printf "%03d" "$TRAIN_NUMBER")
if [ -n "$LATEST_SLIPS_LOG" ]; then
    python3 ./modules/flowmldetection/plot_train_performance.py \
        -f "./output/$LATEST_SLIPS_LOG" \
        -e "train_${TRAIN_ID_PADDED}"
else
    echo "Warning: No slips output logfile found in ./output/ after training." | tee -a "$LOGFILE"
fi

# Copy model and scaler with dataset identifier (do not delete originals)
MODEL_DEST="./modules/flowmldetection/model_${TRAIN_ID_PADDED}.bin"
SCALER_DEST="./modules/flowmldetection/scaler_${TRAIN_ID_PADDED}.bin"

if [ -f "$FILE_TO_DELETE_1" ]; then
    cp "$FILE_TO_DELETE_1" "$MODEL_DEST"
    echo "Copied $FILE_TO_DELETE_1 to $MODEL_DEST" | tee -a "$LOGFILE"
else
    echo "Warning: $FILE_TO_DELETE_1 not found after training." | tee -a "$LOGFILE"
fi

if [ -f "$FILE_TO_DELETE_2" ]; then
    cp "$FILE_TO_DELETE_2" "$SCALER_DEST"
    echo "Copied $FILE_TO_DELETE_2 to $SCALER_DEST" | tee -a "$LOGFILE"
else
    echo "Warning: $FILE_TO_DELETE_2 not found after training." | tee -a "$LOGFILE"
fi

echo "Training completed." | tee -a "$LOGFILE"
echo "-----------------------------------------------------" >> "$LOGFILE"
echo "" | tee -a "$LOGFILE"

# Set mode to test
replace_line "$CONFIG_FILE" "$MODE_LINE_NUMBER" "  mode: test"

# Run testing on all datasets
for TEST_INDEX in "${!DATASETS[@]}"; do
    TEST_FOLDER="${DATASETS[$TEST_INDEX]}"
    TEST_DIR="$DATASET_DIR/$TEST_FOLDER/data"

    echo "----------------------------------------" | tee -a "$LOGFILE"
    echo "Testing on dataset: $TEST_FOLDER" | tee -a "$LOGFILE"
    echo "Running test on $TEST_DIR" | tee -a "$LOGFILE"

    if ! docker run --rm \
            -v "${PWD}:/StratosphereLinuxIPS" \
            --name jan_slips \
            --net=host \
            --cpu-shares 700 \
            --memory=8g \
            --memory-swap=8g \
            --shm-size=512m \
            stratosphereips/slips:latest bash -c "python3 -W ignore slips.py -f '$TEST_DIR'-m" \
            >> "$LOGFILE" 2>&1; then
        echo "Docker testing run failed:" >&2
        cleanup_docker # TODO return to -m when fixed
        exit 1
    fi

    # After each test, run the plotting script on the latest slips output logfile
    TRAIN_ID_PADDED=$(printf "%03d" "$TRAIN_NUMBER")

    TEST_NUMBER=$(($TEST_INDEX+8)) #adjust to start at 008, which is our first dataset
    TEST_ID_PADDED=$(printf "%03d" "$TEST_NUMBER")
    LATEST_SLIPS_LOG=$(ls -1t ./output/ | head -n1)
    if [ -n "$LATEST_SLIPS_LOG" ]; then
        python3 ./modules/flowmldetection/plot_testing_performance.py \
            -f "./output/$LATEST_SLIPS_LOG" \
            -e "${TRAIN_ID_PADDED}_test_${TEST_ID_PADDED}"
    else
        echo "Warning: No slips output logfile found in ./output/ after testing $TEST_FOLDER." | tee -a "$LOGFILE"
    fi
done

echo "Docker container cleaned up."
echo "Training and testing completed." | tee -a "$LOGFILE"
