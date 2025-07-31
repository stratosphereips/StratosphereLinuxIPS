#!/usr/bin/env bash
#
# Training & testing orchestration script (Bash version).
#

set -euo pipefail
IFS=$'\n\t'

# ===================== FUNCTIONS =========================

# bash function!! use sed for in-place line replacement
function Replace-Line {
    local Path="$1"
    local LineNumber="$2"
    local NewText="$3"
    # sed uses 1-based line numbers
    sed -i "${LineNumber}s/.*/${NewText//\//\\/}/" "$Path"
    echo "Replaced line $LineNumber in '$Path' with: $NewText"
}

# Cleanup handler: always remove any running 'slips' container
function cleanup {
    echo "Cleaning up any running slips container…" >&2
    docker rm -f slips >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ===================== USER CONFIGURATION =========================

# Meletemodel and scaler before training (only when not using pre-trained model)
FILE_TO_DELETE_1="/path/to/first/tempfile"
FILE_TO_DELETE_2="/path/to/second/tempfile"

# Log directory (will be created if it doesn't exist)
LOG_DIR="./performance_metrics/comparison_logs"

# Dataset base directory
DATASET_DIR="./dataset-private"
# use datasets 008-015

# config file & mode line
CONFIG_FILE="config/slips.yaml"
MODE_LINE_NUMBER=216   # 1-based line number in YAML

# ========================== CHECKS =========================
echo "Running checks..."

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file '$CONFIG_FILE' does not exist." >&2
    exit 1
fi

current_line=$(sed -n "${MODE_LINE_NUMBER}p" "$CONFIG_FILE")
if [[ "$current_line" != *mode* ]]; then
    echo "Error: Line $MODE_LINE_NUMBER in '$CONFIG_FILE' does not contain 'mode'." >&2
    echo "Please update MODE_LINE_NUMBER to the correct line." >&2
    exit 1
fi

# Print script arguments
echo "Script arguments: $*"

# ===================== SCRIPT STARTS HERE =========================
echo "Starting training script..."

# Collect all dataset folder names (must contain a 'data' subdir)
DATASETS=()
while IFS= read -r -d '' dir; do
    DATASETS+=("$(basename "$(dirname "$dir")")")
done < <(find "$DATASET_DIR" -maxdepth 2 -type d -name data -print0)

if [ "${#DATASETS[@]}" -eq 0 ]; then
    echo "Error: No datasets found in '$DATASET_DIR'." >&2
    exit 1
fi

# Validate parameter count
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <dataset_index>" >&2
    echo "Available datasets:" >&2
    for i in "${!DATASETS[@]}"; do
        echo "  [$i] ${DATASETS[$i]}" >&2
    done
    exit 1
fi

choice="$1"
if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -ge "${#DATASETS[@]}" ]; then
    echo "Error: Invalid dataset index '$choice'." >&2
    exit 1
fi

# Create log directory if needed
mkdir -p "$LOG_DIR"

# Delete pre-run files
echo "Deleting pre-run files..."
rm -f "$FILE_TO_DELETE_1" "$FILE_TO_DELETE_2"
echo "Deleted: $FILE_TO_DELETE_1, $FILE_TO_DELETE_2"

TRAIN_FOLDER="${DATASETS[$choice]}"
TRAIN_DIR="$DATASET_DIR/$TRAIN_FOLDER/data"

TIMESTAMP=$(date +"%d-%m_%H-%M")
LOGFILE="$LOG_DIR/run_on_${TRAIN_FOLDER}_${TIMESTAMP}.txt"

# Start logfile
echo "Logging to: $LOGFILE"
echo "Starting training and testing process..." >"$LOGFILE"
echo "Training on dataset: $TRAIN_FOLDER" >>"$LOGFILE"

# ensure training mode in config
Replace-Line "$CONFIG_FILE" "$MODE_LINE_NUMBER" "  mode: train"

# Run training
echo "Running training on $TRAIN_DIR" >>"$LOGFILE"
if ! docker run --rm \
        --network host \
        --cap-add NET_ADMIN \
        --name slips \
        -v "${PWD}:/StratosphereLinuxIPS" \
        slips_image \
        python3 slips.py -f "/StratosphereLinuxIPS/$TRAIN_DIR" \
        >>"$LOGFILE" 2>&1; then
    echo "Docker training run failed. See log for details." >&2
    exit 1
fi
echo "Training completed." >>"$LOGFILE"
echo "-----------------------------------------------------" >>"$LOGFILE"
echo "" >>"$LOGFILE"

# ensure test mode in config
Replace-Line "$CONFIG_FILE" "$MODE_LINE_NUMBER" "  mode: test"

# Run testing on all other datasets
for TEST_FOLDER in "${DATASETS[@]}"; do
    if [ "$TEST_FOLDER" == "$TRAIN_FOLDER" ]; then
        continue
    fi

    TEST_DIR="$DATASET_DIR/$TEST_FOLDER/data"
    echo "----------------------------------------" >>"$LOGFILE"
    echo "Testing on dataset: $TEST_FOLDER" >>"$LOGFILE"
    echo "Running test on $TEST_DIR" >>"$LOGFILE"

    if ! docker run --rm \
            --network host \
            --cap-add NET_ADMIN \
            --name slips \
            -v "${PWD}:/StratosphereLinuxIPS" \
            slips_image \
            python3 slips.py -f "/StratosphereLinuxIPS/$TEST_DIR" \
            >>"$LOGFILE" 2>&1; then
        echo "Docker test run failed for $TEST_FOLDER. See log for details." >&2
        exit 1
    fi
done

echo "Training and testing completed." >>"$LOGFILE"
