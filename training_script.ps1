<#
.SYNOPSIS
    Training & testing orchestration script (PowerShell version).
#>



param (
    [Parameter(Mandatory=$true)]
    [int]$dataset_index
)

$ErrorActionPreference = 'Stop'
# ===================== FUNCTIONS =========================

#powershell function!! use native file APIs
function Replace-Line {
    param (
        [string]$Path,
        [int]$LineNumber,
        [string]$NewText
    )

    $lines = Get-Content $Path
    $lines[$LineNumber - 1] = $NewText  # arrays are 0-indexed
    $lines | Set-Content $Path
    Write-Output "Replaced line $LineNumber in '$Path' with: $NewText"
}

# ===================== USER CONFIGURATION =========================

# Meletemodel and scaler before training (only when not using pre-trained model)
$FILE_TO_DELETE_1 = "/path/to/first/tempfile"
$FILE_TO_DELETE_2 = "/path/to/second/tempfile"

# Log directory (will be created if it doesn't exist)
$LOG_DIR = "./performance_metrics/comparison_logs"

# Dataset base directory
$DATASET_DIR = "./dataset-private"
# use datasets 008-015

#line where mode is set in config/slips.yaml
$CONFIG_FILE = "config/slips.yaml"
# Line number in the config file where the mode is set (0-indexed)
$MODE_LINE_NUMBER = 216

# ========================== CHECKS =========================
Write-Host "Running checks..."

if (-not (Test-Path $CONFIG_FILE)) {
    Write-Error "Config file '$CONFIG_FILE' does not exist."
    exit 1
}

$line = (Get-Content $CONFIG_FILE)[$MODE_LINE_NUMBER - 1]
if ($line -notmatch 'mode') {
    Write-Host "Config file '$CONFIG_FILE', line $MODE_LINE_NUMBER does not contain 'mode'."
    Write-Host "Please find the correct line where ML mode is set and update MODE_LINE_NUMBER."
    exit 1
}

# Print script arguments
Write-Host "Script arguments: $($args -join ' ')"

# ===================== SCRIPT STARTS HERE =========================
Write-Host "Starting training script..."

# Find all dataset folders in the directory
# Assuming dataset folders are structured as: private-dataset/<dataset_name>/data
$DATASETS = Get-ChildItem -Directory "$DATASET_DIR" | Where-Object {
    Test-Path (Join-Path $_.FullName 'data')
} | ForEach-Object {
    $_.Name
}

if ($DATASETS.Count -eq 0) {
    Write-Error "No datasets found in $DATASET_DIR"
    exit 1
}

# Validate that exactly one parameter (dataset index) is provided
if ($dataset_index -lt 0 -or $dataset_index -ge $DATASETS.Count) {
    Write-Host "Available datasets:"
    for ($i = 0; $i -lt $DATASETS.Count; $i++) {
        Write-Host "[$i] $($DATASETS[$i])"
    }
    exit 1
}

# Create log directory if not exists
if (-not (Test-Path $LOG_DIR)) {
    New-Item -ItemType Directory -Path $LOG_DIR | Out-Null
}

# Delete the model and scaler
Write-Host "Deleting pre-run files..."
Remove-Item -Path $FILE_TO_DELETE_1, $FILE_TO_DELETE_2 -ErrorAction SilentlyContinue
Write-Host "Deleted: $FILE_TO_DELETE_1, $FILE_TO_DELETE_2"

$TRAIN_FOLDER = $DATASETS[$dataset_index]
$TRAIN_DIR    = Join-Path $DATASET_DIR "$TRAIN_FOLDER/data"
$TRAIN_ID     = $dataset_index
$UNIX_TRAIN_DIR = ($TRAIN_DIR -replace '\\','/') -replace '^([A-Za-z]):', '/$1'.ToLower()

# Generate timestamped logfile name
$TIMESTAMP = Get-Date -Format "dd-MM_HH-mm"
$LOGFILE = "$LOG_DIR/run_on_$TRAIN_FOLDER" + "_$TIMESTAMP.txt"

# Create the logfile (empty or overwrite if exists)
New-Item -Path $LOGFILE -ItemType File -Force | Out-Null

Write-Host "Logging to: $LOGFILE"
"Starting training and testing process..." | Out-File $LOGFILE
"Training on dataset: $TRAIN_FOLDER" | Tee-Object -FilePath $LOGFILE -Append

# make sure we are in training mode
Replace-Line -Path $CONFIG_FILE -LineNumber $MODE_LINE_NUMBER -NewText "  mode: train"

# Run training
"Running training on $TRAIN_DIR" | Tee-Object -FilePath $LOGFILE -Append
try {
    & docker run --rm `
        --network="host" `
        --cap-add=NET_ADMIN `
        --name slips `
        -v "${PWD}:/StratosphereLinuxIPS" `
        slips_image `
        bash -c "python3 -W ignore slips.py -f '$UNIX_TRAIN_DIR'" `
        >> $LOGFILE 2>&1
}
catch {
    Write-Host "Docker training run failed:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    docker rm -f slips 2>$null
    exit 1
}

"Training completed." | Tee-Object -FilePath $LOGFILE -Append
"-----------------------------------------------------" | Out-File -FilePath $LOGFILE -Append
""| Tee-Object -FilePath $LOGFILE -Append
# make sure we are in test mode
Replace-Line -Path $CONFIG_FILE -LineNumber $MODE_LINE_NUMBER -NewText "  mode: test"

# Run testing on all other datasets
foreach ($TEST_FOLDER in $DATASETS) {
    if ($TEST_FOLDER -eq $TRAIN_FOLDER) { continue }

    $TEST_DIR = Join-Path $DATASET_DIR "$TEST_FOLDER/data"
    $UNIX_TEST_DIR = ($TEST_DIR -replace '\\','/') -replace '^([A-Za-z]):', '/$1'.ToLower()
    "----------------------------------------" | Tee-Object -FilePath $LOGFILE -Append
    "Testing on dataset: $TEST_FOLDER"         | Tee-Object -FilePath $LOGFILE -Append
    "Running test on $TEST_DIR"                | Tee-Object -FilePath $LOGFILE -Append

    # run tests here!
    try {
        & docker run --rm `
            --network="host" `
            --cap-add=NET_ADMIN `
            --name slips `
            -v "${PWD}:/StratosphereLinuxIPS" `
            slips_image `
            bash -c "python3 -W ignore slips.py -f '$UNIX_TEST_DIR'" `
            >> $LOGFILE 2>&1
    }
    catch {
        Write-Host "Docker training run failed:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        docker rm -f slips 2>$null
        exit 1
    }
    finally{
        # Clean up the docker container
        docker rm -f slips 2>$null
        Write-Host "Docker container cleaned up."
    }
}

"Training and testing completed." | Tee-Object -FilePath $LOGFILE -Append
