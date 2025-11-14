#!/usr/bin/env bash
set -euo pipefail

WIFI_IF="${WIFI_IF}"
ETH_IF="${ETH_IF}"
CWD="${CWD}"
OUTPUT_DIR="$CWD/output"
CONFIG_DIR="$CWD/config"
CONTAINER_NAME="${CONTAINER_NAME:-slips}"
DOCKER_IMAGE="${DOCKER_IMAGE:-stratosphereips/slips:latest}"
LOG_FILE="${LOG_FILE}"

log() { printf "%b\n" "$(date -Iseconds) - $*" | tee -a "$LOG_FILE"; }

remove_existing_container() {
  if docker ps -a --format '{{.Names}}' | grep -xq "$CONTAINER_NAME"; then
    log "Container '$CONTAINER_NAME' already exists."
    read -rp "Delete it? (y/n): " answer
    case "$answer" in
      [Yy]*) docker rm -f "$CONTAINER_NAME" || true ;;
      *) log "Aborted."; exit 1 ;;
    esac
  fi
}

kill_ap_process() {
  PATTERN="create_ap.*\b$WIFI_IF\b.*\b$ETH_IF\b"
  log "Killing create_ap processes matching: $PATTERN"
  pids=$(ps -ef | grep -E "$PATTERN" | grep -v grep | awk '{print $2}' || true)
  [ -n "$pids" ] && kill -TERM $pids || log "No AP processes found."
}

main() {
  log "=== Slips Runner Started ==="

  remove_existing_container

  docker_cmd=(
    docker run -d -it --rm
    -v "$OUTPUT_DIR":/StratosphereLinuxIPS/output/
    # -v "$CONFIG_DIR":/StratosphereLinuxIPS/config/
    --name "$CONTAINER_NAME"
    --net=host
    --cpu-shares 700
    --memory 8g
    --memory-swap 8g
    --shm-size 512m
    "$DOCKER_IMAGE"
    bash -c "tmux new -s slips './slips.py -ap $WIFI_IF,$ETH_IF'"
  )

  log "Starting Slips container using command: ${docker_cmd[*]}"

  # Execute
  container_id=$("${docker_cmd[@]}")

  log "Container started: $container_id"

  while docker ps --format '{{.Names}}' | grep -q "$CONTAINER_NAME"; do
    sleep 10
    status=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")
    log "Container status: $status"
  done

  exit_code=$(docker inspect --format='{{.State.ExitCode}}' "$container_id" 2>/dev/null || echo 0)
  log "Exited with code $exit_code"

  # kill_ap_process

  netfilter-persistent save || true
  docker rm -f "$container_id" >/dev/null 2>&1 || true
  log "Runner finished."
}

main "$@"
