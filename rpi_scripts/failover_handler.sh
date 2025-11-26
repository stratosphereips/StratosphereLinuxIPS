#!/usr/bin/env bash

set -euo pipefail

RESET="\033[0m"; BOLD="\033[1m"; RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[0;33m"; BLUE="\033[0;34m"
echoc() { printf "%b\n" "$*"; }

usage() {
  cat <<EOF
Usage: $0 [-h] <wifi_interface>,<ethernet_interface>

-h        Show help
<wifi_interface>,<ethernet_interface>  e.g. wlan0,eth0

Example:
  $0 wlan0,eth0

This script will:
 - Require root (re-exec with sudo if needed)
 - Check for a running create_ap instance, and exit if not found
 - Create ./output and ./config if missing
 - Install iptables persistence & save iptables rules on any change.
 - Run Slips inside Docker + tmux
 - Log Slips & Docker status to slips_container.log
 - Create a systemd unit for Slips for persistence
EOF
}

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echoc "${YELLOW}Root required, re-running with sudo...${RESET}"
    # Flush output to terminal
    sleep 0.1
    exec sudo bash "$0" "$@"
  fi
}

parse_interfaces() {
  if [ "${1:-}" = "-h" ]; then usage; exit 0; fi
  if [ $# -ne 1 ]; then usage; exit 1; fi
  IFS=',' read -r WIFI_IF ETH_IF <<< "$1" || { echoc "${RED}Invalid format.${RESET}"; exit 1; }
  [ -z "$WIFI_IF" ] || [ -z "$ETH_IF" ] && { echoc "${RED}Missing interface(s).${RESET}"; exit 1; }
  echoc "${GREEN}Using WiFi interface: ${WIFI_IF}, Ethernet interface: ${ETH_IF}${RESET}"
}

ensure_create_ap_is_running() {
  echoc "${BLUE}Checking for running create_ap...${RESET}"
  if ! pgrep -a create_ap | grep -E "\\b${WIFI_IF}\\b.*\\b${ETH_IF}\\b" >/dev/null 2>&1; then
    echoc "${RED}create_ap is not running for ${WIFI_IF},${ETH_IF}.${RESET}"
    echoc "${YELLOW}Run first:${RESET}"
    echoc "${BOLD}sudo create_ap ${WIFI_IF} ${ETH_IF} rpi_wifi mysecurepassword -c 40${RESET}"
    exit 1
  fi
}


create_directories() {
  CWD="$(pwd -P)"
  OUTPUT_DIR="$CWD/output"
  echoc "${BLUE}\nChecking if ${OUTPUT_DIR} exists...${RESET} "

  if [ -d "$OUTPUT_DIR" ]; then
    echoc "${GREEN}${OUTPUT_DIR} exists${RESET}"
  else
    mkdir -p "$OUTPUT_DIR"
    echoc "${GREEN}Created ${OUTPUT_DIR} successfully.${RESET}"
  fi
  echoc "${GREEN}This script will mount ${OUTPUT_DIR} into the Docker container as Slips output directory in /StratosphereLinuxIPS/output.\n ${RESET}"
}

setup_iptables_persistence() {
    # Persistence here is a systemd unit that watches for iptables changes and saves them whenever a change is detected
    echoc "${BLUE}Setting up iptables persistence...${RESET}"

    # Install required packages
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iptables-persistent netfilter-persistent

    # Enable and start netfilter-persistent as fallback
    systemctl enable netfilter-persistent || true
    systemctl restart netfilter-persistent || true
    netfilter-persistent save || iptables-save > /etc/iptables/rules.v4 || true

    # Deploy custom systemd units
    UNIT_DIR="/etc/systemd/system"
    SRC_DIR="$(pwd)/iptables_autosave"

    # copy each unit file in iptables_autosave to the systemd directory
    for unit in iptables-watcher.service iptables-watcher.timer; do
        if [[ -f "$SRC_DIR/$unit" ]]; then
            cp -f "$SRC_DIR/$unit" "$UNIT_DIR/$unit"
            chmod 644 "$UNIT_DIR/$unit"
            echoc "${GREEN}Copied $unit to $UNIT_DIR${RESET}"
        else
            echoc "${RED}File $SRC_DIR/$unit not found, skipping.${RESET}"
        fi
    done


    # Deploy the check-iptables-hash.sh script
    cp -f "$SRC_DIR/check-iptables-hash.sh" "/usr/local/bin/check-iptables-hash.sh"
    chmod +x /usr/local/bin/check-iptables-hash.sh


    # Reload systemd, enable and start units
    systemctl daemon-reload
    systemctl enable iptables-watcher.service
    systemctl enable iptables-watcher.timer
    systemctl start iptables-watcher.timer

    echoc "${GREEN}Done setting up iptables persistence using iptables-watcher units.${RESET}"
    echoc "${BOLD}You can check the status with: ${RESET} sudo systemctl status iptables-watcher.timer\n"
}


create_slips_runner_script() {
  # Creates the slips-runner.sh script from template slips-runner-template.sh
  RUNNER_PATH="/usr/local/bin/slips-runner.sh"
  TEMPLATE="./slips-runner-template.sh"
  LOG_FILE="${CWD}/slips_container.log"

  echoc "${BLUE}Creating runner script from template for slips systemd unit to use...${RESET}"
  [ -f "$TEMPLATE" ] || { echoc "${RED}Template not found: $TEMPLATE${RESET}"; exit 1; }
  echoc "PS: This Slips runner script doesn't start slips with the blocking modules enabled, modify the Slips command in ${TEMPLATE}
  if you want to enable them and rerun this script for the changes to take effect."
  export WIFI_IF ETH_IF CWD LOG_FILE
  envsubst '$WIFI_IF $ETH_IF $CWD $LOG_FILE' < "$TEMPLATE" > "$RUNNER_PATH"
  chmod +x "$RUNNER_PATH"
  echoc "${GREEN}Runner created at $RUNNER_PATH.${RESET}"
}

create_slips_systemd_unit() {
  SERVICE_PATH="/etc/systemd/system/slips.service"
  TEMPLATE="./slips.service.template"

  echoc "${BLUE}Creating slips systemd service from template ./slips.service.template ...${RESET}"
  [ -f "$TEMPLATE" ] || { echoc "${RED}Template not found: $TEMPLATE${RESET}"; exit 1; }

  # Ensure all needed vars are exported for envsubst
  export WIFI_IF ETH_IF CWD LOG_FILE
  export OUTPUT_DIR="$CWD/output"
  export CONFIG_DIR="$CWD/config"
  export CONTAINER_NAME="slips"
  export DOCKER_IMAGE="stratosphereips/slips:latest"
  export RUNNER_PATH="/usr/local/bin/slips-runner.sh"

  envsubst < "$TEMPLATE" > "$SERVICE_PATH"

  systemctl daemon-reload
  systemctl enable slips.service
  systemctl restart slips.service
  echoc "${GREEN}Slips systemd service installed and started.${RESET}"
  echoc "${BOLD}You can check the status with: ${RESET} sudo systemctl status slips\n"
}


main() {
  parse_interfaces "$@"
  ensure_root "$@"
  ensure_create_ap_is_running

  create_directories
  setup_iptables_persistence
  create_slips_runner_script
  create_slips_systemd_unit

  echoc "${YELLOW}Slips is running inside tmux in Docker.${RESET}"
  echoc "You can attach using: ${BOLD}docker exec -it slips${RESET}"
  echoc "For container logs check: ${BOLD}${CWD}/slips_container.log${RESET}"
}

main "$@"
