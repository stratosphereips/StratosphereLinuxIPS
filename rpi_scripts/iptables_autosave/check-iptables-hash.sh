#!/bin/bash

HASH_FILE="/var/run/iptables.hash"

# Get the current ruleset and hash it
CURRENT_HASH=$(/usr/sbin/iptables-save | sha256sum)

# If the hash file doesn't exist, create it and exit
if [ ! -f "$HASH_FILE" ]; then
    echo "$CURRENT_HASH" > "$HASH_FILE"
    exit 0
fi

# Read the old hash
OLD_HASH=$(cat "$HASH_FILE")

# Compare hashes
if [ "$CURRENT_HASH" != "$OLD_HASH" ]; then
    # 1. Update the hash file with the new hash
    echo "$CURRENT_HASH" > "$HASH_FILE"


    # 2. Trigger the action service to reload rules
    echo "Saving updated iptables rules."
    netfilter-persistent save || iptables-save > /etc/iptables/rules.v4 || true

else
    # No changes, do nothing
    :
fi
