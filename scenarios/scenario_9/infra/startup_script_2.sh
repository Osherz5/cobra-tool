#!/bin/bash
# Startup script for the Cobra Scenario 9 second GCP compute instance.
# This is a plain machine — no web app. Only basic setup and optional
# Cortex XDR agent installation.
#
# SAFETY GUARD: This script will only run on the expected GCP instance.
# If the hostname does not match, the script exits immediately.

EXPECTED_HOSTNAME="cobra-scenario-9-instance-2"
CURRENT_HOSTNAME=$(hostname)

if [ "$CURRENT_HOSTNAME" != "$EXPECTED_HOSTNAME" ]; then
    echo "ERROR: Hostname mismatch. Expected '$EXPECTED_HOSTNAME', got '$CURRENT_HOSTNAME'."
    echo "This script is intended to run only on the Cobra Scenario 9 second GCP instance."
    echo "Exiting to prevent accidental execution on a local or unrelated machine."
    exit 1
fi

set -e

# Redirect all stdout and stderr to a log file for debugging
LOG_FILE="/var/log/cobra-startup-script-2.log"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== Cobra Scenario 9 instance-2 startup script started at $(date -u) ==="

# Install dependencies
apt-get update -y
apt-get install -y unzip

# __AGENT_INSTALL_BLOCK__

echo "=== Cobra Scenario 9 instance-2 startup script completed at $(date -u) ==="
