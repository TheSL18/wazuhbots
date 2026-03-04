#!/usr/bin/env bash
## WazuhBOTS Packer — Step 4: Enable first-boot service
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-/opt/wazuhbots}"

echo "▶ [04] Enabling first-boot service..."

# Create marker file — firstboot service runs only when this exists
touch "${PROJECT_DIR}/.firstboot-pending"

# Ensure firstboot script is executable
chmod +x "${PROJECT_DIR}/firstboot.sh"

# Enable the oneshot service
systemctl enable wazuhbots-firstboot.service

echo "✓ [04] First-boot service enabled."
echo "  → On first start, wazuhbots-firstboot.service will:"
echo "    1. Generate .env with unique passwords"
echo "    2. Generate SSL certificates"
echo "    3. Pull Docker images (~4 GB)"
echo "    4. Start the full stack"
echo "    5. Ingest 95,700 documents"
echo "    6. Load 150 CTFd challenges"
