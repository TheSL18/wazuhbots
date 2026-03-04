#!/bin/bash
set -e

echo "[WazuhBOTS] Starting dc-srv (Scenario 2: Iron Gate)..."

# Configure Wazuh Agent
if [ -n "$WAZUH_MANAGER" ]; then
    sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|" /var/ossec/etc/ossec.conf
fi

# Start Wazuh Agent
echo "[WazuhBOTS] Starting Wazuh Agent..."
/var/ossec/bin/wazuh-control start

# Start cron
service cron start

echo "[WazuhBOTS] dc-srv ready!"
echo "[WazuhBOTS] AD simulation logs in /var/log/windows-events/"

# Keep container running
tail -f /var/ossec/logs/ossec.log 2>/dev/null
