#!/bin/bash
set -e

echo "[WazuhBOTS] Starting lnx-srv (Scenario 3: Ghost in the Shell)..."

# Configure Wazuh Agent
if [ -n "$WAZUH_MANAGER" ]; then
    sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|" /var/ossec/etc/ossec.conf
fi

# Start auditd
echo "[WazuhBOTS] Starting auditd..."
service auditd start 2>/dev/null || auditd -l 2>/dev/null || true

# Start SSH
echo "[WazuhBOTS] Starting SSH server..."
service ssh start

# Start Wazuh Agent
echo "[WazuhBOTS] Starting Wazuh Agent..."
/var/ossec/bin/wazuh-control start

# Start cron for baseline traffic
service cron start

echo "[WazuhBOTS] lnx-srv ready!"
echo "[WazuhBOTS] SSH available on port 22"

# Keep container running
tail -f /var/log/auth.log /var/log/syslog /var/ossec/logs/ossec.log 2>/dev/null
