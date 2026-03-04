#!/usr/bin/env bash
## WazuhBOTS Packer — Step 3: Docker daemon configuration
set -euo pipefail

echo "▶ [03] Configuring Docker daemon..."

# Install daemon.json (overlay2, log rotation, address pool)
mkdir -p /etc/docker
cp /tmp/docker-daemon.json /etc/docker/daemon.json

# Systemd override for Docker limits (required by Wazuh/OpenSearch)
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/override.conf << 'EOF'
[Service]
LimitMEMLOCK=infinity
LimitNOFILE=65536
EOF

# Install MOTD
cp /tmp/wazuhbots.motd /etc/motd

# Store sysctl reference (informational — must be applied on the Proxmox HOST)
mkdir -p /opt/wazuhbots/docs
cp /tmp/sysctl-wazuhbots.conf /opt/wazuhbots/docs/sysctl-wazuhbots.conf

echo "✓ [03] Docker daemon configuration complete."
