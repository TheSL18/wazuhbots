#!/usr/bin/env bash
## WazuhBOTS Packer — Step 5: Clean up to reduce template size
set -euo pipefail

echo "▶ [05] Cleaning up..."

# APT caches
apt-get clean -y
rm -rf /var/lib/apt/lists/*

# Pip cache
rm -rf /root/.cache/pip

# Truncate logs
find /var/log -type f -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null || true
truncate -s 0 /var/log/wtmp 2>/dev/null || true
truncate -s 0 /var/log/lastlog 2>/dev/null || true

# Temp files
rm -rf /tmp/* /var/tmp/*

# Shell history
rm -f /root/.bash_history

# Machine ID — regenerated on first boot for unique identity
truncate -s 0 /etc/machine-id

echo "✓ [05] Cleanup complete. Template is ready for packaging."
