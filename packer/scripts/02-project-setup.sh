#!/usr/bin/env bash
## WazuhBOTS Packer — Step 2: Verify project files and datasets
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-/opt/wazuhbots}"

echo "▶ [02] Verifying project at ${PROJECT_DIR}..."

# Core files
for f in docker-compose.yml generate-indexer-certs.yml .env.example; do
    if [[ ! -f "${PROJECT_DIR}/${f}" ]]; then
        echo "✗ Missing: ${f}"
        exit 1
    fi
    echo "  ✓ ${f}"
done

# Datasets
for ds in \
    datasets/scenario1_dark_harvest/wazuh-alerts.json \
    datasets/scenario2_iron_gate/wazuh-alerts.json \
    datasets/scenario3_ghost_shell/wazuh-alerts.json \
    datasets/scenario4_supply_chain/wazuh-alerts.json \
    datasets/baseline_noise/noise-alerts.json; do
    if [[ ! -f "${PROJECT_DIR}/${ds}" ]]; then
        echo "✗ Missing dataset: ${ds}"
        exit 1
    fi
    size=$(stat -c%s "${PROJECT_DIR}/${ds}" 2>/dev/null || echo 0)
    echo "  ✓ ${ds} ($(numfmt --to=iec ${size}))"
done

# Challenge JSONs
for sc in 1 2 3 4; do
    f="ctfd/challenges/scenario${sc}_challenges.json"
    if [[ ! -f "${PROJECT_DIR}/${f}" ]]; then
        echo "✗ Missing: ${f}"
        exit 1
    fi
    echo "  ✓ ${f}"
done

echo "▶ [02] Cleaning ephemeral state..."

# Remove .env — will be generated on first boot with unique passwords
rm -f "${PROJECT_DIR}/.env"

# Remove existing SSL certs — regenerated on first boot
rm -rf "${PROJECT_DIR}/config/wazuh_indexer_ssl_certs/"*.pem
rm -rf "${PROJECT_DIR}/config/wazuh_indexer_ssl_certs/"*.key

# Clean Python cache
find "${PROJECT_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${PROJECT_DIR}" -name "*.pyc" -delete 2>/dev/null || true

echo "▶ [02] Setting permissions..."

chmod +x "${PROJECT_DIR}/scripts/"*.sh 2>/dev/null || true
chmod +x "${PROJECT_DIR}/scripts/"*.py 2>/dev/null || true

# Convenience symlink
ln -sfn "${PROJECT_DIR}" /root/wazuhbots

echo "✓ [02] Project verification complete."
