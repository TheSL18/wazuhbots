#!/usr/bin/env bash
# ==============================================================================
# WazuhBOTS — First Boot Deployment Script
#
# Runs once on the first start of a cloned LXC instance.
# Generates credentials, pulls Docker images, starts the stack,
# ingests 95,700 documents, and loads 150 CTFd challenges.
#
# All output goes to journal + /var/log/wazuhbots-firstboot.log
# Monitor with: journalctl -u wazuhbots-firstboot -f
# ==============================================================================
set -euo pipefail

PROJECT_DIR="/opt/wazuhbots"
ENV_FILE="${PROJECT_DIR}/.env"
ENV_EXAMPLE="${PROJECT_DIR}/.env.example"
LOG_FILE="/var/log/wazuhbots-firstboot.log"
MARKER="${PROJECT_DIR}/.firstboot-pending"

COMPOSE_CMD="docker compose"
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.yml"
CERTS_COMPOSE="${PROJECT_DIR}/generate-indexer-certs.yml"
CERTS_DIR="${PROJECT_DIR}/config/wazuh_indexer_ssl_certs"

# Redirect all output to log file AND stdout (journal)
exec > >(tee -a "${LOG_FILE}") 2>&1

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[*]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[!]${NC} $*"; }
log_step()  { echo -e "\n${BOLD}${CYAN}==> $*${NC}"; }

_gen_pass() {
    local base special
    base="$(openssl rand -base64 24 | tr -d '/+=' | head -c 20)"
    special='!@#.'
    echo "${base}${special:$(( RANDOM % ${#special} )):1}"
}

fail() {
    log_error "$*"
    log_error "First boot FAILED. Check ${LOG_FILE} for details."
    log_error "Fix the issue and re-run: /opt/wazuhbots/firstboot.sh"
    exit 1
}

# ==============================================================================
echo ""
echo "================================================================"
echo "  WazuhBOTS — First Boot Deployment"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================================"
echo ""

# ==============================================================================
# Step 1: Wait for Docker
# ==============================================================================
log_step "Step 1/8 — Waiting for Docker daemon..."

retries=0
max_retries=30
while ! docker info &>/dev/null; do
    retries=$((retries + 1))
    if [[ ${retries} -ge ${max_retries} ]]; then
        fail "Docker daemon did not start after ${max_retries} attempts."
    fi
    log_info "Docker not ready yet (attempt ${retries}/${max_retries})..."
    sleep 2
done
log_ok "Docker daemon is running."

# ==============================================================================
# Step 2: Generate .env with unique passwords
# ==============================================================================
log_step "Step 2/8 — Generating .env with unique passwords..."

if [[ ! -f "${ENV_EXAMPLE}" ]]; then
    fail ".env.example not found at ${ENV_EXAMPLE}"
fi

cp "${ENV_EXAMPLE}" "${ENV_FILE}"

indexer_pass="$(_gen_pass)"
dashboard_pass="$(_gen_pass)"
api_pass="$(_gen_pass)"
ctfd_secret="$(openssl rand -hex 32)"
ctfd_db_pass="$(_gen_pass)"
ctfd_db_root_pass="$(_gen_pass)"

sed -i "s|^INDEXER_PASSWORD=.*|INDEXER_PASSWORD=${indexer_pass}|"                     "${ENV_FILE}"
sed -i "s|^DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=${dashboard_pass}|"               "${ENV_FILE}"
sed -i "s|^API_PASSWORD=.*|API_PASSWORD=${api_pass}|"                                 "${ENV_FILE}"
sed -i "s|^CTFD_SECRET_KEY=.*|CTFD_SECRET_KEY=${ctfd_secret}|"                       "${ENV_FILE}"
sed -i "s|^CTFD_DB_PASSWORD=.*|CTFD_DB_PASSWORD=${ctfd_db_pass}|"                    "${ENV_FILE}"
sed -i "s|^CTFD_DB_ROOT_PASSWORD=.*|CTFD_DB_ROOT_PASSWORD=${ctfd_db_root_pass}|"     "${ENV_FILE}"

chmod 600 "${ENV_FILE}"

# Generate wazuh.yml for dashboard
API_USERNAME="${API_USERNAME:-wazuh-wui}"
mkdir -p "${PROJECT_DIR}/config/wazuh_dashboard"
cat > "${PROJECT_DIR}/config/wazuh_dashboard/wazuh.yml" << WEOF
hosts:
  - default:
      url: https://wazuh-manager
      port: 55000
      username: ${API_USERNAME}
      password: ${api_pass}
      run_as: false
WEOF

log_ok "Environment file generated with unique passwords."

# ==============================================================================
# Step 3: Generate SSL certificates
# ==============================================================================
log_step "Step 3/8 — Generating SSL certificates..."

rm -rf "${CERTS_DIR:?}"/*.pem "${CERTS_DIR:?}"/*.key 2>/dev/null || true
mkdir -p "${CERTS_DIR}"

cd "${PROJECT_DIR}"
${COMPOSE_CMD} -f "${CERTS_COMPOSE}" run --rm generator

# Fix permissions — the generator container sets restrictive ownership
# (container UIDs) and mode 0400, preventing the host from accessing files.
chmod 750 "${CERTS_DIR}" 2>/dev/null || true
chmod 640 "${CERTS_DIR}"/*.pem "${CERTS_DIR}"/*.key 2>/dev/null || true
chown -R "$(id -u):$(id -g)" "${CERTS_DIR}" 2>/dev/null || true

# Verify certificates
expected_certs=(
    "root-ca.pem" "root-ca.key"
    "wazuh-indexer.pem" "wazuh-indexer-key.pem"
    "wazuh-manager.pem" "wazuh-manager-key.pem"
    "wazuh-dashboard.pem" "wazuh-dashboard-key.pem"
    "admin.pem" "admin-key.pem"
)
for cert in "${expected_certs[@]}"; do
    if [[ ! -f "${CERTS_DIR}/${cert}" ]]; then
        fail "Certificate generation incomplete — missing ${cert}"
    fi
done
chmod 750 "${CERTS_DIR}"
chmod 640 "${CERTS_DIR}"/*.pem "${CERTS_DIR}"/*.key 2>/dev/null || true

log_ok "SSL certificates generated (${#expected_certs[@]} files)."

# ==============================================================================
# Step 4: Pull Docker images
# ==============================================================================
log_step "Step 4/8 — Pulling Docker images (~4 GB, this may take a while)..."

cd "${PROJECT_DIR}"
${COMPOSE_CMD} -f "${COMPOSE_FILE}" pull 2>&1 || log_warn "Some images failed to pull, will retry on up."

log_ok "Docker images pulled."

# ==============================================================================
# Step 5: Build custom images (victim containers)
# ==============================================================================
log_step "Step 5/8 — Building custom victim container images..."

cd "${PROJECT_DIR}"
${COMPOSE_CMD} -f "${COMPOSE_FILE}" build 2>&1 || log_warn "Some images failed to build."

log_ok "Custom images built."

# ==============================================================================
# Step 6: Start the stack
# ==============================================================================
log_step "Step 6/8 — Starting WazuhBOTS stack..."

cd "${PROJECT_DIR}"
${COMPOSE_CMD} -f "${COMPOSE_FILE}" up -d

log_ok "Docker stack started. Waiting for services..."

# Wait for services to become healthy (max 5 minutes)
services=(
    "wazuhbots-manager"
    "wazuhbots-indexer"
    "wazuhbots-ctfd"
    "wazuhbots-ctfd-db"
)

max_wait=300
interval=10
elapsed=0

while [[ ${elapsed} -lt ${max_wait} ]]; do
    all_healthy=true
    for container in "${services[@]}"; do
        status=$(docker inspect --format='{{.State.Health.Status}}' "${container}" 2>/dev/null || echo "not-found")
        if [[ "${status}" != "healthy" ]]; then
            all_healthy=false
            break
        fi
    done

    if [[ "${all_healthy}" == "true" ]]; then
        break
    fi

    log_info "Services not ready yet... (${elapsed}s / ${max_wait}s)"
    sleep "${interval}"
    elapsed=$((elapsed + interval))
done

if [[ "${all_healthy}" == "true" ]]; then
    log_ok "All core services are healthy."
else
    log_warn "Timeout waiting for services. Continuing anyway..."
    log_warn "Current container states:"
    docker ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null || true
fi

# ==============================================================================
# Step 7: Configure indexer + ingest datasets
# ==============================================================================
log_step "Step 7/8 — Configuring indexer and ingesting datasets..."

# Source credentials
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

indexer_container="wazuhbots-indexer"
security_tools="/usr/share/wazuh-indexer/plugins/opensearch-security/tools"
certs_path="/usr/share/wazuh-indexer/certs"

# Wait for indexer API to respond
log_info "Waiting for indexer API..."
indexer_ready=false
for i in $(seq 1 30); do
    if curl -sk -u "admin:admin" "https://localhost:9200/" &>/dev/null; then
        indexer_ready=true
        break
    fi
    sleep 5
done

if [[ "${indexer_ready}" != "true" ]]; then
    log_warn "Indexer API not responding. Skipping password config."
else
    # Generate bcrypt hash and apply via securityadmin
    log_info "Setting indexer admin password..."
    admin_hash=$(docker exec -u root "${indexer_container}" bash -c \
        "export JAVA_HOME=/usr/share/wazuh-indexer/jdk && ${security_tools}/hash.sh -p '${INDEXER_PASSWORD}'" 2>&1 \
        | grep '^\$2y' || true)

    if [[ -n "${admin_hash}" ]]; then
        docker exec -u root "${indexer_container}" bash -c "
            mkdir -p ${security_tools}/../securityconfig
            cat > ${security_tools}/../securityconfig/internal_users.yml << IEOF
---
_meta:
  type: internalusers
  config_version: 2
admin:
  hash: \"${admin_hash}\"
  reserved: true
  backend_roles:
    - admin
  description: Admin user
kibanaserver:
  hash: \"${admin_hash}\"
  reserved: true
  description: Kibana server user
IEOF
            export JAVA_HOME=/usr/share/wazuh-indexer/jdk
            ${security_tools}/securityadmin.sh \
                -f ${security_tools}/../securityconfig/internal_users.yml \
                -t internalusers -icl -nhnv \
                -cacert ${certs_path}/root-ca.pem \
                -cert ${certs_path}/admin.pem \
                -key ${certs_path}/admin-key.pem \
                -h localhost
        " &>/dev/null && log_ok "Indexer admin password configured." \
                      || log_warn "Failed to set indexer password."
    else
        log_warn "Could not generate password hash."
    fi
fi

# Ingest datasets
log_info "Ingesting datasets (95,700 documents)..."
if python3 "${PROJECT_DIR}/scripts/ingest_datasets.py" --all --reindex; then
    log_ok "Dataset ingestion complete."
else
    log_warn "Dataset ingestion had errors. Re-run: python3 /opt/wazuhbots/scripts/ingest_datasets.py --all --reindex"
fi

# ==============================================================================
# Step 8: Load CTFd challenges
# ==============================================================================
log_step "Step 8/8 — Loading CTFd challenges..."

# Wait for CTFd API to respond
log_info "Waiting for CTFd API..."
ctfd_ready=false
for i in $(seq 1 30); do
    if curl -s "http://localhost:8000/api/v1/challenges" -o /dev/null -w '%{http_code}' 2>/dev/null | grep -qE '(200|302|401|403)'; then
        ctfd_ready=true
        break
    fi
    sleep 5
done

if [[ "${ctfd_ready}" == "true" ]]; then
    if python3 "${PROJECT_DIR}/scripts/generate_flags.py"; then
        log_ok "CTFd challenges loaded (150 challenges, 39,200 points)."
    else
        log_warn "CTFd challenge loading had errors. Re-run: python3 /opt/wazuhbots/scripts/generate_flags.py"
    fi
else
    log_warn "CTFd API not responding. Skipping challenge loading."
    log_warn "Manually load later: python3 /opt/wazuhbots/scripts/generate_flags.py"
fi

# ==============================================================================
# Done — remove marker
# ==============================================================================
rm -f "${MARKER}"

echo ""
echo "================================================================"
echo -e "  ${GREEN}${BOLD}WazuhBOTS — First Boot Complete!${NC}"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================================"
echo ""
echo "  Access Points:"
echo "    Wazuh Dashboard .... https://<IP>:5601"
echo "    CTFd Platform ...... http://<IP>:8000"
echo "    Wazuh API .......... https://<IP>:55000"
echo "    Nginx Proxy ........ https://<IP>:8443"
echo ""
echo "  Credentials:"
echo "    Stored in: ${ENV_FILE}"
echo "    Participant: analyst / WazuhBOTS2026!"
echo ""
echo "  Useful Commands:"
echo "    Status ........... docker compose ps"
echo "    Logs ............. docker compose logs -f"
echo "    Health check ..... ./scripts/health_check.sh"
echo "    Reset comp ....... ./scripts/reset_environment.sh"
echo ""
echo "================================================================"
