#!/usr/bin/env bash
# ==============================================================================
# WazuhBOTS — Complete Setup Script
# Deploys the full WazuhBOTS CTF platform from scratch.
#
# Usage:
#   ./scripts/setup.sh                # Full interactive setup
#   ./scripts/setup.sh --skip-build   # Skip Docker image building
#   ./scripts/setup.sh --no-generate  # Skip dataset generation (use existing)
#   ./scripts/setup.sh --no-ingest    # Skip dataset ingestion
#   ./scripts/setup.sh --noise-days 7 # Days of baseline noise (default: 7)
#
# Author: MrHacker (Kevin Munoz) — Wazuh Technology Ambassador
# ==============================================================================
set -euo pipefail

# ------------------------------------------------------------------------------
# Color definitions
# ------------------------------------------------------------------------------
BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# ------------------------------------------------------------------------------
# Project paths
# ------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/.env"
ENV_EXAMPLE="${PROJECT_ROOT}/.env.example"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"
CERTS_COMPOSE="${PROJECT_ROOT}/generate-indexer-certs.yml"
CERTS_DIR="${PROJECT_ROOT}/config/wazuh_indexer_ssl_certs"

# ------------------------------------------------------------------------------
# CLI flags
# ------------------------------------------------------------------------------
SKIP_BUILD=false
NO_GENERATE=false
NO_INGEST=false
NO_CTFD=false
NOISE_DAYS=7

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build)
      SKIP_BUILD=true
      shift
      ;;
    --no-generate)
      NO_GENERATE=true
      shift
      ;;
    --no-ingest)
      NO_INGEST=true
      shift
      ;;
    --no-ctfd)
      NO_CTFD=true
      shift
      ;;
    --noise-days)
      NOISE_DAYS="${2:?--noise-days requires a number}"
      shift 2
      ;;
    --help | -h)
      echo "Usage: $0 [--skip-build] [--no-generate] [--no-ingest] [--no-ctfd] [--noise-days N] [--help]"
      exit 0
      ;;
    *)
      echo -e "${RED}[!] Unknown option: $1${NC}"
      exit 1
      ;;
  esac
done

# ------------------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------------------
log_info() { echo -e "${CYAN}[*]${NC} $*"; }
log_ok() { echo -e "${GREEN}[+]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[!]${NC} $*"; }
log_step() { echo -e "\n${BOLD}${CYAN}==> $*${NC}"; }

# ------------------------------------------------------------------------------
# ASCII Banner
# ------------------------------------------------------------------------------
banner() {
  echo -e "${CYAN}"
  cat <<'BANNER'
 __        __                _     ____   ___ _____ ____
 \ \      / /_ _ _____   _| |__ | __ ) / _ \_   _/ ___|
  \ \ /\ / / _` |_  / | | | '_ \|  _ \| | | || | \___ \
   \ V  V / (_| |/ /| |_| | | | | |_) | |_| || |  ___) |
    \_/\_/ \__,_/___|\__,_|_| |_|____/ \___/ |_| |____/

BANNER
  echo -e "${NC}"
  echo -e "${BOLD}  Boss of the SOC — Powered by Wazuh${NC}"
  echo -e "  Created by MrHacker (Kevin Munoz) | Wazuh Ambassador"
  echo -e "  ${CYAN}https://github.com/TheSL18/wazuhbots${NC}"
  echo ""
}

# ------------------------------------------------------------------------------
# Step 1: Check prerequisites
# ------------------------------------------------------------------------------
check_requirements() {
  log_step "Step 1/9 — Checking prerequisites"

  # Warn if running as root with podman (rootless by default)
  if [[ "$(id -u)" -eq 0 ]] && command -v podman &>/dev/null; then
    log_warn "Running as root, but Podman is rootless by default."
    log_warn "Files created now will be owned by root and may cause permission issues."
    log_warn "Consider running without sudo:  ./scripts/setup.sh"
    echo ""
    read -r -p "Continue as root anyway? [y/N] " confirm
    case "${confirm}" in
      [yY] | [yY][eE][sS]) log_info "Continuing as root..." ;;
      *)
        log_info "Aborted. Re-run without sudo."
        exit 0
        ;;
    esac
  fi

  local missing=0

  # Container engine — prefer podman, fallback to docker
  if command -v podman &>/dev/null; then
    CONTAINER_CMD="podman"
    log_ok "podman $(podman --version | awk '{print $NF}')"
  elif command -v docker &>/dev/null; then
    CONTAINER_CMD="docker"
    log_ok "docker $(docker --version | head -1 | sed 's/Docker version /v/')"
  else
    log_error "Neither podman nor docker is installed."
    log_error "Install podman: https://podman.io/docs/installation"
    missing=1
  fi

  # Compose — podman compose > podman-compose > docker compose > docker-compose
  if [[ "${CONTAINER_CMD:-}" == "podman" ]]; then
    if podman compose version &>/dev/null 2>&1; then
      COMPOSE_CMD="podman compose"
      log_ok "podman compose (plugin) $(podman compose version --short 2>/dev/null || echo '')"
    elif command -v podman-compose &>/dev/null; then
      COMPOSE_CMD="podman-compose"
      log_ok "podman-compose $(podman-compose --version 2>&1 | head -1)"
    else
      log_error "podman compose (plugin) or podman-compose is required."
      log_error "Install: pip install podman-compose  OR  dnf install podman-compose"
      missing=1
    fi
  elif [[ "${CONTAINER_CMD:-}" == "docker" ]]; then
    if docker compose version &>/dev/null 2>&1; then
      COMPOSE_CMD="docker compose"
      log_ok "docker compose (plugin) $(docker compose version --short 2>/dev/null || echo '')"
    elif command -v docker-compose &>/dev/null; then
      COMPOSE_CMD="docker-compose"
      log_ok "docker-compose $(docker-compose --version | head -1)"
    else
      log_error "docker compose (plugin) or docker-compose (standalone) is required."
      missing=1
    fi
  fi

  # Python 3
  if command -v python3 &>/dev/null; then
    log_ok "python3 $(python3 --version 2>&1 | awk '{print $2}')"
  else
    log_error "python3 is not installed."
    missing=1
  fi

  # curl
  if command -v curl &>/dev/null; then
    log_ok "curl $(curl --version | head -1 | awk '{print $2}')"
  else
    log_error "curl is not installed."
    missing=1
  fi

  # openssl (needed for password generation)
  if command -v openssl &>/dev/null; then
    log_ok "openssl $(openssl version 2>&1 | awk '{print $2}')"
  else
    log_error "openssl is not installed (needed for password generation)."
    missing=1
  fi

  if [[ "${missing}" -ne 0 ]]; then
    log_error "Missing required dependencies. Install them and re-run this script."
    exit 1
  fi

  # Container engine connectivity check
  if [[ "${CONTAINER_CMD}" == "podman" ]]; then
    if ! podman info &>/dev/null 2>&1; then
      log_error "Podman is not functional. Check with: podman info"
      exit 1
    fi
    log_ok "Podman is functional"
  else
    if ! docker info &>/dev/null 2>&1; then
      log_error "Docker daemon is not running. Start it with: sudo systemctl start docker"
      exit 1
    fi
    log_ok "Docker daemon is running"
  fi
}

# ------------------------------------------------------------------------------
# Step 2: Check sysctl for OpenSearch
# ------------------------------------------------------------------------------
check_sysctl() {
  log_step "Step 2/9 — Checking kernel parameters"

  local current_map_count
  current_map_count=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)

  if [[ "${current_map_count}" -ge 262144 ]]; then
    log_ok "vm.max_map_count = ${current_map_count} (OK)"
  else
    log_warn "vm.max_map_count = ${current_map_count} (required: 262144)"
    log_info "OpenSearch (Wazuh Indexer) requires vm.max_map_count >= 262144"
    log_info "Attempting to set it now (requires sudo)..."

    if sudo sysctl -w vm.max_map_count=262144 &>/dev/null; then
      log_ok "vm.max_map_count set to 262144"
    else
      log_error "Failed to set vm.max_map_count. Run manually:"
      log_error "  sudo sysctl -w vm.max_map_count=262144"
      exit 1
    fi

    # Persist across reboots
    if [[ -d /etc/sysctl.d ]]; then
      if ! grep -q "vm.max_map_count" /etc/sysctl.d/99-wazuhbots.conf 2>/dev/null; then
        echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-wazuhbots.conf >/dev/null
        log_ok "Persisted in /etc/sysctl.d/99-wazuhbots.conf"
      fi
    fi
  fi
}

# ------------------------------------------------------------------------------
# Step 3: Memory check
# ------------------------------------------------------------------------------
check_resources() {
  log_step "Step 3/9 — Checking system resources"

  local total_mem_kb
  total_mem_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
  local total_mem_gb=$((total_mem_kb / 1024 / 1024))

  log_info "Total system memory: ${total_mem_gb} GB"

  if [[ "${total_mem_gb}" -lt 8 ]]; then
    log_error "System has less than 8 GB RAM. WazuhBOTS requires at least 12 GB."
    log_error "The stack will likely fail to start. Aborting."
    exit 1
  elif [[ "${total_mem_gb}" -lt 12 ]]; then
    log_warn "System has less than 12 GB RAM (found ${total_mem_gb} GB)."
    log_warn "Recommended: 16 GB+. Performance may be degraded."
    echo ""
    read -r -p "Continue anyway? [y/N] " confirm
    case "${confirm}" in
      [yY] | [yY][eE][sS]) log_info "Proceeding with limited resources..." ;;
      *)
        log_info "Aborted."
        exit 0
        ;;
    esac
  else
    log_ok "Memory check passed (${total_mem_gb} GB available)"
  fi

  # Disk space check — warn if less than 20 GB free on the Docker root
  local docker_root
  docker_root=$(${CONTAINER_CMD} info --format '{{.DockerRootDir}}' 2>/dev/null || echo "/var/lib/containers")
  local free_gb
  free_gb=$(df -BG "${docker_root}" 2>/dev/null | awk 'NR==2{gsub(/G/,"",$4); print $4}')
  if [[ -n "${free_gb}" ]] && [[ "${free_gb}" -lt 20 ]]; then
    log_warn "Less than 20 GB free disk space on ${docker_root} (${free_gb} GB free)."
  else
    log_ok "Disk space check passed (${free_gb:-?} GB free on Docker root)"
  fi
}

# ------------------------------------------------------------------------------
# Step 4: Generate .env
# ------------------------------------------------------------------------------
generate_env() {
  log_step "Step 4/9 — Generating environment configuration"

  if [[ -f "${ENV_FILE}" ]]; then
    log_warn ".env already exists at ${ENV_FILE}"
    read -r -p "Overwrite with new random passwords? [y/N] " confirm
    case "${confirm}" in
      [yY] | [yY][eE][sS]) log_info "Regenerating .env..." ;;
      *)
        log_ok "Keeping existing .env"
        return 0
        ;;
    esac
  fi

  if [[ ! -f "${ENV_EXAMPLE}" ]]; then
    log_error ".env.example not found at ${ENV_EXAMPLE}. Cannot generate .env."
    exit 1
  fi

  cp "${ENV_EXAMPLE}" "${ENV_FILE}"

  # Generate secure random passwords that satisfy Wazuh complexity policy:
  # uppercase + lowercase + digit + special char, min 8 chars
  _gen_pass() {
    local base special
    base="$(openssl rand -base64 24 | tr -d '/+=' | head -c 20)"
    special='!@#.'
    # Pick one random special char and append to guarantee policy compliance
    echo "${base}${special:$((RANDOM % ${#special})):1}"
  }

  local indexer_pass dashboard_pass api_pass ctfd_secret ctfd_db_pass ctfd_db_root_pass
  indexer_pass="$(_gen_pass)"
  dashboard_pass="$(_gen_pass)"
  api_pass="$(_gen_pass)"
  ctfd_secret="$(openssl rand -hex 32)"
  ctfd_db_pass="$(_gen_pass)"
  ctfd_db_root_pass="$(_gen_pass)"

  # Replace placeholder passwords in .env
  sed -i "s|^INDEXER_PASSWORD=.*|INDEXER_PASSWORD=${indexer_pass}|" "${ENV_FILE}"
  sed -i "s|^DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=${dashboard_pass}|" "${ENV_FILE}"
  sed -i "s|^API_PASSWORD=.*|API_PASSWORD=${api_pass}|" "${ENV_FILE}"
  sed -i "s|^CTFD_SECRET_KEY=.*|CTFD_SECRET_KEY=${ctfd_secret}|" "${ENV_FILE}"
  sed -i "s|^CTFD_DB_PASSWORD=.*|CTFD_DB_PASSWORD=${ctfd_db_pass}|" "${ENV_FILE}"
  sed -i "s|^CTFD_DB_ROOT_PASSWORD=.*|CTFD_DB_ROOT_PASSWORD=${ctfd_db_root_pass}|" "${ENV_FILE}"

  chmod 600 "${ENV_FILE}"
  # If running as root, fix ownership to the real user (for rootless podman)
  if [[ "$(id -u)" -eq 0 ]] && [[ -n "${SUDO_USER:-}" ]]; then
    chown "${SUDO_USER}:${SUDO_USER}" "${ENV_FILE}"
  fi
  log_ok "Environment file generated with random passwords at ${ENV_FILE}"

  # Generate wazuh.yml for dashboard with the actual API password
  local wazuh_yml="${PROJECT_ROOT}/config/wazuh_dashboard/wazuh.yml"
  cat >"${wazuh_yml}" <<WEOF
hosts:
  - default:
      url: https://wazuh-manager
      port: 55000
      username: ${API_USERNAME:-wazuh-wui}
      password: ${api_pass}
      run_as: false
WEOF
  log_ok "Dashboard wazuh.yml generated with API credentials"
}

# ------------------------------------------------------------------------------
# Step 5: Generate SSL certificates
# ------------------------------------------------------------------------------
generate_certs() {
  log_step "Step 5/9 — Generating SSL certificates for Wazuh stack"

  # Check if certs already exist
  if [[ -f "${CERTS_DIR}/root-ca.pem" ]] && [[ -f "${CERTS_DIR}/wazuh-indexer.pem" ]]; then
    log_warn "SSL certificates already exist in ${CERTS_DIR}"
    read -r -p "Regenerate certificates? [y/N] " confirm
    case "${confirm}" in
      [yY] | [yY][eE][sS])
        log_info "Removing old certificates..."
        rm -rf "${CERTS_DIR:?}"/*
        ;;
      *)
        log_ok "Keeping existing certificates"
        return 0
        ;;
    esac
  fi

  if [[ ! -f "${CERTS_COMPOSE}" ]]; then
    log_error "Certificate generator compose file not found: ${CERTS_COMPOSE}"
    exit 1
  fi

  # Ensure certs directory exists with correct ownership before generator runs
  mkdir -p "${CERTS_DIR}"

  log_info "Running Wazuh certificate generator..."
  ${COMPOSE_CMD} -f "${CERTS_COMPOSE}" run --rm generator

  # Fix permissions before verifying — the generator container sets restrictive
  # ownership (container UIDs) and mode 0400, which prevents the host user from
  # even stat()-ing the files.  We need at least directory traversal to verify.
  if [[ "$(id -u)" -eq 0 ]]; then
    chmod 750 "${CERTS_DIR}"
    chmod 640 "${CERTS_DIR}"/*.pem "${CERTS_DIR}"/*.key 2>/dev/null || true
  else
    sudo chmod 750 "${CERTS_DIR}" 2>/dev/null || true
    sudo chmod 640 "${CERTS_DIR}"/*.pem "${CERTS_DIR}"/*.key 2>/dev/null || true
    sudo chown "$(id -u):$(id -g)" "${CERTS_DIR}" 2>/dev/null || true
    sudo chown "$(id -u):$(id -g)" "${CERTS_DIR}"/* 2>/dev/null || true
  fi

  # Verify expected certificate files were created
  local -a expected_certs=(
    "root-ca.pem"
    "root-ca.key"
    "wazuh-indexer.pem"
    "wazuh-indexer-key.pem"
    "wazuh-manager.pem"
    "wazuh-manager-key.pem"
    "wazuh-dashboard.pem"
    "wazuh-dashboard-key.pem"
    "admin.pem"
    "admin-key.pem"
  )

  local cert_missing=0
  for cert in "${expected_certs[@]}"; do
    if [[ ! -f "${CERTS_DIR}/${cert}" ]]; then
      log_error "Missing expected certificate: ${cert}"
      cert_missing=1
    fi
  done

  if [[ "${cert_missing}" -ne 0 ]]; then
    log_error "Certificate generation incomplete. Check the output above."
    exit 1
  fi

  # Fix permissions — certs must be readable by the containers
  chmod 750 "${CERTS_DIR}"
  chmod 640 "${CERTS_DIR}"/*.pem "${CERTS_DIR}"/*.key 2>/dev/null || true
  # If running as root, fix ownership to the real user (for rootless podman)
  if [[ "$(id -u)" -eq 0 ]] && [[ -n "${SUDO_USER:-}" ]]; then
    chown -R "${SUDO_USER}:${SUDO_USER}" "${CERTS_DIR}"
  fi
  log_ok "SSL certificates generated successfully ($(ls "${CERTS_DIR}"/*.pem | wc -l) files)"
}

# ------------------------------------------------------------------------------
# Step 6: Deploy the Docker stack
# ------------------------------------------------------------------------------
deploy_stack() {
  log_step "Step 6/9 — Deploying WazuhBOTS Docker stack"

  cd "${PROJECT_ROOT}"

  local build_flag=""
  if [[ "${SKIP_BUILD}" == "false" ]]; then
    build_flag="--build"
  else
    log_info "Skipping image build (--skip-build)"
  fi

  log_info "Running: ${COMPOSE_CMD} up -d ${build_flag}"
  ${COMPOSE_CMD} -f "${COMPOSE_FILE}" up -d ${build_flag}

  log_ok "Docker stack started. Containers are booting..."
}

# ------------------------------------------------------------------------------
# Step 7: Wait for services to become healthy
# ------------------------------------------------------------------------------
wait_for_health() {
  log_step "Step 7/9 — Waiting for services to become healthy"

  # Services and their expected container names
  local -a services=(
    "wazuhbots-manager:Wazuh Manager"
    "wazuhbots-indexer:Wazuh Indexer"
    "wazuhbots-dashboard:Wazuh Dashboard"
    "wazuhbots-ctfd:CTFd"
    "wazuhbots-ctfd-db:CTFd Database"
    "wazuhbots-nginx:Nginx Proxy"
  )

  local max_wait=300 # 5 minutes total max
  local interval=10
  local elapsed=0

  log_info "Polling container health (timeout: ${max_wait}s)..."

  while [[ "${elapsed}" -lt "${max_wait}" ]]; do
    local all_healthy=true

    for entry in "${services[@]}"; do
      local container="${entry%%:*}"
      local label="${entry##*:}"

      # Check if container exists at all
      if ! ${CONTAINER_CMD} ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
        all_healthy=false
        continue
      fi

      local status
      status=$(${CONTAINER_CMD} inspect --format='{{.State.Health.Status}}' "${container}" 2>/dev/null || echo "no-healthcheck")

      case "${status}" in
        healthy) ;;
        no-healthcheck)
          # For containers without healthcheck, check if running
          local running
          running=$(${CONTAINER_CMD} inspect --format='{{.State.Running}}' "${container}" 2>/dev/null || echo "false")
          if [[ "${running}" != "true" ]]; then
            all_healthy=false
          fi
          ;;
        *)
          all_healthy=false
          ;;
      esac
    done

    if [[ "${all_healthy}" == "true" ]]; then
      echo ""
      log_ok "All services are healthy!"
      echo ""

      # Print final status table
      for entry in "${services[@]}"; do
        local container="${entry%%:*}"
        local label="${entry##*:}"
        printf "  ${GREEN}[PASS]${NC}  %-20s  (%s)\n" "${label}" "${container}"
      done
      echo ""
      return 0
    fi

    printf "\r  Waiting... %3ds / %ds" "${elapsed}" "${max_wait}"
    sleep "${interval}"
    elapsed=$((elapsed + interval))
  done

  echo ""
  log_warn "Timed out waiting for all services. Current status:"
  echo ""
  for entry in "${services[@]}"; do
    local container="${entry%%:*}"
    local label="${entry##*:}"
    local status
    status=$(${CONTAINER_CMD} inspect --format='{{.State.Health.Status}}' "${container}" 2>/dev/null || echo "unknown")
    local running
    running=$(${CONTAINER_CMD} inspect --format='{{.State.Running}}' "${container}" 2>/dev/null || echo "false")

    if [[ "${status}" == "healthy" ]] || { [[ "${status}" == "no-healthcheck" ]] && [[ "${running}" == "true" ]]; }; then
      printf "  ${GREEN}[PASS]${NC}  %-20s\n" "${label}"
    else
      printf "  ${RED}[FAIL]${NC}  %-20s  (status: %s, running: %s)\n" "${label}" "${status}" "${running}"
    fi
  done
  echo ""
  log_warn "Some services may still be starting. Check with: ${CONTAINER_CMD} ps"
  log_warn "View logs with: ${COMPOSE_CMD} -f ${COMPOSE_FILE} logs -f <service>"
}

# ------------------------------------------------------------------------------
# Step 8: Generate datasets (attacks + baseline noise)
# ------------------------------------------------------------------------------
generate_datasets() {
  log_step "Step 8/9 — Generating datasets (attacks + ${NOISE_DAYS}-day baseline noise)"

  if [[ "${NO_GENERATE}" == "true" ]]; then
    log_info "Skipping dataset generation (--no-generate)"

    # Verify datasets exist
    local missing=0
    for scenario_dir in "${PROJECT_ROOT}/datasets/scenario"*; do
      if [[ ! -f "${scenario_dir}/wazuh-alerts.json" ]]; then
        log_warn "Missing: ${scenario_dir}/wazuh-alerts.json"
        missing=1
      fi
    done
    if [[ ! -f "${PROJECT_ROOT}/datasets/baseline_noise/noise-alerts.json" ]]; then
      log_warn "Missing: datasets/baseline_noise/noise-alerts.json"
      missing=1
    fi
    if [[ "${missing}" -ne 0 ]]; then
      log_warn "Some datasets are missing. Run without --no-generate to create them."
    else
      log_ok "Existing datasets found"
    fi
    return 0
  fi

  local gen_script="${SCRIPT_DIR}/generate_datasets.py"
  if [[ ! -f "${gen_script}" ]]; then
    log_error "generate_datasets.py not found at ${gen_script}"
    return 1
  fi

  # Generate attack data for all 4 scenarios
  log_info "Generating attack datasets for 4 scenarios..."
  if python3 "${gen_script}" --all; then
    log_ok "Attack datasets generated and validated (4 scenarios, 150 flags)"
  else
    log_error "Attack dataset generation failed!"
    log_error "Fix errors and re-run: python3 scripts/generate_datasets.py --all"
    return 1
  fi

  # Generate baseline noise (7+ days)
  log_info "Generating ${NOISE_DAYS}-day baseline noise (${NOISE_DAYS} x 12,000 = $((NOISE_DAYS * 12000)) events)..."
  if python3 "${gen_script}" --noise-only --days "${NOISE_DAYS}"; then
    log_ok "Baseline noise generated (${NOISE_DAYS} days)"
  else
    log_error "Noise generation failed!"
    log_error "Fix errors and re-run: python3 scripts/generate_datasets.py --noise-only --days ${NOISE_DAYS}"
    return 1
  fi

  # Summary
  local total_attack total_noise
  total_attack=$(python3 -c "
import json; from pathlib import Path
total = 0
for p in sorted(Path('${PROJECT_ROOT}/datasets').glob('scenario*/wazuh-alerts.json')):
    total += len(json.loads(p.read_text()))
print(total)
" 2>/dev/null || echo "?")
  total_noise=$(python3 -c "
import json; from pathlib import Path
p = Path('${PROJECT_ROOT}/datasets/baseline_noise/noise-alerts.json')
print(len(json.loads(p.read_text())) if p.exists() else 0)
" 2>/dev/null || echo "?")

  log_ok "Datasets ready: ${total_attack} attack alerts + ${total_noise} noise events"
}

# ------------------------------------------------------------------------------
# Step 9: Post-deploy tasks (indexer config + ingestion + CTFd)
# ------------------------------------------------------------------------------
post_deploy() {
  log_step "Step 9/9 — Post-deployment tasks"

  # Set indexer admin password via securityadmin
  log_info "Configuring Wazuh Indexer admin password..."
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a

  local indexer_container="wazuhbots-indexer"
  local security_tools="/usr/share/wazuh-indexer/plugins/opensearch-security/tools"
  local certs_path="/usr/share/wazuh-indexer/certs"

  # Generate bcrypt hashes for admin and kibanaserver (dashboard) users
  local admin_hash kibana_hash
  admin_hash=$(${CONTAINER_CMD} exec -u root "${indexer_container}" bash -c \
    "export JAVA_HOME=/usr/share/wazuh-indexer/jdk && ${security_tools}/hash.sh -p '${INDEXER_PASSWORD}'" 2>&1 \
    | grep '^\$2y')
  kibana_hash=$(${CONTAINER_CMD} exec -u root "${indexer_container}" bash -c \
    "export JAVA_HOME=/usr/share/wazuh-indexer/jdk && ${security_tools}/hash.sh -p '${DASHBOARD_PASSWORD}'" 2>&1 \
    | grep '^\$2y')

  if [[ -z "${admin_hash}" ]] || [[ -z "${kibana_hash}" ]]; then
    log_warn "Could not generate password hash(es). Indexer may use default credentials."
    [[ -z "${admin_hash}" ]] && log_warn "  - admin hash failed"
    [[ -z "${kibana_hash}" ]] && log_warn "  - kibanaserver hash failed"
  else
    log_info "Applying security configuration via securityadmin..."
    local securityadmin_output
    securityadmin_output=$(${CONTAINER_CMD} exec -u root "${indexer_container}" bash -c "
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
  hash: \"${kibana_hash}\"
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
        " 2>&1) && log_ok "Indexer admin + kibanaserver passwords configured" \
      || { log_warn "Failed to set indexer passwords. securityadmin output:"; echo "${securityadmin_output}"; }
  fi

  # Ingest datasets (attacks + baseline noise)
  if [[ "${NO_INGEST}" == "false" ]]; then
    if [[ -f "${SCRIPT_DIR}/ingest_datasets.py" ]]; then
      log_info "Ingesting datasets into Wazuh Indexer (attacks + noise)..."
      # Source .env so the python script picks up credentials
      set -a
      # shellcheck disable=SC1090
      source "${ENV_FILE}"
      set +a
      if python3 "${SCRIPT_DIR}/ingest_datasets.py" --all --reindex; then
        log_ok "Dataset ingestion complete."

        # Show per-index document counts
        log_info "Index document counts:"
        for day in 01 02 03 04 05 06 07; do
          local idx="wazuh-alerts-4.x-2026.03.${day}"
          local count
          count=$(curl -sk -u "admin:${INDEXER_PASSWORD}" \
            "https://localhost:9200/${idx}/_count" 2>/dev/null \
            | python3 -c "import sys,json; print(json.load(sys.stdin).get('count','N/A'))" 2>/dev/null \
            || echo "N/A")
          if [[ "${count}" != "N/A" ]] && [[ "${count}" -gt 0 ]] 2>/dev/null; then
            echo -e "    2026-03-${day}: ${CYAN}${count}${NC} docs"
          fi
        done
      else
        log_warn "Dataset ingestion had errors. Re-run: INDEXER_PASSWORD=... python3 scripts/ingest_datasets.py --all --reindex"
      fi
    else
      log_warn "ingest_datasets.py not found, skipping dataset ingestion."
    fi
  else
    log_info "Skipping dataset ingestion (--no-ingest)"
  fi

  # Load CTFd challenges
  if [[ "${NO_CTFD}" == "false" ]]; then
    if [[ -f "${SCRIPT_DIR}/generate_flags.py" ]]; then
      log_info "Loading CTFd challenges..."
      set -a
      # shellcheck disable=SC1090
      source "${ENV_FILE}"
      set +a
      python3 "${SCRIPT_DIR}/generate_flags.py" \
        && log_ok "CTFd challenges loaded." \
        || log_warn "CTFd challenge loading had errors. You can re-run: python3 scripts/generate_flags.py"
    else
      log_warn "generate_flags.py not found, skipping CTFd setup."
    fi
  else
    log_info "Skipping CTFd challenge loading (--no-ctfd)"
  fi
}

# ------------------------------------------------------------------------------
# Final summary
# ------------------------------------------------------------------------------
print_summary() {
  echo ""
  echo -e "${GREEN}${BOLD}================================================================${NC}"
  echo -e "${GREEN}${BOLD}   WazuhBOTS has been deployed successfully!${NC}"
  echo -e "${GREEN}${BOLD}================================================================${NC}"
  echo ""
  echo -e "  ${BOLD}Access Points:${NC}"
  echo -e "    Wazuh Dashboard .... ${CYAN}https://localhost:5601${NC}"
  echo -e "    CTFd Platform ...... ${CYAN}http://localhost:8000${NC}"
  echo -e "    Wazuh API .......... ${CYAN}https://localhost:55000${NC}"
  echo -e "    Nginx Proxy ........ ${CYAN}https://localhost:8443${NC}  (HTTP: ${CYAN}http://localhost:8880${NC})"
  echo ""
  echo -e "  ${BOLD}Credentials:${NC}"
  echo -e "    All passwords are stored in: ${CYAN}${ENV_FILE}${NC}"
  echo -e "    Participant account:  ${CYAN}analyst / (see PARTICIPANT_PASSWORD in .env)${NC}"
  echo ""
  echo -e "  ${BOLD}Useful Commands:${NC}"
  echo -e "    Health check ........ ${CYAN}./scripts/health_check.sh${NC}"
  echo -e "    Reset competition ... ${CYAN}./scripts/reset_environment.sh${NC}"
  echo -e "    Regen noise ......... ${CYAN}python3 scripts/generate_datasets.py --noise-only --days ${NOISE_DAYS}${NC}"
  echo -e "    Re-ingest ........... ${CYAN}INDEXER_PASSWORD=... python3 scripts/ingest_datasets.py --all --reindex${NC}"
  echo -e "    View logs ........... ${CYAN}${COMPOSE_CMD} logs -f${NC}"
  echo -e "    Stop stack .......... ${CYAN}${COMPOSE_CMD} down${NC}"
  echo ""
  echo -e "${GREEN}${BOLD}================================================================${NC}"
  echo ""
}

# ------------------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------------------
main() {
  banner
  check_requirements
  check_sysctl
  check_resources
  generate_env
  generate_certs
  deploy_stack
  wait_for_health
  generate_datasets
  post_deploy
  print_summary
}

main "$@"
