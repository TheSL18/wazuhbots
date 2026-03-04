#!/usr/bin/env bash
# ==============================================================================
# WazuhBOTS — Reset Environment Script
# Resets the competition state while preserving datasets and configuration.
#
# What this script does:
#   - Clears CTFd scores, submissions, and user accounts (keeps challenges)
#   - Regenerates challenge flags with new random values
#   - Optionally reloads challenges into CTFd
#   - Preserves all Wazuh Indexer datasets
#   - Preserves Docker volumes for Wazuh data
#
# Usage:
#   ./scripts/reset_environment.sh             # Interactive reset
#   ./scripts/reset_environment.sh --force     # Skip confirmation prompts
#   ./scripts/reset_environment.sh --full      # Also rebuild containers
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
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"

# ------------------------------------------------------------------------------
# Load environment
# ------------------------------------------------------------------------------
if [[ -f "${ENV_FILE}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
fi

CTFD_DB_PASSWORD="${CTFD_DB_PASSWORD:-ChangeMeDB123!}"
CTFD_DB_ROOT_PASSWORD="${CTFD_DB_ROOT_PASSWORD:-ChangeMeDBRoot123!}"

# ------------------------------------------------------------------------------
# Detect compose command
# ------------------------------------------------------------------------------
if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo -e "${RED}[!] docker compose or docker-compose is required.${NC}"
    exit 1
fi

# ------------------------------------------------------------------------------
# CLI flags
# ------------------------------------------------------------------------------
FORCE=false
FULL_RESET=false

for arg in "$@"; do
    case "${arg}" in
        --force|-f) FORCE=true ;;
        --full)     FULL_RESET=true ;;
        --help|-h)
            echo "Usage: $0 [--force] [--full] [--help]"
            echo ""
            echo "  --force   Skip confirmation prompts"
            echo "  --full    Also rebuild containers from scratch"
            echo "  --help    Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Unknown option: ${arg}${NC}"
            exit 1
            ;;
    esac
done

# ------------------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------------------
log_info()  { echo -e "${CYAN}[*]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[!]${NC} $*"; }
log_step()  { echo -e "\n${BOLD}${CYAN}==> $*${NC}"; }

# ------------------------------------------------------------------------------
# Confirmation prompt
# ------------------------------------------------------------------------------
confirm_reset() {
    if [[ "${FORCE}" == "true" ]]; then
        return 0
    fi

    echo ""
    echo -e "${RED}${BOLD}================================================================${NC}"
    echo -e "${RED}${BOLD}   WARNING: WazuhBOTS Environment Reset${NC}"
    echo -e "${RED}${BOLD}================================================================${NC}"
    echo ""
    echo -e "  This will:"
    echo -e "    ${RED}- Clear all CTFd scores and submissions${NC}"
    echo -e "    ${RED}- Delete all CTFd user accounts${NC}"
    echo -e "    ${RED}- Regenerate challenge flags${NC}"
    echo ""
    echo -e "  This will ${GREEN}NOT${NC} affect:"
    echo -e "    ${GREEN}+ Wazuh Indexer datasets${NC}"
    echo -e "    ${GREEN}+ Wazuh Manager configuration${NC}"
    echo -e "    ${GREEN}+ Docker images and volumes (except CTFd DB)${NC}"
    echo -e "    ${GREEN}+ Challenge definitions (JSON files)${NC}"
    echo ""

    if [[ "${FULL_RESET}" == "true" ]]; then
        echo -e "  ${YELLOW}FULL RESET mode: Containers will also be rebuilt.${NC}"
        echo ""
    fi

    read -r -p "  Are you sure you want to continue? Type 'RESET' to confirm: " confirmation
    if [[ "${confirmation}" != "RESET" ]]; then
        log_info "Reset cancelled."
        exit 0
    fi
    echo ""
}

# ------------------------------------------------------------------------------
# Step 1: Stop CTFd services
# ------------------------------------------------------------------------------
stop_ctfd() {
    log_step "Step 1/4 — Stopping CTFd services"

    cd "${PROJECT_ROOT}"

    # Stop only CTFd-related containers, leave Wazuh running
    ${COMPOSE_CMD} -f "${COMPOSE_FILE}" stop ctfd ctfd-redis 2>/dev/null || true
    log_ok "CTFd services stopped"
}

# ------------------------------------------------------------------------------
# Step 2: Clear CTFd database (scores, submissions, users)
# Keep challenge definitions so we can re-import them.
# ------------------------------------------------------------------------------
clear_ctfd_data() {
    log_step "Step 2/4 — Clearing CTFd competition data"

    local db_container="wazuhbots-ctfd-db"

    # Verify the database container is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${db_container}$"; then
        log_error "CTFd database container '${db_container}' is not running."
        log_info "Attempting to start it..."
        cd "${PROJECT_ROOT}"
        ${COMPOSE_CMD} -f "${COMPOSE_FILE}" start ctfd-db
        sleep 5
    fi

    log_info "Clearing CTFd tables: submissions, solves, tracking, awards, notifications, users..."

    # SQL commands to clear competition data while preserving challenge structure
    # We use the root password to ensure we have permissions.
    docker exec -i "${db_container}" mariadb -u root -p"${CTFD_DB_ROOT_PASSWORD}" ctfd <<'SQL'
SET FOREIGN_KEY_CHECKS = 0;

-- Clear competition results
TRUNCATE TABLE submissions;
TRUNCATE TABLE solves;
TRUNCATE TABLE tracking;
TRUNCATE TABLE awards;
TRUNCATE TABLE notifications;
TRUNCATE TABLE unlocks;

-- Clear user data (participants) but keep admin
DELETE FROM users WHERE id > 1;

-- Clear team data
TRUNCATE TABLE teams;

-- Reset auto-increment on users (keep 1 for admin)
ALTER TABLE users AUTO_INCREMENT = 2;

-- Clear challenges and flags (will be re-imported)
TRUNCATE TABLE flags;
TRUNCATE TABLE hints;
TRUNCATE TABLE tags;
TRUNCATE TABLE challenges;
TRUNCATE TABLE files;
TRUNCATE TABLE pages;

SET FOREIGN_KEY_CHECKS = 1;
SQL

    if [[ $? -eq 0 ]]; then
        log_ok "CTFd database cleared successfully"
    else
        log_error "Failed to clear CTFd database. Check MariaDB logs."
        log_info "You can check logs with: docker logs ${db_container}"
    fi
}

# ------------------------------------------------------------------------------
# Step 3: Regenerate flags and reload challenges
# ------------------------------------------------------------------------------
regenerate_flags() {
    log_step "Step 3/4 — Regenerating flags and reloading challenges"

    # Restart CTFd so it picks up the clean database
    cd "${PROJECT_ROOT}"
    ${COMPOSE_CMD} -f "${COMPOSE_FILE}" start ctfd ctfd-redis
    log_info "Waiting for CTFd to restart..."
    sleep 10

    # Wait until CTFd is responsive
    local retries=0
    local max_retries=30
    while [[ "${retries}" -lt "${max_retries}" ]]; do
        local http_code
        http_code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "http://localhost:8000" 2>/dev/null || echo "000")
        if [[ "${http_code}" == "200" ]] || [[ "${http_code}" == "302" ]]; then
            break
        fi
        retries=$(( retries + 1 ))
        sleep 2
    done

    if [[ "${retries}" -ge "${max_retries}" ]]; then
        log_warn "CTFd did not become responsive within timeout."
        log_warn "You may need to manually run: python3 scripts/generate_flags.py"
        return 1
    fi

    # Reload challenges via the generate_flags script
    if [[ -f "${SCRIPT_DIR}/generate_flags.py" ]]; then
        log_info "Loading challenges into CTFd..."
        python3 "${SCRIPT_DIR}/generate_flags.py" && \
            log_ok "Challenges reloaded with fresh flags." || \
            log_warn "Challenge loading had errors. Run manually: python3 scripts/generate_flags.py"
    else
        log_warn "generate_flags.py not found. Challenges must be loaded manually."
    fi
}

# ------------------------------------------------------------------------------
# Step 4: Full reset (optional — rebuild containers)
# ------------------------------------------------------------------------------
full_rebuild() {
    if [[ "${FULL_RESET}" != "true" ]]; then
        return 0
    fi

    log_step "Step 4/4 — Full rebuild of containers"

    cd "${PROJECT_ROOT}"

    log_info "Rebuilding all containers..."
    ${COMPOSE_CMD} -f "${COMPOSE_FILE}" up -d --build --force-recreate

    log_info "Waiting for services to stabilize..."
    sleep 20

    log_ok "Full rebuild complete"
}

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
print_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo -e "${GREEN}${BOLD}   WazuhBOTS environment has been reset!${NC}"
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo ""
    echo -e "  ${BOLD}What was reset:${NC}"
    echo -e "    - CTFd scores, submissions, and user accounts cleared"
    echo -e "    - Challenge flags regenerated"
    echo -e "    - Challenges reloaded into CTFd"
    echo ""
    echo -e "  ${BOLD}What was preserved:${NC}"
    echo -e "    - All Wazuh Indexer datasets"
    echo -e "    - Wazuh Manager configuration and rules"
    echo -e "    - Dashboard saved objects"
    echo ""
    echo -e "  ${BOLD}Next steps:${NC}"
    echo -e "    1. Verify health:  ${CYAN}./scripts/health_check.sh${NC}"
    echo -e "    2. Complete CTFd initial setup at ${CYAN}http://localhost:8000${NC}"
    echo -e "    3. Share participant credentials with teams"
    echo ""
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo ""
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
main() {
    echo ""
    echo -e "${BOLD}${CYAN}  WazuhBOTS — Environment Reset${NC}"
    echo -e "  $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo ""

    confirm_reset
    stop_ctfd
    clear_ctfd_data
    regenerate_flags
    full_rebuild
    print_summary
}

main "$@"
