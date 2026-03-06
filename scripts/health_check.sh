#!/usr/bin/env bash
# ==============================================================================
# WazuhBOTS — Health Check Script
# Verifies that all WazuhBOTS services are running and reachable.
#
# Usage:
#   ./scripts/health_check.sh          # Full health check
#   ./scripts/health_check.sh --quiet  # Exit code only (0 = healthy, 1 = issues)
#   ./scripts/health_check.sh --json   # Output as JSON
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

# ------------------------------------------------------------------------------
# Load environment variables
# ------------------------------------------------------------------------------
if [[ -f "${ENV_FILE}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
fi

# Defaults from .env or fallback
INDEXER_PASSWORD="${INDEXER_PASSWORD:-admin}"
# Wazuh indexer 4.14.3 ignores OPENSEARCH_INITIAL_ADMIN_PASSWORD;
# admin user keeps the default password "admin".
INDEXER_ADMIN_PASSWORD="admin"
API_USERNAME="${API_USERNAME:-wazuh-wui}"
API_PASSWORD="${API_PASSWORD:-ChangeMeAPI123!}"

# ------------------------------------------------------------------------------
# CLI flags
# ------------------------------------------------------------------------------
QUIET=false
JSON_OUTPUT=false

for arg in "$@"; do
    case "${arg}" in
        --quiet|-q) QUIET=true ;;
        --json|-j)  JSON_OUTPUT=true ;;
        --help|-h)
            echo "Usage: $0 [--quiet] [--json] [--help]"
            exit 0
            ;;
    esac
done

# ------------------------------------------------------------------------------
# State tracking
# ------------------------------------------------------------------------------
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
declare -a JSON_RESULTS=()

# ------------------------------------------------------------------------------
# Check helpers
# ------------------------------------------------------------------------------
check_pass() {
    local name="$1"
    local detail="${2:-}"
    TOTAL_CHECKS=$(( TOTAL_CHECKS + 1 ))
    PASSED_CHECKS=$(( PASSED_CHECKS + 1 ))
    if [[ "${QUIET}" == "false" ]] && [[ "${JSON_OUTPUT}" == "false" ]]; then
        printf "  ${GREEN}[PASS]${NC}  %-35s  %s\n" "${name}" "${detail}"
    fi
    JSON_RESULTS+=("{\"check\":\"${name}\",\"status\":\"pass\",\"detail\":\"${detail}\"}")
}

check_fail() {
    local name="$1"
    local detail="${2:-}"
    TOTAL_CHECKS=$(( TOTAL_CHECKS + 1 ))
    FAILED_CHECKS=$(( FAILED_CHECKS + 1 ))
    if [[ "${QUIET}" == "false" ]] && [[ "${JSON_OUTPUT}" == "false" ]]; then
        printf "  ${RED}[FAIL]${NC}  %-35s  %s\n" "${name}" "${detail}"
    fi
    JSON_RESULTS+=("{\"check\":\"${name}\",\"status\":\"fail\",\"detail\":\"${detail}\"}")
}

check_warn() {
    local name="$1"
    local detail="${2:-}"
    TOTAL_CHECKS=$(( TOTAL_CHECKS + 1 ))
    PASSED_CHECKS=$(( PASSED_CHECKS + 1 ))
    if [[ "${QUIET}" == "false" ]] && [[ "${JSON_OUTPUT}" == "false" ]]; then
        printf "  ${YELLOW}[WARN]${NC}  %-35s  %s\n" "${name}" "${detail}"
    fi
    JSON_RESULTS+=("{\"check\":\"${name}\",\"status\":\"warn\",\"detail\":\"${detail}\"}")
}

section() {
    if [[ "${QUIET}" == "false" ]] && [[ "${JSON_OUTPUT}" == "false" ]]; then
        echo ""
        echo -e "  ${BOLD}${CYAN}--- $1 ---${NC}"
    fi
}

# ------------------------------------------------------------------------------
# Check: Container running
# Verifies that a named container exists and is in "running" state.
# ------------------------------------------------------------------------------
check_container() {
    local container_name="$1"
    local display_name="$2"

    if ! docker ps -a --format '{{.Names}}' | grep -q "^${container_name}$"; then
        check_fail "${display_name} container" "Container '${container_name}' does not exist"
        return 1
    fi

    local state
    state=$(docker inspect --format='{{.State.Status}}' "${container_name}" 2>/dev/null || echo "unknown")

    if [[ "${state}" == "running" ]]; then
        # Check health status if available
        local health
        health=$(docker inspect --format='{{.State.Health.Status}}' "${container_name}" 2>/dev/null || echo "none")
        if [[ "${health}" == "healthy" ]]; then
            check_pass "${display_name} container" "running (healthy)"
        elif [[ "${health}" == "unhealthy" ]]; then
            check_fail "${display_name} container" "running but unhealthy"
            return 1
        else
            check_pass "${display_name} container" "running"
        fi
        return 0
    else
        check_fail "${display_name} container" "state: ${state}"
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Check: HTTP endpoint reachable
# Attempts to reach an HTTP(S) endpoint and validates the response code.
# ------------------------------------------------------------------------------
check_endpoint() {
    local display_name="$1"
    local url="$2"
    local expected_code="${3:-200}"
    local auth="${4:-}"

    local curl_args=(-sk --max-time 10 -o /dev/null -w "%{http_code}")
    if [[ -n "${auth}" ]]; then
        curl_args+=(-u "${auth}")
    fi

    local http_code
    http_code=$(curl "${curl_args[@]}" "${url}" 2>/dev/null || echo "000")

    if [[ "${http_code}" == "${expected_code}" ]]; then
        check_pass "${display_name}" "HTTP ${http_code}"
        return 0
    elif [[ "${http_code}" == "000" ]]; then
        check_fail "${display_name}" "Connection refused or timeout"
        return 1
    else
        check_fail "${display_name}" "HTTP ${http_code} (expected ${expected_code})"
        return 1
    fi
}

# ==============================================================================
# Health Check Suites
# ==============================================================================

check_containers() {
    section "Docker Containers"

    check_container "wazuhbots-manager"    "Wazuh Manager"
    check_container "wazuhbots-indexer"    "Wazuh Indexer"
    check_container "wazuhbots-dashboard"  "Wazuh Dashboard"
    check_container "wazuhbots-ctfd"       "CTFd"
    check_container "wazuhbots-ctfd-db"    "CTFd Database"
    check_container "wazuhbots-ctfd-redis" "CTFd Redis"
    check_container "wazuhbots-nginx"      "Nginx Proxy"
    check_container "wazuhbots-web-srv"    "Victim: web-srv"
    check_container "wazuhbots-lnx-srv"    "Victim: lnx-srv"
}

check_wazuh_api() {
    section "Wazuh API"

    # Authentication endpoint
    local token
    token=$(curl -sk --max-time 10 -u "${API_USERNAME}:${API_PASSWORD}" \
        "https://localhost:55000/security/user/authenticate" 2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('token',''))" 2>/dev/null || echo "")

    if [[ -n "${token}" ]]; then
        check_pass "Wazuh API authentication" "Token obtained"

        # Manager status
        local manager_status
        manager_status=$(curl -sk --max-time 10 \
            -H "Authorization: Bearer ${token}" \
            "https://localhost:55000/manager/status" 2>/dev/null | \
            python3 -c "
import sys,json
data = json.load(sys.stdin).get('data',{}).get('affected_items',[{}])[0]
running = sum(1 for v in data.values() if v == 'running')
total = len(data)
print(f'{running}/{total} daemons running')
" 2>/dev/null || echo "unknown")
        if [[ "${manager_status}" != "unknown" ]]; then
            check_pass "Wazuh Manager daemons" "${manager_status}"
        else
            check_warn "Wazuh Manager daemons" "Could not parse status"
        fi

        # Connected agents
        local agent_info
        agent_info=$(curl -sk --max-time 10 \
            -H "Authorization: Bearer ${token}" \
            "https://localhost:55000/agents/summary/status" 2>/dev/null | \
            python3 -c "
import sys,json
data = json.load(sys.stdin).get('data',{})
active = data.get('connection',{}).get('active',0)
total = data.get('connection',{}).get('total',0)
print(f'{active} active / {total} total')
" 2>/dev/null || echo "unknown")
        if [[ "${agent_info}" != "unknown" ]]; then
            check_pass "Wazuh Agents" "${agent_info}"
        else
            check_warn "Wazuh Agents" "Could not retrieve agent summary"
        fi
    else
        check_fail "Wazuh API authentication" "Failed to obtain token"
    fi
}

## Detect container engine
if command -v podman &>/dev/null; then
    _CONTAINER_CMD="podman"
elif command -v docker &>/dev/null; then
    _CONTAINER_CMD="docker"
else
    _CONTAINER_CMD="docker"
fi

## Helper: query indexer from host, fallback to container exec
indexer_curl() {
    local path="$1"
    local result
    result=$(curl -sk --max-time 10 -u "admin:${INDEXER_ADMIN_PASSWORD}" \
        "https://localhost:9200${path}" 2>/dev/null || echo "")
    if [[ -z "${result}" ]] || ! echo "${result}" | grep -q '{'; then
        result=$($_CONTAINER_CMD exec wazuhbots-indexer curl -sk --max-time 10 \
            -u "admin:${INDEXER_ADMIN_PASSWORD}" \
            "https://localhost:9200${path}" 2>/dev/null || echo "")
    fi
    echo "${result}"
}

check_wazuh_indexer() {
    section "Wazuh Indexer (OpenSearch)"

    # Cluster health (retry up to 3 times — indexer may still be initializing HTTPS)
    local cluster_health=""
    local attempt
    for attempt in 1 2 3; do
        cluster_health=$(indexer_curl "/_cluster/health")
        [[ -n "${cluster_health}" ]] && break
        sleep 2
    done

    if [[ -n "${cluster_health}" ]]; then
        local status
        status=$(echo "${cluster_health}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")
        local node_count
        node_count=$(echo "${cluster_health}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('number_of_nodes',0))" 2>/dev/null || echo "0")

        if [[ "${status}" == "green" ]]; then
            check_pass "Indexer cluster health" "GREEN (${node_count} node(s))"
        elif [[ "${status}" == "yellow" ]]; then
            check_warn "Indexer cluster health" "YELLOW (${node_count} node(s))"
        else
            check_fail "Indexer cluster health" "${status} (${node_count} node(s))"
        fi
    else
        check_fail "Indexer cluster health" "Connection refused"
    fi

    # Check for Wazuh alert indices
    local index_count
    index_count=$(indexer_curl "/_cat/indices/wazuh-alerts*?h=index" | wc -l || echo "0")
    index_count=$(echo "${index_count}" | tr -d ' ')

    if [[ "${index_count}" -gt 0 ]]; then
        check_pass "Wazuh alert indices" "${index_count} index(es) found"
    else
        check_warn "Wazuh alert indices" "No wazuh-alerts indices yet (may be normal on fresh deploy)"
    fi

    # Check for WazuhBOTS dataset indices
    local bots_index_count
    bots_index_count=$(indexer_curl "/_cat/indices/wazuhbots-*?h=index" | wc -l || echo "0")
    bots_index_count=$(echo "${bots_index_count}" | tr -d ' ')

    if [[ "${bots_index_count}" -gt 0 ]]; then
        check_pass "WazuhBOTS dataset indices" "${bots_index_count} index(es)"
    else
        check_warn "WazuhBOTS dataset indices" "No datasets ingested yet"
    fi
}

check_ctfd() {
    section "CTFd Platform"

    # CTFd redirects to /setup (first run) or /login (configured) — 302 is expected
    check_endpoint "CTFd web interface" "http://localhost:8000" "302"

    # Check if CTFd API is available
    local api_resp
    api_resp=$(curl -sk --max-time 10 -o /dev/null -w "%{http_code}" \
        "http://localhost:8000/api/v1/challenges" 2>/dev/null || echo "000")

    if [[ "${api_resp}" == "200" ]] || [[ "${api_resp}" == "302" ]] || [[ "${api_resp}" == "403" ]]; then
        check_pass "CTFd API endpoint" "HTTP ${api_resp}"
    else
        check_warn "CTFd API endpoint" "HTTP ${api_resp} (may need initial setup)"
    fi
}

check_nginx() {
    section "Nginx Reverse Proxy"

    check_endpoint "Nginx HTTP" "http://localhost:8880" "302"
    # HTTPS server block is disabled by default (development mode)
    # Uncomment the SSL block in nginx.conf and enable this check for production
    # check_endpoint "Nginx HTTPS" "https://localhost:8443" "200"
}

# ==============================================================================
# Main
# ==============================================================================
main() {
    if [[ "${QUIET}" == "false" ]] && [[ "${JSON_OUTPUT}" == "false" ]]; then
        echo ""
        echo -e "${BOLD}${CYAN}  WazuhBOTS — Health Check${NC}"
        echo -e "  $(date '+%Y-%m-%d %H:%M:%S %Z')"
    fi

    check_containers
    check_wazuh_api
    check_wazuh_indexer
    check_ctfd
    check_nginx

    # Summary
    if [[ "${JSON_OUTPUT}" == "true" ]]; then
        local json_arr
        json_arr=$(printf '%s,' "${JSON_RESULTS[@]}")
        json_arr="[${json_arr%,}]"
        echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"total\":${TOTAL_CHECKS},\"passed\":${PASSED_CHECKS},\"failed\":${FAILED_CHECKS},\"results\":${json_arr}}"
    elif [[ "${QUIET}" == "false" ]]; then
        echo ""
        echo -e "  ${BOLD}────────────────────────────────────────────${NC}"
        if [[ "${FAILED_CHECKS}" -eq 0 ]]; then
            echo -e "  ${GREEN}${BOLD}  All ${TOTAL_CHECKS} checks passed.${NC}"
        else
            echo -e "  ${RED}${BOLD}  ${FAILED_CHECKS}/${TOTAL_CHECKS} checks failed.${NC}"
        fi
        echo -e "  ${BOLD}────────────────────────────────────────────${NC}"
        echo ""
    fi

    # Exit code: 0 if all checks passed, 1 otherwise
    [[ "${FAILED_CHECKS}" -eq 0 ]]
}

main "$@"
