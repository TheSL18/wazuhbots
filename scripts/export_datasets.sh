#!/usr/bin/env bash
# ==============================================================================
# WazuhBOTS -- Export Datasets from Wazuh Indexer
#
# Exports alert data from the Wazuh Indexer (OpenSearch) to JSON files
# organized by scenario, and optionally creates index snapshots for
# backup or distribution.
#
# Usage:
#   ./scripts/export_datasets.sh --all                    # Export all scenarios
#   ./scripts/export_datasets.sh --scenario 1             # Export scenario 1 only
#   ./scripts/export_datasets.sh --all --snapshot         # Also create snapshots
#   ./scripts/export_datasets.sh --all --date-range       # Specify date range
#   ./scripts/export_datasets.sh --indices                # List available indices
#
# Author: MrHacker (Kevin Munoz) -- Wazuh Technology Ambassador
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
DATASETS_DIR="${PROJECT_ROOT}/datasets"
ENV_FILE="${PROJECT_ROOT}/.env"

# ------------------------------------------------------------------------------
# Load environment
# ------------------------------------------------------------------------------
if [[ -f "${ENV_FILE}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
fi

INDEXER_URL="${INDEXER_URL:-https://localhost:9200}"
INDEXER_USER="${INDEXER_USERNAME:-admin}"
INDEXER_PASS="${INDEXER_PASSWORD:-admin}"

# OpenSearch scroll API settings
SCROLL_SIZE=1000       # Documents per scroll page
SCROLL_TTL="5m"        # Scroll context lifetime

# ------------------------------------------------------------------------------
# Scenario definitions
# Maps scenario numbers to their directory names and the Wazuh index patterns
# to export for each.
# ------------------------------------------------------------------------------
declare -A SCENARIO_NAMES
SCENARIO_NAMES[1]="scenario1_dark_harvest"
SCENARIO_NAMES[2]="scenario2_iron_gate"
SCENARIO_NAMES[3]="scenario3_ghost_shell"
SCENARIO_NAMES[4]="scenario4_supply_chain"

declare -A SCENARIO_AGENTS
SCENARIO_AGENTS[1]="web-srv"
SCENARIO_AGENTS[2]="dc-srv"
SCENARIO_AGENTS[3]="lnx-srv"
SCENARIO_AGENTS[4]=""  # multi-host

declare -A SCENARIO_DESCRIPTIONS
SCENARIO_DESCRIPTIONS[1]="Operation Dark Harvest - Web Application Compromise"
SCENARIO_DESCRIPTIONS[2]="Iron Gate - Active Directory Compromise"
SCENARIO_DESCRIPTIONS[3]="Ghost in the Shell - Linux Server Compromise"
SCENARIO_DESCRIPTIONS[4]="Supply Chain Phantom - Multi-Vector Advanced"

# ------------------------------------------------------------------------------
# CLI flags
# ------------------------------------------------------------------------------
SCENARIO=""
EXPORT_ALL=false
CREATE_SNAPSHOT=false
LIST_INDICES=false
DATE_FROM=""
DATE_TO=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --all)       EXPORT_ALL=true ;;
            --scenario)  shift; SCENARIO="$1" ;;
            --snapshot)  CREATE_SNAPSHOT=true ;;
            --indices)   LIST_INDICES=true ;;
            --from)      shift; DATE_FROM="$1" ;;
            --to)        shift; DATE_TO="$1" ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --all                 Export all scenarios"
                echo "  --scenario N          Export scenario N (1-4)"
                echo "  --snapshot            Create OpenSearch index snapshots"
                echo "  --indices             List available Wazuh indices"
                echo "  --from YYYY-MM-DD     Start date filter"
                echo "  --to YYYY-MM-DD       End date filter"
                echo "  --help                Show this help"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                exit 1
                ;;
        esac
        shift
    done
}

# ------------------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------------------
log_info()  { echo -e "${CYAN}[*]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[!]${NC} $*"; }
log_step()  { echo -e "\n${BOLD}${CYAN}==> $*${NC}"; }

# Authenticated curl wrapper for the Wazuh Indexer
indexer_curl() {
    curl -sk --max-time 60 -u "${INDEXER_USER}:${INDEXER_PASS}" "$@"
}

# ------------------------------------------------------------------------------
# Check Indexer connectivity
# ------------------------------------------------------------------------------
check_indexer() {
    log_info "Connecting to Wazuh Indexer at ${INDEXER_URL}..."
    local resp
    resp=$(indexer_curl "${INDEXER_URL}" 2>/dev/null || echo "")
    if [[ -z "${resp}" ]]; then
        log_error "Cannot connect to Wazuh Indexer at ${INDEXER_URL}"
        exit 1
    fi

    local version
    version=$(echo "${resp}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',{}).get('number','unknown'))" 2>/dev/null || echo "unknown")
    log_ok "Connected (version: ${version})"
}

# ------------------------------------------------------------------------------
# List indices
# ------------------------------------------------------------------------------
list_indices() {
    log_step "Available Wazuh Indices"
    echo ""

    local indices
    indices=$(indexer_curl "${INDEXER_URL}/_cat/indices?v&s=index" 2>/dev/null || echo "")

    if [[ -z "${indices}" ]]; then
        log_error "Failed to list indices"
        return 1
    fi

    # Filter to show only relevant indices
    echo "${indices}" | head -1  # header
    echo "${indices}" | grep -E "(wazuh-|wazuhbots-)" | sort || echo "  (no Wazuh indices found)"
    echo ""

    # Show document counts
    local alert_count
    alert_count=$(indexer_curl "${INDEXER_URL}/wazuh-alerts-*/_count" 2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0")
    log_info "Total documents in wazuh-alerts-*: ${alert_count}"
}

# ------------------------------------------------------------------------------
# Export index to JSON file using the scroll API
#
# The scroll API is used for large exports to avoid loading everything into
# memory at once. Documents are fetched in pages of SCROLL_SIZE.
# ------------------------------------------------------------------------------
export_index() {
    local index_pattern="$1"
    local output_file="$2"
    local agent_filter="${3:-}"
    local description="${4:-}"

    log_info "Exporting: ${index_pattern} -> $(basename "${output_file}")"

    # Build the query
    local query='{"match_all":{}}'

    # Apply agent filter if specified
    if [[ -n "${agent_filter}" ]]; then
        query="{\"bool\":{\"must\":[{\"match\":{\"agent.name\":\"${agent_filter}\"}}]}}"
    fi

    # Apply date range filter if specified
    if [[ -n "${DATE_FROM}" ]] || [[ -n "${DATE_TO}" ]]; then
        local range_clause='{"range":{"timestamp":{'
        local range_parts=()
        [[ -n "${DATE_FROM}" ]] && range_parts+=("\"gte\":\"${DATE_FROM}\"")
        [[ -n "${DATE_TO}" ]]   && range_parts+=("\"lte\":\"${DATE_TO}\"")
        range_clause+=$(IFS=,; echo "${range_parts[*]}")
        range_clause+='}}}'

        if [[ -n "${agent_filter}" ]]; then
            query="{\"bool\":{\"must\":[{\"match\":{\"agent.name\":\"${agent_filter}\"}},${range_clause}]}}"
        else
            query="{\"bool\":{\"must\":[${range_clause}]}}"
        fi
    fi

    # Initial scroll request
    local scroll_body="{\"size\":${SCROLL_SIZE},\"query\":${query}}"

    local response
    response=$(indexer_curl -X POST \
        "${INDEXER_URL}/${index_pattern}/_search?scroll=${SCROLL_TTL}" \
        -H "Content-Type: application/json" \
        -d "${scroll_body}" 2>/dev/null || echo "")

    if [[ -z "${response}" ]]; then
        log_warn "No response for index pattern: ${index_pattern}"
        return 1
    fi

    # Parse initial response
    local scroll_id
    scroll_id=$(echo "${response}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('_scroll_id',''))" 2>/dev/null || echo "")
    local total_hits
    total_hits=$(echo "${response}" | python3 -c "import sys,json; d=json.load(sys.stdin); h=d.get('hits',{}).get('total',{}); print(h.get('value',0) if isinstance(h,dict) else h)" 2>/dev/null || echo "0")

    if [[ "${total_hits}" -eq 0 ]]; then
        log_warn "No documents found in ${index_pattern}"
        echo "[]" > "${output_file}"
        return 0
    fi

    log_info "Found ${total_hits} documents to export"

    # Extract documents page by page
    local exported=0
    echo "[" > "${output_file}"
    local first_page=true

    while true; do
        # Extract hits from current page
        local hits
        hits=$(echo "${response}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
hits = data.get('hits', {}).get('hits', [])
for i, hit in enumerate(hits):
    src = hit.get('_source', {})
    if i > 0:
        print(',')
    print(json.dumps(src))
" 2>/dev/null || echo "")

        local page_count
        page_count=$(echo "${response}" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('hits',{}).get('hits',[])))" 2>/dev/null || echo "0")

        if [[ "${page_count}" -eq 0 ]]; then
            break
        fi

        # Append to output file
        if [[ "${first_page}" == "true" ]]; then
            first_page=false
        else
            echo "," >> "${output_file}"
        fi
        echo "${hits}" >> "${output_file}"

        exported=$(( exported + page_count ))

        # Progress
        local pct=0
        if [[ "${total_hits}" -gt 0 ]]; then
            pct=$(( exported * 100 / total_hits ))
        fi
        printf "\r  Progress: %d/%d documents (%d%%)" "${exported}" "${total_hits}" "${pct}"

        # Fetch next page
        response=$(indexer_curl -X POST \
            "${INDEXER_URL}/_search/scroll" \
            -H "Content-Type: application/json" \
            -d "{\"scroll\":\"${SCROLL_TTL}\",\"scroll_id\":\"${scroll_id}\"}" 2>/dev/null || echo "")

        if [[ -z "${response}" ]]; then
            break
        fi

        # Update scroll_id (may change between pages)
        scroll_id=$(echo "${response}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('_scroll_id',''))" 2>/dev/null || echo "")
    done

    echo "" >> "${output_file}"
    echo "]" >> "${output_file}"
    echo ""  # newline after progress bar

    # Clean up scroll context
    if [[ -n "${scroll_id}" ]]; then
        indexer_curl -X DELETE "${INDEXER_URL}/_search/scroll" \
            -H "Content-Type: application/json" \
            -d "{\"scroll_id\":\"${scroll_id}\"}" &>/dev/null || true
    fi

    local file_size
    file_size=$(du -h "${output_file}" | cut -f1)
    log_ok "Exported ${exported} documents (${file_size}) to $(basename "${output_file}")"
    return 0
}

# ------------------------------------------------------------------------------
# Create metadata file for a scenario export
# ------------------------------------------------------------------------------
create_metadata() {
    local scenario_num="$1"
    local output_dir="$2"
    local doc_count="$3"

    local name="${SCENARIO_NAMES[${scenario_num}]}"
    local desc="${SCENARIO_DESCRIPTIONS[${scenario_num}]}"
    local agent="${SCENARIO_AGENTS[${scenario_num}]}"
    local export_date
    export_date=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    cat > "${output_dir}/metadata.json" <<EOF
{
  "scenario": "${name}",
  "description": "${desc}",
  "export_date": "${export_date}",
  "primary_agent": "${agent}",
  "date_filter_from": "${DATE_FROM:-none}",
  "date_filter_to": "${DATE_TO:-none}",
  "total_documents_exported": ${doc_count},
  "indexer_url": "${INDEXER_URL}",
  "wazuhbots_version": "1.0"
}
EOF

    log_ok "Metadata written to ${output_dir}/metadata.json"
}

# ------------------------------------------------------------------------------
# Export a single scenario
# ------------------------------------------------------------------------------
export_scenario() {
    local scenario_num="$1"

    local name="${SCENARIO_NAMES[${scenario_num}]:-}"
    if [[ -z "${name}" ]]; then
        log_error "Unknown scenario number: ${scenario_num}"
        return 1
    fi

    local desc="${SCENARIO_DESCRIPTIONS[${scenario_num}]}"
    local agent="${SCENARIO_AGENTS[${scenario_num}]}"
    local output_dir="${DATASETS_DIR}/${name}"

    log_step "Exporting Scenario ${scenario_num}: ${desc}"
    log_info "Output directory: ${output_dir}"

    mkdir -p "${output_dir}"

    local total_docs=0

    # Export wazuh-alerts (filtered by agent if applicable)
    export_index "wazuh-alerts-*" "${output_dir}/wazuh-alerts.json" "${agent}" "Wazuh Alerts"
    total_docs=$(( total_docs + $(python3 -c "import json; print(len(json.load(open('${output_dir}/wazuh-alerts.json'))))" 2>/dev/null || echo 0) ))

    # Export archives if they exist
    local archives_count
    archives_count=$(indexer_curl "${INDEXER_URL}/wazuh-archives-*/_count" 2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0")
    if [[ "${archives_count}" -gt 0 ]]; then
        export_index "wazuh-archives-*" "${output_dir}/wazuh-archives.json" "${agent}" "Wazuh Archives"
    fi

    # Scenario-specific index exports
    case "${scenario_num}" in
        1)
            # FIM events for web-srv
            export_index "wazuh-alerts-*" "${output_dir}/fim-events.json" "${agent}" "FIM Events" || true
            ;;
        2)
            # Windows security events (simulated)
            export_index "wazuh-alerts-*" "${output_dir}/windows-security.json" "${agent}" "Windows Security" || true
            ;;
        3)
            # Auditd events from lnx-srv
            export_index "wazuh-alerts-*" "${output_dir}/auditd-events.json" "${agent}" "Auditd Events" || true
            ;;
    esac

    # Export any WazuhBOTS-specific indices for this scenario
    local bots_indices
    bots_indices=$(indexer_curl "${INDEXER_URL}/_cat/indices/wazuhbots-${name}-*?h=index" 2>/dev/null || echo "")
    if [[ -n "${bots_indices}" ]]; then
        while IFS= read -r idx; do
            idx=$(echo "${idx}" | tr -d '[:space:]')
            [[ -z "${idx}" ]] && continue
            local stem="${idx#wazuhbots-${name}-}"
            export_index "${idx}" "${output_dir}/${stem}.json" "" "${stem}" || true
        done <<< "${bots_indices}"
    fi

    # Write metadata
    create_metadata "${scenario_num}" "${output_dir}" "${total_docs}"
}

# ------------------------------------------------------------------------------
# Create OpenSearch snapshot
# ------------------------------------------------------------------------------
create_snapshot() {
    log_step "Creating OpenSearch index snapshot"

    local snapshot_name="wazuhbots-$(date +%Y%m%d-%H%M%S)"
    local repo_name="wazuhbots_backup"

    # Register snapshot repository (filesystem-based)
    log_info "Registering snapshot repository: ${repo_name}"
    local reg_resp
    reg_resp=$(indexer_curl -X PUT \
        "${INDEXER_URL}/_snapshot/${repo_name}" \
        -H "Content-Type: application/json" \
        -d "{
            \"type\": \"fs\",
            \"settings\": {
                \"location\": \"/snapshots/wazuhbots\",
                \"compress\": true
            }
        }" 2>/dev/null || echo "")

    if echo "${reg_resp}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('acknowledged')" 2>/dev/null; then
        log_ok "Snapshot repository registered"
    else
        log_warn "Could not register snapshot repository. Ensure path.repo is configured."
        log_info "Response: ${reg_resp}"
        return 1
    fi

    # Create snapshot of all Wazuh and WazuhBOTS indices
    log_info "Creating snapshot: ${snapshot_name}"
    local snap_resp
    snap_resp=$(indexer_curl -X PUT \
        "${INDEXER_URL}/_snapshot/${repo_name}/${snapshot_name}?wait_for_completion=true" \
        -H "Content-Type: application/json" \
        -d "{
            \"indices\": \"wazuh-*,wazuhbots-*\",
            \"ignore_unavailable\": true,
            \"include_global_state\": false
        }" 2>/dev/null || echo "")

    local snap_state
    snap_state=$(echo "${snap_resp}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('snapshot',{}).get('state','UNKNOWN'))" 2>/dev/null || echo "UNKNOWN")

    if [[ "${snap_state}" == "SUCCESS" ]]; then
        local shard_count
        shard_count=$(echo "${snap_resp}" | python3 -c "import sys,json; s=json.load(sys.stdin).get('snapshot',{}).get('shards',{}); print(f\"{s.get('successful',0)}/{s.get('total',0)} shards\")" 2>/dev/null || echo "unknown")
        log_ok "Snapshot '${snapshot_name}' created successfully (${shard_count})"
    else
        log_warn "Snapshot state: ${snap_state}"
        log_info "This may be a permissions issue. Ensure the indexer has write access to /snapshots/"
    fi
}

# ==============================================================================
# Main
# ==============================================================================
main() {
    parse_args "$@"

    echo ""
    echo -e "${BOLD}${CYAN}  WazuhBOTS -- Dataset Export Tool${NC}"
    echo -e "  $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo ""

    check_indexer

    # List mode
    if [[ "${LIST_INDICES}" == "true" ]]; then
        list_indices
        exit 0
    fi

    # Require --all or --scenario
    if [[ "${EXPORT_ALL}" != "true" ]] && [[ -z "${SCENARIO}" ]]; then
        echo "  Usage: $0 [--all | --scenario N] [--snapshot] [--from DATE] [--to DATE]"
        echo ""
        echo "  Available scenarios:"
        for num in "${!SCENARIO_DESCRIPTIONS[@]}"; do
            echo "    ${num} - ${SCENARIO_DESCRIPTIONS[${num}]}"
        done | sort
        echo ""
        exit 0
    fi

    # Run exports
    local start_time
    start_time=$(date +%s)

    if [[ "${EXPORT_ALL}" == "true" ]]; then
        for num in $(echo "${!SCENARIO_NAMES[@]}" | tr ' ' '\n' | sort -n); do
            export_scenario "${num}"
        done
    else
        export_scenario "${SCENARIO}"
    fi

    # Optionally create snapshot
    if [[ "${CREATE_SNAPSHOT}" == "true" ]]; then
        create_snapshot
    fi

    # Summary
    local elapsed=$(( $(date +%s) - start_time ))
    local total_size
    total_size=$(du -sh "${DATASETS_DIR}" 2>/dev/null | cut -f1 || echo "unknown")

    echo ""
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo -e "${GREEN}${BOLD}  Dataset export complete!${NC}"
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo ""
    echo -e "  Output directory: ${CYAN}${DATASETS_DIR}/${NC}"
    echo -e "  Total size:       ${CYAN}${total_size}${NC}"
    echo -e "  Elapsed time:     ${CYAN}${elapsed}s${NC}"
    echo ""
    echo -e "  ${BOLD}Dataset structure:${NC}"
    find "${DATASETS_DIR}" -name "*.json" -type f | sort | while read -r f; do
        local fsize
        fsize=$(du -h "${f}" | cut -f1)
        local rel="${f#${DATASETS_DIR}/}"
        echo -e "    ${CYAN}${rel}${NC} (${fsize})"
    done
    echo ""
}

main "$@"
