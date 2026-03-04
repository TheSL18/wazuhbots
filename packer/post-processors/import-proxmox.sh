#!/usr/bin/env bash
# ==============================================================================
# WazuhBOTS — Import Packer LXC rootfs into Proxmox as a template
#
# Called automatically by Packer as a post-processor.
# Can also be run manually:
#   bash import-proxmox.sh <VMID> <STORAGE> <CORES> <MEMORY> <DISK> <HOSTNAME>
#
# Author: MrHacker (Kevin Munoz)
# ==============================================================================
set -euo pipefail

VMID="${1:-9000}"
STORAGE="${2:-local}"
CORES="${3:-8}"
MEMORY="${4:-16384}"
DISK_SIZE="${5:-120G}"
HOSTNAME="${6:-wazuhbots}"

TARBALL_DIR="output"
TEMPLATE_CACHE="/var/lib/vz/template/cache"
TEMPLATE_NAME="wazuhbots-lxc-rootfs.tar.gz"

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

# ------------------------------------------------------------------------------
# Preflight checks
# ------------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
    log_error "This script must be run as root on a Proxmox host."
    exit 1
fi

if ! command -v pct &>/dev/null; then
    log_error "pct not found. This script must run on a Proxmox VE host."
    exit 1
fi

# ------------------------------------------------------------------------------
# Step 1: Set vm.max_map_count on the host
# ------------------------------------------------------------------------------
log_info "Checking host sysctl settings..."

current_map_count=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if [[ "${current_map_count}" -lt 262144 ]]; then
    log_info "Setting vm.max_map_count=262144 on host..."
    sysctl -w vm.max_map_count=262144
    if ! grep -q "vm.max_map_count" /etc/sysctl.d/99-wazuhbots.conf 2>/dev/null; then
        echo "vm.max_map_count=262144" > /etc/sysctl.d/99-wazuhbots.conf
        log_ok "Persisted in /etc/sysctl.d/99-wazuhbots.conf"
    fi
fi
log_ok "vm.max_map_count = $(sysctl -n vm.max_map_count)"

# ------------------------------------------------------------------------------
# Step 2: Find and prepare the rootfs tarball
# ------------------------------------------------------------------------------
log_info "Locating rootfs tarball..."

# Find the tarball produced by the LXC builder
tarball=""
for f in "${TARBALL_DIR}"/rootfs.tar.gz "${TARBALL_DIR}"/*.tar.gz; do
    if [[ -f "${f}" ]]; then
        tarball="${f}"
        break
    fi
done

if [[ -z "${tarball}" ]]; then
    log_error "No rootfs tarball found in ${TARBALL_DIR}/."
    log_error "Make sure Packer build completed successfully."
    exit 1
fi

log_info "Found tarball: ${tarball} ($(du -h "${tarball}" | cut -f1))"

# Some LXC builders produce tarballs with a rootfs/ prefix.
# Proxmox expects files at the root level. Repackage if needed.
if tar tzf "${tarball}" 2>/dev/null | head -1 | grep -q '^rootfs/'; then
    log_info "Tarball has rootfs/ prefix — repackaging for Proxmox..."
    tmp_dir=$(mktemp -d)
    tar xzf "${tarball}" -C "${tmp_dir}"
    repackaged="${TARBALL_DIR}/${TEMPLATE_NAME}"
    tar czf "${repackaged}" -C "${tmp_dir}/rootfs" .
    rm -rf "${tmp_dir}"
    tarball="${repackaged}"
    log_ok "Repackaged: ${tarball}"
fi

# ------------------------------------------------------------------------------
# Step 3: Copy tarball to template cache
# ------------------------------------------------------------------------------
log_info "Copying tarball to ${TEMPLATE_CACHE}..."
mkdir -p "${TEMPLATE_CACHE}"
cp "${tarball}" "${TEMPLATE_CACHE}/${TEMPLATE_NAME}"
log_ok "Template stored at ${TEMPLATE_CACHE}/${TEMPLATE_NAME}"

# ------------------------------------------------------------------------------
# Step 4: Create LXC container from tarball
# ------------------------------------------------------------------------------
log_info "Creating LXC container VMID ${VMID}..."

# Remove existing container with same VMID if it exists
if pct status "${VMID}" &>/dev/null; then
    log_warn "VMID ${VMID} already exists. Destroying..."
    pct stop "${VMID}" 2>/dev/null || true
    pct destroy "${VMID}" --force 2>/dev/null || true
fi

pct create "${VMID}" "${TEMPLATE_CACHE}/${TEMPLATE_NAME}" \
    --hostname "${HOSTNAME}" \
    --cores "${CORES}" \
    --memory "${MEMORY}" \
    --swap 2048 \
    --rootfs "${STORAGE}:${DISK_SIZE%%G*}" \
    --ostype ubuntu \
    --features "nesting=1,keyctl=1" \
    --unprivileged 0 \
    --start 0 \
    --onboot 0 \
    --description "WazuhBOTS CTF Platform — Boss of the SOC (Wazuh SIEM + CTFd)"

log_ok "LXC container created (VMID: ${VMID})"

# ------------------------------------------------------------------------------
# Step 5: Add Docker-in-LXC configuration
# ------------------------------------------------------------------------------
log_info "Applying Docker-in-LXC configuration..."

LXC_CONF="/etc/pve/lxc/${VMID}.conf"

cat >> "${LXC_CONF}" << 'EOF'

# Docker-in-LXC: Required for running Docker inside this container
lxc.apparmor.profile: unconfined
lxc.cgroup2.devices.allow: a
lxc.cap.drop:
lxc.mount.auto: proc:rw sys:rw
EOF

log_ok "Docker-in-LXC config applied to ${LXC_CONF}"

# ------------------------------------------------------------------------------
# Step 6: Convert to template
# ------------------------------------------------------------------------------
log_info "Converting VMID ${VMID} to template..."

pct template "${VMID}"

log_ok "Template created successfully!"

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo -e "${GREEN}${BOLD}  WazuhBOTS LXC Template Ready!${NC}"
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo ""
echo "  Template VMID: ${VMID}"
echo "  Storage: ${STORAGE}"
echo "  Resources: ${CORES} cores, $((MEMORY / 1024)) GB RAM, ${DISK_SIZE} disk"
echo ""
echo "  Usage:"
echo "    # Clone a new instance"
echo "    pct clone ${VMID} 100 --hostname wazuhbots-ctf --full"
echo ""
echo "    # Configure networking"
echo "    pct set 100 --net0 \"name=eth0,bridge=vmbr0,ip=10.0.0.100/24,gw=10.0.0.1\""
echo ""
echo "    # Start the instance (first-boot takes ~15-25 min)"
echo "    pct start 100"
echo ""
echo "    # Monitor first-boot progress"
echo "    pct exec 100 -- journalctl -u wazuhbots-firstboot -f"
echo ""
echo -e "${GREEN}${BOLD}================================================================${NC}"
