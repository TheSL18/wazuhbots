#!/usr/bin/env bash
## WazuhBOTS Packer — Step 1: System base packages + Docker CE
set -euo pipefail

echo "▶ [01] Installing base packages..."

apt-get update -qq
apt-get upgrade -y -qq

apt-get install -y -qq \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    python3 \
    python3-pip \
    openssl \
    jq \
    git \
    make \
    net-tools \
    sudo \
    systemd \
    systemd-sysv \
    dbus \
    iproute2 \
    iptables \
    kmod \
    procps

echo "▶ [01] Adding Docker CE repository..."

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list

apt-get update -qq

echo "▶ [01] Installing Docker CE..."

apt-get install -y -qq \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-compose-plugin \
    docker-buildx-plugin

systemctl enable docker

echo "▶ [01] Installing Python dependencies..."

pip3 install --no-cache-dir requests

echo "✓ [01] System base installation complete."
