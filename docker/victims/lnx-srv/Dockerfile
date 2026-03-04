# ============================================
# WazuhBOTS — lnx-srv (Scenario 3: Ghost in the Shell)
# Linux server with SSH exposed + auditd
# ============================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV WAZUH_MANAGER=wazuh-manager
ENV WAZUH_AGENT_GROUP=victims
ENV WAZUH_AGENT_NAME=lnx-srv

# Install base packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    auditd \
    audispd-plugins \
    curl \
    wget \
    sudo \
    cron \
    net-tools \
    iproute2 \
    gnupg \
    apt-transport-https \
    lsb-release \
    python3 \
    python3-pip \
    openssl \
    vim \
    htop \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Wazuh Agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER=${WAZUH_MANAGER} apt-get install -y wazuh-agent && \
    rm -rf /var/lib/apt/lists/*

# Configure SSH with weak settings (intentionally vulnerable)
RUN mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 20/' /etc/ssh/sshd_config

# Create vulnerable users with weak passwords
# Use openssl passwd + useradd -p to avoid chpasswd (fails in Podman rootless builds)
# Note: 'backup' user exists in base image, use 'backupadm' instead
RUN useradd -m -s /bin/bash -p "$(openssl passwd -6 'Summer2026!')" sysadmin && \
    usermod -aG sudo sysadmin && \
    useradd -m -s /bin/bash -p "$(openssl passwd -6 'password123')" devops && \
    useradd -m -s /bin/bash -p "$(openssl passwd -6 'backup2026')" backupadm

# Configure auditd rules for kernel module monitoring
COPY audit.rules /etc/audit/rules.d/wazuhbots.rules

# Place some "sensitive" files
RUN mkdir -p /opt/company/configs && \
    printf 'DB_HOST=prod-db.corp.local\nDB_USER=admin\nDB_PASS=Pr0duct10n!\n' > /opt/company/configs/database.conf && \
    echo 'API_KEY=sk-prod-a1b2c3d4e5f6g7h8i9j0' > /opt/company/configs/api_keys.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
