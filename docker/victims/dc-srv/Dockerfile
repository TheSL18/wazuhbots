# ============================================
# WazuhBOTS — dc-srv (Scenario 2: Iron Gate)
# Active Directory simulation with Windows-like logs
# Simulates AD environment via Sysmon-style JSON logs
# ============================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV WAZUH_MANAGER=wazuh-manager
ENV WAZUH_AGENT_GROUP=victims
ENV WAZUH_AGENT_NAME=dc-srv

# Install base packages
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    sudo \
    python3 \
    python3-pip \
    gnupg \
    apt-transport-https \
    lsb-release \
    cron \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Wazuh Agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER=${WAZUH_MANAGER} apt-get install -y wazuh-agent && \
    rm -rf /var/lib/apt/lists/*

# Create directory for simulated Windows event logs
RUN mkdir -p /var/log/windows-events /opt/wazuhbots/ad-sim

COPY entrypoint.sh /entrypoint.sh
COPY ad_log_simulator.py /opt/wazuhbots/ad-sim/
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
