# ============================================
# WazuhBOTS — web-srv (Scenario 1: Dark Harvest)
# Vulnerable web application with Wazuh Agent
# Apache + DVWA + MySQL + PHP
# ============================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV WAZUH_MANAGER=wazuh-manager
ENV WAZUH_AGENT_GROUP=victims
ENV WAZUH_AGENT_NAME=web-srv

# Install base packages
RUN apt-get update && apt-get install -y \
    apache2 \
    php \
    php-mysql \
    php-gd \
    php-xml \
    php-mbstring \
    mariadb-server \
    mariadb-client \
    curl \
    wget \
    git \
    sudo \
    cron \
    net-tools \
    iproute2 \
    gnupg \
    apt-transport-https \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Install Wazuh Agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER=${WAZUH_MANAGER} apt-get install -y wazuh-agent && \
    rm -rf /var/lib/apt/lists/*

# Clone DVWA (Damn Vulnerable Web Application)
RUN git clone https://github.com/digininja/DVWA.git /var/www/html/dvwa && \
    chown -R www-data:www-data /var/www/html/dvwa && \
    chmod -R 755 /var/www/html/dvwa

# Configure DVWA
COPY dvwa-config.php /var/www/html/dvwa/config/config.inc.php

# Configure Apache
RUN a2enmod rewrite && \
    echo "ServerName web-srv" >> /etc/apache2/apache2.conf

# Configure Wazuh Agent for FIM and log collection
COPY wazuh-agent.conf /var/ossec/etc/local_internal_options.conf

# Enable additional logging
RUN echo "CustomLog /var/log/apache2/access_detailed.log combined" >> /etc/apache2/apache2.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 3306

ENTRYPOINT ["/entrypoint.sh"]
