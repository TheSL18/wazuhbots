#!/bin/bash
set -e

echo "[WazuhBOTS] Starting web-srv (Scenario 1: Dark Harvest)..."

# Configure Wazuh Agent
if [ -n "$WAZUH_MANAGER" ]; then
    sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|" /var/ossec/etc/ossec.conf
fi

if [ -n "$WAZUH_AGENT_NAME" ]; then
    sed -i "s|<agent_name>.*</agent_name>|<agent_name>${WAZUH_AGENT_NAME}</agent_name>|" /var/ossec/etc/ossec.conf 2>/dev/null || true
fi

# Start MariaDB
echo "[WazuhBOTS] Starting MariaDB..."
service mariadb start
sleep 3

# Setup DVWA database
mysql -u root -e "CREATE DATABASE IF NOT EXISTS dvwa;"
mysql -u root -e "CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';"
mysql -u root -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';"
mysql -u root -e "FLUSH PRIVILEGES;"

# Create a "sensitive" database for exfiltration scenario
mysql -u root -e "CREATE DATABASE IF NOT EXISTS company_data;"
mysql -u root -e "USE company_data; CREATE TABLE IF NOT EXISTS employees (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100), email VARCHAR(100), ssn VARCHAR(20), salary DECIMAL(10,2));"
mysql -u root -e "USE company_data; INSERT IGNORE INTO employees (name, email, ssn, salary) VALUES ('John Smith', 'jsmith@corp.local', '123-45-6789', 85000.00), ('Jane Doe', 'jdoe@corp.local', '987-65-4321', 92000.00), ('Bob Wilson', 'bwilson@corp.local', '456-78-9012', 78000.00);"
mysql -u root -e "GRANT ALL PRIVILEGES ON company_data.* TO 'dvwa'@'localhost';"

# Start Apache
echo "[WazuhBOTS] Starting Apache..."
service apache2 start

# Start Wazuh Agent
echo "[WazuhBOTS] Starting Wazuh Agent..."
/var/ossec/bin/wazuh-control start

# Start cron for legitimate traffic simulation
service cron start

echo "[WazuhBOTS] web-srv ready!"
echo "[WazuhBOTS] DVWA available at http://web-srv/dvwa"

# Keep container running
tail -f /var/log/apache2/access.log /var/log/apache2/error.log /var/ossec/logs/ossec.log 2>/dev/null
