# WazuhBOTS -- Deployment Guide

This guide covers everything needed to deploy WazuhBOTS, from a local development setup on a single machine to a production deployment in the cloud serving dozens of participants.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step-by-Step Installation](#step-by-step-installation)
- [Configuration Options](#configuration-options)
- [Service Verification](#service-verification)
- [Troubleshooting](#troubleshooting)
- [Cloud Deployment](#cloud-deployment)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)

---

## Prerequisites

### Software Requirements

| Software         | Minimum Version | Purpose                         | Installation                                       |
|------------------|-----------------|---------------------------------|----------------------------------------------------|
| Docker Engine    | 20.10+          | Container runtime               | https://docs.docker.com/engine/install/            |
| Docker Compose   | 2.0+ (plugin)   | Multi-container orchestration   | Included with Docker Desktop, or install separately|
| Python 3         | 3.8+            | Dataset ingestion and scripting | Pre-installed on most Linux distributions          |
| curl             | 7.x+            | Health checks and API calls     | Pre-installed on most systems                      |
| openssl          | 1.1+            | Secure password generation      | Pre-installed on most systems                      |

**Note:** Both `docker compose` (plugin, recommended) and the standalone `docker-compose` binary are supported. The setup script auto-detects which is available.

### Hardware Requirements

| Deployment Target              | CPU      | RAM    | Disk        |
|--------------------------------|----------|--------|-------------|
| Development / Personal         | 4 cores  | 16 GB  | 100 GB SSD  |
| Meetup (10--20 participants)   | 8 cores  | 32 GB  | 200 GB SSD  |
| CTF Public (50+ participants)  | 16 cores | 64 GB  | 500 GB SSD  |
| Corporate Training             | 8 cores  | 32 GB  | 200 GB SSD  |

**Disk I/O matters.** Wazuh Indexer (OpenSearch) is I/O intensive. SSD or NVMe storage is strongly recommended. HDD-based deployments will experience significant performance degradation during searches.

### Network Requirements

The following ports are used by the stack. Ensure they are available on the host or configure alternatives in `.env`:

| Port  | Protocol | Service             | Access                     |
|-------|----------|---------------------|----------------------------|
| 80    | TCP      | Nginx (HTTP)        | Participants (redirects to HTTPS) |
| 443   | TCP      | Nginx (HTTPS)       | Participants               |
| 5601  | TCP      | Wazuh Dashboard     | Participants / Admin       |
| 8000  | TCP      | CTFd                | Participants               |
| 9200  | TCP      | Wazuh Indexer       | Internal only              |
| 1514  | TCP      | Wazuh Agent comms   | Internal only              |
| 1515  | TCP      | Wazuh Agent enrollment | Internal only           |
| 55000 | TCP      | Wazuh API           | Admin only                 |

### Operating System

WazuhBOTS is tested on:
- Ubuntu 22.04 / 24.04 LTS
- Debian 12
- Rocky Linux 9 / AlmaLinux 9
- Arch Linux
- macOS (Docker Desktop) -- for development only

**vm.max_map_count:** Wazuh Indexer (OpenSearch) requires the kernel parameter `vm.max_map_count` to be at least 262144. On Linux, set it with:

```bash
# Temporary (resets on reboot)
sudo sysctl -w vm.max_map_count=262144

# Persistent
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## Step-by-Step Installation

### 1. Clone the Repository

```bash
git clone https://github.com/MrHacker-X/wazuhbots.git
cd wazuhbots
```

### 2. Run the Automated Setup

The setup script handles everything: prerequisite checks, environment generation, container deployment, health verification, dataset ingestion, and challenge loading.

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

**Setup script options:**

| Flag            | Effect                                              |
|-----------------|-----------------------------------------------------|
| `--skip-build`  | Skip building Docker images (use pre-pulled images) |
| `--no-ingest`   | Skip dataset ingestion into Wazuh Indexer           |
| `--no-ctfd`     | Skip loading challenges into CTFd                   |
| `--help`        | Show usage information                              |

The script performs six steps:

1. **Check prerequisites** -- Verifies Docker, Docker Compose, Python 3, curl, and openssl are installed and the Docker daemon is running.
2. **Check system resources** -- Validates available RAM (minimum 8 GB, recommended 16 GB+) and disk space (warns below 20 GB free).
3. **Generate .env** -- Copies `.env.example` to `.env` and replaces placeholder passwords with cryptographically random values. Sets file permissions to 600.
4. **Deploy Docker stack** -- Runs `docker compose up -d --build` to build custom images and start all containers.
5. **Wait for health** -- Polls container health checks for up to 5 minutes until all services report healthy.
6. **Post-deployment** -- Ingests scenario datasets into Wazuh Indexer and loads challenges into CTFd.

### 3. Verify the Deployment

```bash
./scripts/health_check.sh
```

The health check script validates:
- All Docker containers are running
- Wazuh API is reachable and authenticated
- Wazuh Manager daemons are operational
- Wazuh Indexer cluster health is green or yellow
- Dataset indices are present
- CTFd web interface is responding
- Nginx proxy is routing correctly

**Output formats:**

```bash
./scripts/health_check.sh            # Human-readable output
./scripts/health_check.sh --quiet    # Exit code only (0 = healthy)
./scripts/health_check.sh --json     # JSON output for automation
```

### 4. Access the Platform

| Service          | URL                        | Credentials                          |
|------------------|----------------------------|--------------------------------------|
| Wazuh Dashboard  | https://localhost:5601     | `admin` / (see INDEXER_PASSWORD in .env) |
| CTFd Platform    | http://localhost:8000      | Create admin account on first access |
| Wazuh API        | https://localhost:55000    | `wazuh-wui` / (see API_PASSWORD in .env) |
| Nginx Proxy      | https://localhost          | Routes to Dashboard and CTFd         |

**Participant credentials:** The read-only analyst account for Wazuh Dashboard is configured in `.env` as `PARTICIPANT_USER` and `PARTICIPANT_PASSWORD`. Share these with participants so they can investigate alerts without modifying the data.

### 5. Complete CTFd Initial Setup

On first access to CTFd (http://localhost:8000), you will be prompted to create an admin account and configure basic settings. This is a one-time step. After initial setup, challenges should already be loaded by the setup script.

---

## Configuration Options

All configuration is managed through the `.env` file. The `.env.example` file documents every variable:

### Wazuh Stack

| Variable             | Default               | Description                                    |
|----------------------|-----------------------|------------------------------------------------|
| `INDEXER_PASSWORD`   | (auto-generated)      | Password for the Wazuh Indexer admin user       |
| `INDEXER_HEAP`       | `2g`                  | JVM heap size for Wazuh Indexer (OpenSearch)    |
| `DASHBOARD_PASSWORD` | (auto-generated)      | Password for the Wazuh Dashboard backend user   |
| `API_USERNAME`       | `wazuh-wui`           | Wazuh API username                              |
| `API_PASSWORD`       | (auto-generated)      | Wazuh API password                              |

### CTFd Platform

| Variable                | Default            | Description                                |
|-------------------------|--------------------|--------------------------------------------|
| `CTFD_SECRET_KEY`       | (auto-generated)   | Flask secret key for session management    |
| `CTFD_DB_PASSWORD`      | (auto-generated)   | MariaDB password for the CTFd user         |
| `CTFD_DB_ROOT_PASSWORD` | (auto-generated)   | MariaDB root password                      |

### Competition Settings

| Variable                    | Default           | Description                                   |
|-----------------------------|-------------------|-----------------------------------------------|
| `COMPETITION_NAME`          | `WazuhBOTS`       | Name displayed on the CTFd scoreboard         |
| `COMPETITION_MODE`          | `competition`     | Mode: `training`, `competition`, `self-guided`, `public` |
| `COMPETITION_DURATION_HOURS`| `4`               | Duration for timed competitions               |

### Network

| Variable             | Default            | Description                                    |
|----------------------|--------------------|------------------------------------------------|
| `SUBNET`             | `172.25.0.0/24`    | Docker network subnet                          |
| `DOMAIN`             | `wazuhbots.local`  | Domain name for the deployment                 |

### Participant Access

| Variable               | Default              | Description                                  |
|------------------------|----------------------|----------------------------------------------|
| `PARTICIPANT_USER`     | `analyst`            | Read-only Wazuh Dashboard username           |
| `PARTICIPANT_PASSWORD` | `WazuhBOTS2026!`     | Read-only Wazuh Dashboard password           |

### Tuning the Indexer Heap

For production deployments, adjust `INDEXER_HEAP` based on available RAM:

| System RAM | Recommended INDEXER_HEAP |
|------------|--------------------------|
| 16 GB      | 2g                       |
| 32 GB      | 4g                       |
| 64 GB      | 8g                       |

The general rule: allocate no more than 50% of available RAM to the Indexer JVM heap, and never exceed 32 GB (OpenSearch/JVM limitation).

---

## Service Verification

After deployment, verify each component is working correctly.

### Verify Wazuh Manager

```bash
# Check manager status via API
curl -sk -u "wazuh-wui:<API_PASSWORD>" https://localhost:55000/manager/status | python3 -m json.tool

# Check connected agents
curl -sk -u "wazuh-wui:<API_PASSWORD>" https://localhost:55000/agents/summary/status | python3 -m json.tool
```

### Verify Wazuh Indexer

```bash
# Cluster health
curl -sk -u "admin:<INDEXER_PASSWORD>" https://localhost:9200/_cluster/health | python3 -m json.tool

# List indices (should include wazuhbots-* after dataset ingestion)
curl -sk -u "admin:<INDEXER_PASSWORD>" https://localhost:9200/_cat/indices?v
```

### Verify CTFd

```bash
# Check CTFd is responding
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000
# Expected: 200 or 302
```

### Verify Nginx

```bash
# HTTP should redirect to HTTPS
curl -s -o /dev/null -w "%{http_code}" http://localhost
# Expected: 301

# HTTPS should serve content
curl -sk -o /dev/null -w "%{http_code}" https://localhost
# Expected: 200
```

### Container Logs

To inspect logs for a specific service:

```bash
docker compose logs -f wazuh-manager
docker compose logs -f wazuh-indexer
docker compose logs -f wazuh-dashboard
docker compose logs -f ctfd
docker compose logs -f nginx
```

---

## Troubleshooting

### Wazuh Indexer fails to start

**Symptom:** The `wazuhbots-indexer` container exits immediately or enters a restart loop.

**Cause:** Almost always the `vm.max_map_count` kernel parameter.

**Fix:**
```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
docker compose restart wazuh-indexer
```

### Wazuh Dashboard shows "Wazuh API is not reachable"

**Symptom:** Dashboard loads but displays an error about the Wazuh API.

**Cause:** The Manager has not fully initialized, or credentials are mismatched.

**Fix:**
1. Wait 1--2 minutes. The Manager takes time to initialize, especially on first boot.
2. Verify the API is reachable: `curl -sk -u "wazuh-wui:<API_PASSWORD>" https://localhost:55000`
3. If credentials are wrong, check `.env` and restart: `docker compose restart wazuh-dashboard`

### CTFd shows "Setup" page after reset

**Symptom:** After running `reset_environment.sh`, CTFd prompts for initial setup again.

**Cause:** The reset script clears the admin account (keeping only ID 1). If the admin row was also cleared, CTFd enters setup mode.

**Fix:** Complete the setup wizard to create a new admin account. Challenges will be reloaded by the reset script.

### Containers cannot communicate with each other

**Symptom:** Services fail health checks; logs show connection refused errors between containers.

**Cause:** Docker network subnet conflict with existing networks.

**Fix:** Change the `SUBNET` variable in `.env` to an unused range (e.g., `172.26.0.0/24`) and redeploy:
```bash
docker compose down
docker compose up -d
```

### Dataset ingestion fails

**Symptom:** The setup script reports errors during dataset ingestion, or no `wazuhbots-*` indices appear.

**Cause:** Wazuh Indexer was not fully ready when ingestion started.

**Fix:**
```bash
# Verify the indexer is healthy
curl -sk -u "admin:<INDEXER_PASSWORD>" https://localhost:9200/_cluster/health

# Re-run ingestion manually
source .env
python3 scripts/ingest_datasets.py --all
```

### Out of disk space

**Symptom:** Containers crash with I/O errors; Docker reports insufficient disk space.

**Fix:**
```bash
# Check Docker disk usage
docker system df

# Remove unused images and build cache
docker system prune -a

# If datasets are very large, consider pruning old indices
curl -sk -u "admin:<INDEXER_PASSWORD>" -XDELETE https://localhost:9200/wazuhbots-*
```

### Port conflicts

**Symptom:** `docker compose up` fails because a port is already in use.

**Fix:** Identify the conflicting process and either stop it or change the port mapping in `docker-compose.yml`. Common conflicts:

| Port | Common Conflict             |
|------|-----------------------------|
| 80   | Apache, Nginx on the host   |
| 443  | Apache, Nginx on the host   |
| 9200 | Elasticsearch on the host   |
| 5601 | Kibana on the host          |

---

## Cloud Deployment

### General Recommendations

- Use an instance with SSD/NVMe storage (not network-attached HDD).
- Place the instance behind a load balancer with TLS termination for production use.
- Restrict SSH access and Wazuh API (port 55000) to administrator IP addresses only.
- Open only ports 80 and 443 to participants.
- Set `vm.max_map_count=262144` in the instance user data or cloud-init script.

### Amazon Web Services (AWS)

**Recommended instance types:**

| Deployment Size    | Instance Type | vCPUs | RAM    | Storage              |
|--------------------|---------------|-------|--------|----------------------|
| Development        | t3.xlarge     | 4     | 16 GB  | 100 GB gp3           |
| Meetup (10--20)    | m6i.2xlarge   | 8     | 32 GB  | 200 GB gp3           |
| Public CTF (50+)   | m6i.4xlarge   | 16    | 64 GB  | 500 GB gp3           |

**Security Group inbound rules:**

| Port  | Source       | Description        |
|-------|--------------|--------------------|
| 22    | Admin IP     | SSH administration |
| 80    | 0.0.0.0/0    | HTTP (redirect)    |
| 443   | 0.0.0.0/0    | HTTPS              |
| 55000 | Admin IP     | Wazuh API          |

**Quick launch (Amazon Linux 2023 / Ubuntu):**

```bash
# User data script
#!/bin/bash
sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" >> /etc/sysctl.conf
yum install -y docker git   # Amazon Linux
# apt install -y docker.io git  # Ubuntu
systemctl enable --now docker
usermod -aG docker ec2-user  # or ubuntu

# Install Docker Compose plugin
mkdir -p /usr/local/lib/docker/cli-plugins
curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Deploy WazuhBOTS
cd /opt
git clone https://github.com/MrHacker-X/wazuhbots.git
cd wazuhbots
./scripts/setup.sh
```

### Microsoft Azure

**Recommended VM sizes:**

| Deployment Size    | VM Size          | vCPUs | RAM    |
|--------------------|------------------|-------|--------|
| Development        | Standard_D4s_v5  | 4     | 16 GB  |
| Meetup (10--20)    | Standard_D8s_v5  | 8     | 32 GB  |
| Public CTF (50+)   | Standard_D16s_v5 | 16    | 64 GB  |

Use Premium SSD (P30 or higher) for the OS disk. Configure the Network Security Group (NSG) with the same port rules as the AWS Security Group above.

### Google Cloud Platform (GCP)

**Recommended machine types:**

| Deployment Size    | Machine Type    | vCPUs | RAM    |
|--------------------|-----------------|-------|--------|
| Development        | e2-standard-4   | 4     | 16 GB  |
| Meetup (10--20)    | e2-standard-8   | 8     | 32 GB  |
| Public CTF (50+)   | e2-standard-16  | 16    | 64 GB  |

Use SSD Persistent Disk. Configure the VPC firewall rules to match the required port access above.

### Using a Custom Domain

To serve WazuhBOTS on a custom domain:

1. Point your domain's DNS A record to the server's public IP.
2. Update `DOMAIN` in `.env` to your domain name.
3. Obtain a TLS certificate (e.g., via Let's Encrypt / certbot).
4. Place the certificate and key in `docker/nginx/certs/` and update the Nginx configuration.

---

## Upgrading

To upgrade WazuhBOTS to a newer version:

```bash
cd /path/to/wazuhbots

# Pull latest changes
git pull origin main

# Rebuild and restart containers
docker compose up -d --build

# Re-run dataset ingestion if there are new scenarios
source .env
python3 scripts/ingest_datasets.py --all
```

Docker volumes (containing Wazuh data, CTFd data, and datasets) are preserved across upgrades.

---

## Uninstalling

To completely remove WazuhBOTS and all its data:

```bash
cd /path/to/wazuhbots

# Stop and remove containers, networks, and volumes
docker compose down -v

# Remove built images
docker images | grep wazuhbots | awk '{print $3}' | xargs docker rmi

# Remove the project directory
cd ..
rm -rf wazuhbots
```

**Warning:** The `docker compose down -v` command destroys all Docker volumes, permanently deleting all datasets, CTFd data, and Wazuh configuration. This action is irreversible.
