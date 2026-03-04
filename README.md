```
 __        __                _     ____   ___ _____ ____
 \ \      / /_ _ _____   _| |__ | __ ) / _ \_   _/ ___|
  \ \ /\ / / _` |_  / | | | '_ \|  _ \| | | || | \___ \
   \ V  V / (_| |/ /| |_| | | | | |_) | |_| || |  ___) |
    \_/\_/ \__,_/___|\__,_|_| |_|____/ \___/ |_| |____/
```

# WazuhBOTS -- Boss of the SOC

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status: Active Development](https://img.shields.io/badge/Status-Active%20Development-brightgreen.svg)](#)
[![Wazuh 4.x](https://img.shields.io/badge/Wazuh-4.x%20Compatible-00bfff.svg)](https://wazuh.com)
[![100% Open Source](https://img.shields.io/badge/Open%20Source-100%25-orange.svg)](#)
[![Docker](https://img.shields.io/badge/Deploy-Docker%20Compose-2496ED.svg)](#quick-start)
[![Challenges](https://img.shields.io/badge/Challenges-150-blueviolet.svg)](#scenarios)
[![Points](https://img.shields.io/badge/Total%20Points-39%2C200-gold.svg)](#difficulty-levels)

**A "Boss of the SOC" CTF platform built entirely on open-source tools, with Wazuh SIEM at its core.**

WazuhBOTS brings the BOTS (Boss of the SOC) competition format to the Wazuh ecosystem. Participants investigate realistic, pre-generated security incidents by querying Wazuh alerts, correlating events across multiple data sources, and submitting answers as CTF flags. Whether you are onboarding junior SOC analysts, running a community meetup competition, or hosting a public CTF, WazuhBOTS provides the infrastructure, scenarios, and scoring in a single deployable stack.

With **150 challenges across 4 attack scenarios**, WazuhBOTS surpasses the combined scope of all three Splunk BOTS competitions (BOTSv1 + BOTSv2 + BOTSv3 = ~136 challenges) -- separating *los cachorros de los perros salvajes*.

Created by **MrHacker (Kevin Munoz)** -- Wazuh Technology Ambassador.

---

## Table of Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Screenshots](#screenshots)
- [Scenarios](#scenarios)
- [Difficulty Levels](#difficulty-levels)
- [Challenge Statistics](#challenge-statistics)
- [Hardware Requirements](#hardware-requirements)
- [Modes of Operation](#modes-of-operation)
- [Scripts & Tooling](#scripts--tooling)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [Credits](#credits)
- [License](#license)

---

## Key Features

- **150 CTF Challenges** -- More than any single BOTS competition ever created. Challenges span from beginner (Pup) to expert (Fenrir), totaling 39,200 base points.
- **4 Attack Scenarios** -- Web application compromise, Active Directory attack chain, Linux server rootkit, and a multi-vector supply chain attack, each mapped to the MITRE ATT&CK framework.
- **4 Difficulty Levels** -- Progressive challenge tiers from entry-level analyst (Pup) to expert threat hunter (Fenrir), with point values from 100 to 500.
- **100% Open Source** -- Every component in the stack is free and open source: Wazuh, CTFd, MITRE CALDERA, Atomic Red Team, Docker.
- **Reproducible Datasets** -- Deterministic generators with fixed random seeds produce identical alert datasets on every run. All 150 flags are programmatically verified.
- **One-Command Deploy** -- A single `./scripts/setup.sh` brings up the full platform, generates secure credentials, ingests datasets, and loads challenges.

---

## Architecture

```
+------------------------------------------------------------------+
|                     WazuhBOTS Infrastructure                     |
+------------------------------------------------------------------+
|                                                                  |
|  [Participant]     [Participant]     [Participant]               |
|      Browser           Browser           Browser                 |
|         |                 |                 |                    |
|         +--------+--------+---------+-------+                    |
|                  |                                                |
|          +-------v--------+                                      |
|          |  Nginx Proxy   |                                      |
|          |  :80 / :443    |                                      |
|          +---+--------+---+                                      |
|              |        |                                          |
|     +--------v--+  +--v---------+                                |
|     |  Wazuh    |  |   CTFd     |                                |
|     | Dashboard |  | Scoreboard |                                |
|     |  :5601    |  |   :8000    |                                |
|     +-----+-----+  +-----+-----+                                |
|           |               |                                      |
|     +-----v-----+  +-----v-----+                                |
|     |  Wazuh    |  |  MariaDB  |                                |
|     |  Indexer  |  | (CTFd DB) |                                |
|     |(OpenSearch)|  |   :3306   |                                |
|     |   :9200   |  +-----------+                                |
|     +-----+-----+                                                |
|           |                                                      |
|     +-----v-------+                                              |
|     |   Wazuh     |                                              |
|     |   Manager   |                                              |
|     | :1514/:1515 |                                              |
|     +-----+-------+                                              |
|           |                                                      |
|     +-----+----------+----------+                                |
|     |                |          |                                |
|  +--v------+  +------v---+  +--v-------+                        |
|  | WEB-SRV |  |  DC-SRV  |  | LNX-SRV  |                        |
|  | (Vuln   |  | (Active  |  | (Linux   |                        |
|  |  WebApp)|  |  Dir Sim)|  |  Server) |                        |
|  | Agent 1 |  | Agent 2  |  | Agent 3  |                        |
|  +---------+  +----------+  +----------+                        |
|                                                                  |
|  +----------------------------------------------+               |
|  |         Attack Simulation Layer               |               |
|  |  +----------------+  +--------------------+   |               |
|  |  | Atomic Red Team|  |  MITRE CALDERA     |   |               |
|  |  +----------------+  +--------------------+   |               |
|  +----------------------------------------------+               |
|                                                                  |
+------------------------------------------------------------------+
```

| Component           | Technology                | Role                                         |
|---------------------|---------------------------|----------------------------------------------|
| SIEM Core           | Wazuh Manager 4.x         | Log collection, decoding, and correlation    |
| Indexer             | Wazuh Indexer (OpenSearch) | Alert storage and full-text indexing          |
| Dashboard           | Wazuh Dashboard            | Investigation interface for participants      |
| CTF Platform        | CTFd                       | Scoreboard, flags, hints, teams, registration|
| Attack Generation   | Atomic Red Team + CALDERA  | MITRE ATT&CK TTP simulation                 |
| Victim Machines     | Docker containers          | Vulnerable servers with Wazuh agents         |
| Orchestration       | Docker Compose             | Full-stack deployment in one command         |
| Reverse Proxy       | Nginx                      | Unified access to Dashboard and CTFd         |

---

## Quick Start

**Prerequisites:** Docker, Docker Compose, 16 GB+ RAM, 100 GB+ free disk space.

```bash
# Step 1: Clone the repository
git clone https://github.com/MrHacker-X/wazuhbots.git
cd wazuhbots

# Step 2: Run the automated setup
chmod +x scripts/setup.sh
./scripts/setup.sh

# Step 3: Access the platform
#   Wazuh Dashboard ... https://localhost:5601
#   CTFd Platform ..... http://localhost:8000
#   Wazuh API ......... https://localhost:55000
```

The setup script will check prerequisites, generate secure random passwords, deploy all containers, wait for services to become healthy, ingest scenario datasets, and load CTFd challenges. Credentials are stored in the `.env` file.

For detailed installation instructions, cloud deployment guides, and configuration options, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

### Manual deployment (step by step)

```bash
# Generate datasets (deterministic -- same output every time)
python3 scripts/generate_datasets.py --all

# Verify all 150 flags match generated data
python3 scripts/verify_flags.py --all

# Start Docker stack
docker compose up -d

# Ingest datasets into Wazuh Indexer
INDEXER_PASSWORD=<password> python3 scripts/ingest_datasets.py --all

# Load challenges into CTFd
CTFD_ACCESS_TOKEN=<token> python3 scripts/generate_flags.py --clear-existing
```

---

## Screenshots

> Screenshots will be added after the first complete deployment. Planned screenshots:
>
> - Wazuh Dashboard -- BOTS Overview with alert timeline and MITRE ATT&CK heatmap
> - CTFd Scoreboard -- Live competition scoreboard with team rankings
> - Investigation Workspace -- Participant view during active investigation
> - Challenge Interface -- CTFd challenge list with difficulty levels and hints

---

## Scenarios

| # | Codename              | Attack Type                        | Victim     | Challenges | Alerts |
|---|-----------------------|------------------------------------|------------|------------|--------|
| 1 | **Operation Dark Harvest**   | Web Application Compromise (SQLi, web shell, privilege escalation, data exfiltration) | `web-srv`  | 36 | 900 |
| 2 | **Operation Iron Gate**      | Active Directory Attack Chain (phishing, Mimikatz, Kerberoasting, lateral movement, ransomware) | `dc-srv`   | 36 | 1,200 |
| 3 | **Ghost in the Shell**       | Linux Server Compromise (SSH brute force, rootkit, C2, cryptominer)                   | `lnx-srv`  | 36 | 9,000 |
| 4 | **Supply Chain Phantom**     | Multi-Vector Supply Chain Attack (dependency confusion, DNS tunneling, multi-host exfiltration) | All hosts  | 42 | 600 |
| | **Total** | | | **150** | **11,700** |

Each scenario includes a narrative briefing, a mapped kill chain, pre-generated Wazuh alert datasets, custom correlation rules, and graduated challenge questions with hints.

---

## Difficulty Levels

WazuhBOTS uses a wolf-themed progressive difficulty model. Each level targets a different analyst skill set and awards different point values.

| Level | Name                | Target Profile              | Points | Skills Tested | Query Complexity |
|-------|---------------------|-----------------------------|--------|---------------|------------------|
| 1     | **Pup** 🐶          | SOC Analyst N1 / Student    | 100    | Dashboard navigation, single filter, field reading | 1 filter, 1 field |
| 2     | **Hunter** 🐕       | SOC Analyst N2              | 200    | Event correlation, timeline analysis, multi-filter | 2-3 filters, time ranges |
| 3     | **Alpha** 🐺        | Threat Hunter / IR          | 300    | MITRE mapping, detection engineering, forensics | Complex aggregations |
| 4     | **Fenrir** 🐺‍❄️     | Expert / Red Team           | 500    | Full incident reconstruction, evasion, IOC chains | Multi-source correlation |

---

## Challenge Statistics

| Scenario | Pup (100) | Hunter (200) | Alpha (300) | Fenrir (500) | Total Challenges | Base Points |
|----------|-----------|--------------|-------------|--------------|------------------|-------------|
| S1 Dark Harvest | 10 | 10 | 9 | 7 | 36 | 9,200 |
| S2 Iron Gate | 10 | 10 | 9 | 7 | 36 | 9,200 |
| S3 Ghost Shell | 10 | 10 | 9 | 7 | 36 | 9,200 |
| S4 Supply Chain | 10 | 10 | 12 | 10 | 42 | 11,600 |
| **Total** | **40** | **40** | **39** | **31** | **150** | **39,200** |

**Scoring details:**

- Dynamic scoring (point value decreases as more teams solve a challenge)
- Minimum value: 50% of original points
- Hints cost 25--50% of the challenge value
- First Blood bonus: 20% extra for the first solve
- Time bonus: 10% extra during the first hour of competition
- Maximum possible score with all bonuses: **50,960 points**

### Comparison with Splunk BOTS

| Competition | Challenges | WazuhBOTS Equivalent |
|-------------|------------|----------------------|
| Splunk BOTSv1 | 28 | Surpassed |
| Splunk BOTSv2 | 48 | Surpassed |
| Splunk BOTSv3 | 60 | Surpassed |
| **All Splunk BOTS combined** | **~136** | **Surpassed (150)** |

---

## Hardware Requirements

| Deployment Scenario              | CPU      | RAM    | Disk        | Notes                        |
|----------------------------------|----------|--------|-------------|------------------------------|
| Development / Personal           | 4 cores  | 16 GB  | 100 GB SSD  | Laptop or local workstation  |
| Meetup (10--20 participants)     | 8 cores  | 32 GB  | 200 GB SSD  | VPS or dedicated server      |
| CTF Public (50+ participants)    | 16 cores | 64 GB  | 500 GB SSD  | Cloud (AWS / Azure / GCP)    |
| Corporate Training               | 8 cores  | 32 GB  | 200 GB SSD  | On-premise server            |

---

## Modes of Operation

WazuhBOTS supports four operational modes, configurable via the `COMPETITION_MODE` variable in `.env`:

### Training Mode

- No time limit
- Hints are free (zero cost)
- Documentation accessible during exercises
- Guided sessions with a facilitator

### Competition Mode

- Time-limited (default: 4 hours, configurable)
- Hints cost points
- Live scoreboard visible to all teams
- Teams of 2--4 people recommended

### Self-Guided Mode

- No competitive scoreboard
- Walkthroughs unlock after a configurable number of failed attempts
- Progressive unlocking: level N+1 requires completing level N
- Ideal for educational content and self-paced learning

### Public CTF Mode

- Open registration
- Anti-cheating verification
- Extended duration (days or weeks)
- Global rankings

See [docs/FACILITATOR_GUIDE.md](docs/FACILITATOR_GUIDE.md) for configuration details on each mode.

---

## Scripts & Tooling

WazuhBOTS includes a complete toolchain for dataset generation, verification, and deployment:

| Script | Purpose | Usage |
|--------|---------|-------|
| `scripts/generate_datasets.py` | Generate deterministic alert datasets | `python3 scripts/generate_datasets.py --all` |
| `scripts/verify_flags.py` | Verify all 150 flags against datasets | `python3 scripts/verify_flags.py --all --verbose` |
| `scripts/ingest_datasets.py` | Ingest datasets into Wazuh Indexer | `INDEXER_PASSWORD=... python3 scripts/ingest_datasets.py --all` |
| `scripts/generate_flags.py` | Import challenges into CTFd via API | `CTFD_ACCESS_TOKEN=... python3 scripts/generate_flags.py` |
| `scripts/setup.sh` | Automated full deployment | `./scripts/setup.sh` |
| `scripts/health_check.sh` | Service verification | `./scripts/health_check.sh` |
| `scripts/reset_environment.sh` | Reset between competitions | `./scripts/reset_environment.sh` |

### Dataset Generators

Each scenario has a dedicated generator module in `scripts/generators/`:

- `base.py` -- AlertBuilder class and BaseScenarioGenerator abstract class
- `scenario1_dark_harvest.py` -- Web attack alerts (SQLi, web shell, exfil)
- `scenario2_iron_gate.py` -- AD attack alerts (Mimikatz, Kerberoasting, ransomware)
- `scenario3_ghost_shell.py` -- Linux attack alerts (SSH brute force, rootkit, C2)
- `scenario4_supply_chain.py` -- Multi-host supply chain alerts (pip backdoor, DNS tunnel)

Generators use fixed random seeds (42-45) for full reproducibility. Every run produces identical datasets.

---

## Project Structure

```
wazuhbots/
|-- docker-compose.yml              # Full-stack orchestration
|-- .env.example                    # Environment variable template
|-- README.md                       # This file
|-- LICENSE                         # MIT License
|
|-- docker/                         # Custom Dockerfiles and configs
|   |-- wazuh-manager/config/       # ossec.conf, local_rules.xml
|   |-- victims/
|       |-- web-srv/                # Apache + DVWA + Wazuh Agent
|       |-- dc-srv/                 # Active Directory simulation + Agent
|       |-- lnx-srv/                # Ubuntu + SSH + auditd + Agent
|
|-- datasets/                       # Pre-generated attack datasets
|   |-- scenario1_dark_harvest/     # 900 alerts, metadata, flags
|   |-- scenario2_iron_gate/        # 1,200 alerts, metadata, flags
|   |-- scenario3_ghost_shell/      # 9,000 alerts, metadata, flags
|   |-- scenario4_supply_chain/     # 600 alerts, metadata, flags
|
|-- scripts/
|   |-- generators/                 # Deterministic alert generator modules
|   |   |-- base.py                 # AlertBuilder + BaseScenarioGenerator
|   |   |-- scenario1_dark_harvest.py
|   |   |-- scenario2_iron_gate.py
|   |   |-- scenario3_ghost_shell.py
|   |   |-- scenario4_supply_chain.py
|   |-- generate_datasets.py        # Generate + validate datasets
|   |-- verify_flags.py             # Verify all 150 flags vs datasets
|   |-- ingest_datasets.py          # Ingest into Wazuh Indexer
|   |-- generate_flags.py           # Import challenges into CTFd
|   |-- setup.sh                    # Automated full deployment
|   |-- health_check.sh             # Service verification
|   |-- reset_environment.sh        # Reset between competitions
|
|-- ctfd/
|   |-- challenges/                 # 150 challenge definitions (JSON)
|   |   |-- scenario1_challenges.json   # 36 challenges
|   |   |-- scenario2_challenges.json   # 36 challenges
|   |   |-- scenario3_challenges.json   # 36 challenges
|   |   |-- scenario4_challenges.json   # 42 challenges
|   |-- scoreboard_config.json      # Scoring configuration
|
|-- wazuh/
|   |-- rules/
|   |   |-- custom_bots_rules.xml   # Custom detection rules (87900+)
|   |   |-- correlation_rules.xml   # Correlation rules (88000+)
|   |-- dashboards/                 # Pre-configured Wazuh dashboards
|
|-- caldera/
|   |-- adversary_profiles/         # CALDERA attack profiles (YAML)
|
|-- branding/                       # Logos, banners, certificate templates
|
|-- docs/                           # Documentation
    |-- DEPLOYMENT.md               # Deployment guide
    |-- PARTICIPANT_GUIDE.md        # Guide for CTF participants
    |-- FACILITATOR_GUIDE.md        # Guide for event organizers
    |-- CREATING_SCENARIOS.md       # How to create new scenarios
    |-- ANSWER_KEY.md               # Answer key for verifiers (150 flags)
```

---

## Documentation

| Document | Audience | Description |
|----------|----------|-------------|
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Administrators | Prerequisites, installation, configuration, troubleshooting, cloud deployment |
| [PARTICIPANT_GUIDE.md](docs/PARTICIPANT_GUIDE.md) | CTF Players | How to access the platform, use Wazuh Dashboard, submit flags, and use hints |
| [FACILITATOR_GUIDE.md](docs/FACILITATOR_GUIDE.md) | Event Organizers | Setting up competitions, managing teams, configuring modes, resetting between rounds |
| [CREATING_SCENARIOS.md](docs/CREATING_SCENARIOS.md) | Contributors | Scenario template format, YAML structure, dataset generation, testing |
| [ANSWER_KEY.md](docs/ANSWER_KEY.md) | Verifiers / Organizers | Complete answer key for all 150 challenges with flags and verification hints |

---

## Contributing

Contributions are welcome and encouraged. WazuhBOTS is a community-driven project.

**Ways to contribute:**

- **New scenarios** -- Create additional attack scenarios following the template in [docs/CREATING_SCENARIOS.md](docs/CREATING_SCENARIOS.md)
- **Custom Wazuh rules** -- Improve detection coverage with new correlation rules
- **Dashboard visualizations** -- Build investigation dashboards for specific attack types
- **Documentation** -- Improve guides, add translations, create tutorials
- **Bug fixes and improvements** -- Submit issues and pull requests

**Contribution workflow:**

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-scenario`)
3. Make your changes and test locally
4. Run `python3 scripts/verify_flags.py --all` to ensure no regressions
5. Submit a pull request with a clear description of changes

Please ensure all scenarios include complete challenge definitions, metadata files, and at least basic documentation before submitting.

---

## Roadmap

**Phase 1 -- MVP (Complete)**
- Docker Compose stack with Wazuh + CTFd + Nginx
- 4 attack scenarios with full datasets (11,700 alerts)
- 150 CTF challenges across 4 difficulty tiers
- Deterministic dataset generators with reproducible output
- Automated flag verification (150/150 passing)
- Pre-configured investigation dashboards

**Phase 2 -- Live Deployment**
- Automated dataset ingestion and CTFd challenge loading
- Automated setup, health check, and reset scripts
- Branding assets and participant certificates

**Phase 3 -- Community**
- Scenario template system for community contributions
- Custom CTFd plugin with Wazuh-specific features
- Self-guided mode with progressive walkthroughs
- Internationalization (English, Spanish)

**Phase 4 -- Enterprise**
- Multi-tenant support for simultaneous competitions
- Automated per-participant reporting
- LMS integration for training platforms
- Cloud-native log scenarios (AWS CloudTrail, Azure Activity Log, GCP Audit Log)

---

## Credits

**Creator and Maintainer**
- **MrHacker (Kevin Munoz)** -- Wazuh Technology Ambassador

**Powered By**
- [Wazuh](https://wazuh.com) -- Open source security monitoring platform
- [CTFd](https://ctfd.io) -- Capture The Flag platform
- [MITRE CALDERA](https://caldera.mitre.org) -- Automated adversary emulation
- [Atomic Red Team](https://atomicredteam.io) -- Library of ATT&CK-mapped tests
- [MITRE ATT&CK](https://attack.mitre.org) -- Adversarial tactics and techniques knowledge base
- [Docker](https://docker.com) -- Container runtime and orchestration

---

## License

WazuhBOTS is released under the **MIT License**. See [LICENSE](LICENSE) for the full text.

```
Copyright (c) 2026 MrHacker (Kevin Munoz)
```

---

*"In the SOC, it is not the one with the most tools who prevails, but the one who investigates best."*
-- MrHacker
