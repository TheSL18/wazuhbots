# WazuhBOTS -- Creating Scenarios

This guide explains how to create new attack scenarios for WazuhBOTS. A scenario is a self-contained security incident with pre-generated attack data, a set of investigation questions at multiple difficulty levels, and metadata that ties everything together.

---

## Table of Contents

- [Scenario Anatomy](#scenario-anatomy)
- [Step 1: Design the Scenario](#step-1-design-the-scenario)
- [Step 2: Define the YAML Scenario File](#step-2-define-the-yaml-scenario-file)
- [Step 3: Build the Victim Infrastructure](#step-3-build-the-victim-infrastructure)
- [Step 4: Generate Attack Data](#step-4-generate-attack-data)
- [Step 5: Create Questions and Flags](#step-5-create-questions-and-flags)
- [Step 6: Create the Metadata File](#step-6-create-the-metadata-file)
- [Step 7: Test Your Scenario](#step-7-test-your-scenario)
- [Scenario Template Reference](#scenario-template-reference)
- [Challenge JSON Format](#challenge-json-format)
- [Best Practices](#best-practices)

---

## Scenario Anatomy

A complete WazuhBOTS scenario consists of the following components:

```
datasets/scenario5_your_codename/
|-- metadata.json              # Scenario metadata, timestamps, IOCs, flags
|-- wazuh-alerts.json          # Wazuh alert data (the primary investigation source)
|-- (additional data files)    # FIM events, auditd logs, sysmon events, etc.

ctfd/challenges/
|-- scenario5_challenges.json  # Challenge definitions for CTFd

caldera/adversary_profiles/
|-- your_codename.yml          # CALDERA adversary profile (optional)

docker/victims/your-srv/       # Victim machine Dockerfile (if new host needed)
|-- Dockerfile
|-- entrypoint.sh
```

---

## Step 1: Design the Scenario

Before writing any code or configuration, plan the scenario on paper.

### Define the Narrative

Every good BOTS scenario tells a story. The narrative provides context for the participants and makes the investigation feel realistic.

Answer these questions:
- Who is the attacker? (external threat actor, insider, automated botnet)
- What is the target? (web server, domain controller, cloud infrastructure, database)
- What is the motive? (data theft, ransomware, cryptomining, espionage)
- What is the attack timeline? (single day, multi-day campaign)

### Map the Kill Chain

Map the attack to the MITRE ATT&CK framework. Identify which tactics and techniques will be represented:

| Kill Chain Phase     | MITRE Tactic       | Technique ID | What Happens                          |
|----------------------|--------------------|--------------|---------------------------------------|
| 1. Reconnaissance    | Reconnaissance     | T1595.002    | Nmap scan against target              |
| 2. Initial Access    | Initial Access     | T1190        | Exploit public-facing application     |
| 3. Execution         | Execution          | T1059.004    | Command execution via web shell       |
| 4. Persistence       | Persistence        | T1053.003    | Cron job for callback                 |
| 5. Privilege Escalation | Privilege Escalation | T1068    | Sudo exploit                          |
| 6. Exfiltration      | Exfiltration       | T1048        | Data dump over alternative protocol   |

### Identify Wazuh Detection Points

For each kill chain step, identify which Wazuh rules and modules will detect the activity:

- **Web attacks:** Rules 31100--31110 (web attack detection)
- **FIM:** Rules 550--554 (file integrity monitoring)
- **SSH:** Rules 5710--5716 (SSH authentication)
- **Auditd:** Rules 80700+ (Linux audit events)
- **Windows Security:** Rules 60000+ (Windows event log)
- **Sysmon:** Rules 92000+ (Sysmon event processing)
- **Custom rules:** Rules 87900+ (WazuhBOTS custom correlation rules)

### Plan Questions Across Difficulty Levels

Design 8--12 questions distributed across the four difficulty levels:

| Level  | Count | Question Types                                            |
|--------|-------|-----------------------------------------------------------|
| Pup    | 3     | Alert counts, IP addresses, rule IDs, basic dashboard use |
| Hunter | 3     | User-Agents, filenames, commands, event correlation       |
| Alpha  | 2--3  | MITRE technique IDs, custom rule analysis, forensic data  |
| Fenrir | 1--2  | Evasion detection, timeline reconstruction, IOC chains    |

---

## Step 2: Define the YAML Scenario File

Create a YAML file that documents the scenario's structure. This file is used both as documentation and as input for automated tools.

Create the file at: `scenarios/your_codename.yml` (or include it in your scenario documentation).

```yaml
scenario:
  name: "Operation Codename"
  codename: "operation_codename"
  version: "1.0"
  author: "Your Name"
  difficulty: "mixed"         # Options: easy, medium, hard, mixed
  narrative: |
    A detailed narrative description of the attack scenario.
    This should be 2-3 paragraphs explaining the storyline,
    the threat actor, and the business impact.

  timeframe:
    date: "2026-03-15"
    attack_start: "2026-03-15T10:00:00Z"
    attack_end: "2026-03-15T16:30:00Z"
    timezone: "UTC"

  kill_chain:
    - step: 1
      phase: "Reconnaissance"
      tactic: "Reconnaissance"
      technique_id: "T1595.002"
      technique_name: "Active Scanning: Vulnerability Scanning"
      description: "Attacker scans the target with Nmap and Nikto"
      wazuh_rules: [31110]
      detection_expected: true

    - step: 2
      phase: "Initial Access"
      tactic: "Initial Access"
      technique_id: "T1190"
      technique_name: "Exploit Public-Facing Application"
      description: "SQL injection against the web application"
      wazuh_rules: [31103, 87901]
      detection_expected: true

    # Add more steps as needed...

  infrastructure:
    victims:
      - hostname: "target-srv"
        ip: "172.25.0.35"
        os: "Ubuntu 22.04"
        services: ["apache2", "mysql", "php"]
        wazuh_agent: true
        agent_group: "victims"
        dockerfile: "docker/victims/target-srv/Dockerfile"

    attacker:
      ip: "203.0.113.100"
      geo_country: "Country"
      geo_city: "City"

    c2:
      ip: "198.51.100.50"
      domain: "malicious-domain.evil.com"
      port: 4444

  questions:
    pup:
      - id: "S5-PUP-01"
        text: "How many high-severity alerts were generated during the attack?"
        flag: "123"
        points: 100
        hints:
          - text: "Filter by rule.level >= 10 and the attack date."
            cost: 25

    hunter:
      - id: "S5-HNT-01"
        text: "What tool did the attacker use for reconnaissance?"
        flag: "ToolName/1.0"
        points: 200
        hints:
          - text: "Look at the User-Agent field in web attack alerts."
            cost: 50

    alpha:
      - id: "S5-ALP-01"
        text: "What MITRE ATT&CK technique was used for persistence?"
        flag: "T1053.003"
        points: 300
        hints:
          - text: "Search for alerts with rule.mitre.id populated."
            cost: 75

    fenrir:
      - id: "S5-FNR-01"
        text: "Reconstruct the complete IOC chain for this incident."
        flag: "ip1,ip2,domain,hash,port"
        points: 500
        hints:
          - text: "Correlate across all data sources and all agents."
            cost: 100
```

---

## Step 3: Build the Victim Infrastructure

If your scenario requires a new victim machine (beyond `web-srv`, `dc-srv`, and `lnx-srv`), create a Docker container for it.

### Dockerfile Template

Create the directory and files:

```
docker/victims/target-srv/
|-- Dockerfile
|-- entrypoint.sh
```

**Dockerfile:**

```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install base packages and vulnerable services
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    openssh-server \
    # Add your vulnerable services here
    && rm -rf /var/lib/apt/lists/*

# Install Wazuh Agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
    --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    | tee /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER=${WAZUH_MANAGER:-wazuh-manager} apt-get install -y wazuh-agent && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
```

**entrypoint.sh:**

```bash
#!/bin/bash
set -e

# Configure Wazuh Agent
if [ -n "${WAZUH_MANAGER}" ]; then
    sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|" \
        /var/ossec/etc/ossec.conf
fi

if [ -n "${WAZUH_AGENT_NAME}" ]; then
    sed -i "s|<agent_name>.*</agent_name>|<agent_name>${WAZUH_AGENT_NAME}</agent_name>|" \
        /var/ossec/etc/ossec.conf 2>/dev/null || true
fi

# Start Wazuh Agent
/var/ossec/bin/wazuh-control start

# Start your services
# service apache2 start
# service mysql start

# Keep container running
tail -f /var/ossec/logs/ossec.log
```

### Add to docker-compose.yml

Add your new victim machine to the compose file:

```yaml
  target-srv:
    build:
      context: ./docker/victims/target-srv
      dockerfile: Dockerfile
    container_name: wazuhbots-target-srv
    hostname: target-srv
    restart: unless-stopped
    environment:
      WAZUH_MANAGER: wazuh-manager
      WAZUH_AGENT_GROUP: victims
      WAZUH_AGENT_NAME: target-srv
    depends_on:
      wazuh-manager:
        condition: service_healthy
    networks:
      wazuhbots-net:
        ipv4_address: 172.25.0.35
```

---

## Step 4: Generate Attack Data

The attack data is what participants investigate. There are two approaches:

### Approach A: Live Attack Execution (Recommended)

Execute real attacks against your victim machine while Wazuh is collecting logs. This produces the most realistic data.

1. **Generate baseline traffic (24--48 hours before attack):**
   - Normal web browsing (curl/wget to the web application)
   - Legitimate SSH logins
   - Standard cron jobs
   - Package updates
   - Normal DNS queries

2. **Execute the attack following your kill chain:**
   - Use Atomic Red Team for individual technique execution
   - Use CALDERA adversary profiles for automated attack chains
   - Manually execute commands for precision control

3. **Export the data from Wazuh Indexer:**

```bash
# Export alerts for a specific time range
curl -sk -u "admin:${INDEXER_PASSWORD}" \
  "https://localhost:9200/wazuh-alerts-*/_search?size=10000" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "bool": {
        "must": [
          {"term": {"agent.name": "target-srv"}},
          {"range": {"timestamp": {
            "gte": "2026-03-15T00:00:00Z",
            "lte": "2026-03-15T23:59:59Z"
          }}}
        ]
      }
    }
  }' | python3 -c "
import sys, json
data = json.load(sys.stdin)
docs = [hit['_source'] for hit in data['hits']['hits']]
json.dump(docs, sys.stdout, indent=2)
" > datasets/scenario5_your_codename/wazuh-alerts.json
```

### Approach B: Synthetic Data Generation

For scenarios that cannot be easily executed (e.g., ransomware, destructive attacks), generate synthetic Wazuh alert JSON documents that mimic what Wazuh would produce.

Each alert document should follow the Wazuh alert schema:

```json
{
  "timestamp": "2026-03-15T14:23:45.123+0000",
  "rule": {
    "level": 12,
    "description": "SQL injection attempt detected",
    "id": "31103",
    "mitre": {
      "id": ["T1190"],
      "tactic": ["Initial Access"],
      "technique": ["Exploit Public-Facing Application"]
    },
    "groups": ["web", "attack"],
    "firedtimes": 1
  },
  "agent": {
    "id": "005",
    "name": "target-srv",
    "ip": "172.25.0.35"
  },
  "manager": {
    "name": "wazuh-manager"
  },
  "data": {
    "srcip": "203.0.113.100",
    "protocol": "GET",
    "url": "/app/vulnerable?id=1' OR '1'='1"
  },
  "full_log": "203.0.113.100 - - [15/Mar/2026:14:23:45 +0000] \"GET /app/vulnerable?id=1'+OR+'1'%3D'1 HTTP/1.1\" 200 4523 \"-\" \"sqlmap/1.7.2\""
}
```

**Important:** Synthetic data must be realistic enough that participants cannot distinguish it from real Wazuh output. Include realistic timestamps, consistent IP addresses, properly formatted log lines, and correct Wazuh rule metadata.

### Using CALDERA Adversary Profiles

If using CALDERA for automated attack execution, create an adversary profile:

```yaml
# caldera/adversary_profiles/your_codename.yml
id: wazuhbots-your-codename
name: "Operation Codename"
description: |
  Automated attack chain for Scenario 5.

atomic_ordering:
  - technique: T1595.002
    name: "Vulnerability Scanning"
    commands:
      - "nmap -sV -sC -p 80,443 target-srv"
    delay_seconds: 30

  - technique: T1190
    name: "Exploit Application"
    commands:
      - "curl 'http://target-srv/vuln?id=1+OR+1=1'"
    delay_seconds: 60

  # Additional attack steps...

target_hosts:
  - hostname: target-srv
    ip: 172.25.0.35
```

---

## Step 5: Create Questions and Flags

Create the challenge definitions file for CTFd.

### Challenge JSON Format

Create: `ctfd/challenges/scenario5_challenges.json`

```json
{
  "scenario": {
    "id": 5,
    "name": "Operation Codename",
    "codename": "your_codename",
    "category": "Scenario 5: Codename",
    "description": "Brief scenario description for participants.",
    "victim_host": "target-srv",
    "attack_timeframe": "2026-03-15T00:00:00Z to 2026-03-15T23:59:59Z",
    "kill_chain_summary": [
      "Step 1 description",
      "Step 2 description"
    ]
  },
  "challenges": [
    {
      "id": "S5-PUP-01",
      "name": "[Pup] Challenge Title",
      "category": "Scenario 5: Codename",
      "level": "Pup",
      "description": "Full question text.\n\nAdditional context to guide the participant.",
      "value": 100,
      "type": "standard",
      "state": "visible",
      "flags": [
        {
          "type": "static",
          "content": "answer",
          "case_sensitive": false
        }
      ],
      "tags": ["pup", "scenario5", "relevant-tag"],
      "hints": [
        {
          "content": "First hint text (least specific).",
          "cost": 25
        },
        {
          "content": "Second hint text (more specific).",
          "cost": 25
        },
        {
          "content": "Third hint text (most specific, nearly gives the answer).",
          "cost": 25
        }
      ]
    }
  ]
}
```

### Flag Design Guidelines

| Flag Type        | Case Sensitive | Example                    | Notes                          |
|------------------|----------------|----------------------------|--------------------------------|
| Numbers          | No             | `247`                      | Alert counts, port numbers     |
| IP addresses     | No             | `203.0.113.47`             | Source IPs, C2 addresses       |
| Rule IDs         | No             | `31103`                    | Wazuh rule identifiers         |
| Filenames        | Yes            | `cmd.php`                  | Exact filename with extension  |
| Commands         | Yes            | `id`                       | Exact command as executed       |
| Tool names       | Yes            | `Nikto/2.1.6`             | Include version if relevant    |
| MITRE IDs        | No             | `T1053.003`                | Technique IDs                  |
| Hashes           | No             | `d41d8cd9...`              | MD5, SHA256                    |
| Timestamps       | No             | `2026-03-01T14:23Z`        | ISO 8601 format, UTC           |
| Composite        | Yes            | `ip1,ip2,domain`           | Multiple values, comma-separated|

### Hint Design Guidelines

Each challenge should have 1--3 hints of increasing specificity:

1. **First hint:** Points the participant toward the right area of investigation (which module, which field, which time range). This should be enough for someone who knows Wazuh but is unfamiliar with the specific scenario.

2. **Second hint:** Narrows the search significantly (specific filter, specific rule ID range, specific field value). This should be enough for someone with moderate experience.

3. **Third hint:** Nearly gives the answer away. Useful as a last resort for training mode, but expensive enough in competition mode that teams think twice.

---

## Step 6: Create the Metadata File

The metadata file documents the ground truth for a scenario: exact timestamps, IP addresses, IOCs, flags, and rule mappings.

Create: `datasets/scenario5_your_codename/metadata.json`

```json
{
  "scenario": {
    "id": 5,
    "codename": "Codename",
    "name": "Operation Codename",
    "description": "Brief description of the scenario",
    "difficulty": "all_levels",
    "version": "1.0"
  },
  "timeframe": {
    "start": "2026-03-15T00:00:00Z",
    "end": "2026-03-15T23:59:59Z",
    "attack_start": "2026-03-15T10:00:00Z",
    "attack_end": "2026-03-15T16:30:00Z",
    "timezone": "UTC"
  },
  "infrastructure": {
    "victim": {
      "hostname": "target-srv",
      "ip": "172.25.0.35",
      "os": "Ubuntu 22.04",
      "services": ["Apache/2.4.52", "MySQL 8.0"],
      "wazuh_agent_id": "005"
    },
    "attacker": {
      "ip": "203.0.113.100",
      "geo": {
        "country": "Country",
        "city": "City"
      }
    },
    "c2": {
      "ip": "198.51.100.50",
      "domain": "malicious-domain.evil.com",
      "port": 4444
    }
  },
  "flags": {
    "pup_1_description": "answer1",
    "hunter_1_description": "answer2",
    "alpha_1_description": "answer3",
    "fenrir_1_description": "answer4"
  },
  "iocs": {
    "ips": ["203.0.113.100", "198.51.100.50"],
    "domains": ["malicious-domain.evil.com"],
    "hashes": {
      "malware_md5": "hash_here",
      "malware_sha256": "hash_here"
    },
    "files": ["/path/to/malicious/file"],
    "ports": [4444, 80]
  },
  "wazuh_rules_triggered": [
    {
      "id": "31103",
      "description": "SQL injection attempt",
      "level": 7,
      "count": 50
    }
  ],
  "mitre_techniques": [
    "T1595.002", "T1190", "T1059.004"
  ],
  "total_alerts": 500,
  "total_archives": 5000
}
```

---

## Step 7: Test Your Scenario

### Functional Testing

1. **Ingest the dataset:**
   ```bash
   source .env
   python3 scripts/ingest_datasets.py --scenario scenario5_your_codename
   ```

2. **Verify data in Wazuh Dashboard:**
   - Log in to the Dashboard.
   - Set the time range to your scenario's timeframe.
   - Filter by your agent name.
   - Verify alerts are visible and searchable.

3. **Load challenges into CTFd:**
   ```bash
   python3 scripts/generate_flags.py
   ```

4. **Solve every challenge yourself:**
   - Register as a participant in CTFd.
   - Attempt to answer every question using only the Wazuh Dashboard.
   - Verify that every flag is correct.
   - Time yourself to estimate difficulty and adjust point values if needed.

### Quality Checklist

Before submitting a scenario, verify:

- [ ] Narrative is clear and provides enough context.
- [ ] Kill chain is mapped to MITRE ATT&CK with correct technique IDs.
- [ ] All flags are verified to be correct and findable in the data.
- [ ] Questions at each difficulty level are appropriately challenging.
- [ ] Hints are progressively more specific and point costs are reasonable.
- [ ] Metadata file contains all IOCs, timestamps, and rule mappings.
- [ ] Data includes both attack events and enough baseline (legitimate) traffic to require filtering.
- [ ] Challenge descriptions do not accidentally reveal the answer.
- [ ] JSON files are valid and parseable.
- [ ] The scenario works after a fresh `reset_environment.sh`.

---

## Scenario Template Reference

The quick reference for all files needed for a complete scenario:

```
New Scenario Checklist:

1. datasets/scenarioN_codename/
   |-- metadata.json           [REQUIRED] Ground truth and IOCs
   |-- wazuh-alerts.json       [REQUIRED] Primary alert dataset

2. ctfd/challenges/
   |-- scenarioN_challenges.json  [REQUIRED] Challenge definitions

3. caldera/adversary_profiles/
   |-- codename.yml            [OPTIONAL] CALDERA attack profile

4. docker/victims/target-srv/  [OPTIONAL] New victim machine
   |-- Dockerfile
   |-- entrypoint.sh

5. wazuh/rules/
   |-- custom_scenarioN.xml    [OPTIONAL] Custom detection rules

6. wazuh/dashboards/
   |-- scenarioN_dashboard.ndjson  [OPTIONAL] Pre-built dashboard
```

---

## Best Practices

1. **Make the data realistic.** The learning value comes from investigating real-looking events. Avoid obviously fake data.

2. **Include noise.** A dataset with only attack events is unrealistic. Include legitimate baseline traffic so participants must filter and identify the malicious activity.

3. **Test with beginners.** Have someone unfamiliar with Wazuh attempt the Pup-level challenges. If they cannot solve them with the hints, the scenario needs adjustment.

4. **Document the ground truth.** The metadata file should contain everything needed to verify answers. Future maintainers will need this to validate the scenario still works.

5. **Use RFC 5737 IP ranges for attackers.** Use `198.51.100.0/24`, `203.0.113.0/24`, or `192.0.2.0/24` for attacker IPs. These are reserved documentation ranges and will not conflict with real infrastructure.

6. **Align with the MITRE ATT&CK framework.** Every attack step should map to a technique. This gives participants a structured way to understand the attack and allows facilitators to use the MITRE module in Wazuh Dashboard.

7. **Version your scenarios.** Use the `version` field in metadata. When you update a scenario (new questions, modified data), increment the version so facilitators know which version they are running.

8. **Consider internationalization.** While challenge descriptions and hints are typically in English, the narrative can be translated. Use the scenario YAML to maintain translations alongside the original text.
