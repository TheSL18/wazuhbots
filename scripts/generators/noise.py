"""
WazuhBOTS -- Noise Generator: "El Pajar del SOC"
=================================================
Generates realistic SIEM background noise to make CTF challenges harder.
~60,000 events across 4 scenarios (4,000 events/host/day).

Noise is written to noise-alerts.json alongside wazuh-alerts.json.
The ingestion pipeline discovers all *.json (except metadata.json),
so zero changes needed to ingest_datasets.py.

Seeds 101-104 (isolated from attack seeds 42-45).
"""

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .base import AlertBuilder, incremental_timestamps

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EVENTS_PER_HOST_PER_DAY = 4000

# Host definitions (must match scenario agents)
HOSTS = {
    "web-srv": {"agent_id": "001", "ip": "172.26.0.30"},
    "dc-srv":  {"agent_id": "002", "ip": "172.26.0.32"},
    "lnx-srv": {"agent_id": "003", "ip": "172.26.0.31"},
}

# Scenario dates (legacy per-scenario mode)
SCENARIO_DATES = {
    1: [datetime(2026, 3, 1, tzinfo=timezone.utc)],
    2: [datetime(2026, 3, 2, tzinfo=timezone.utc)],
    3: [datetime(2026, 3, 3, tzinfo=timezone.utc)],
    4: [datetime(2026, 3, 5, tzinfo=timezone.utc),
        datetime(2026, 3, 6, tzinfo=timezone.utc)],
}

# Baseline: 7 continuous days of infrastructure noise
BASELINE_START = datetime(2026, 3, 1, tzinfo=timezone.utc)
BASELINE_DAYS = 7  # Mar 1-7
BASELINE_SEED = 100  # Isolated from attack seeds (42-45)

# Seeds isolated from attack generators (42-45)
NOISE_SEEDS = {1: 101, 2: 102, 3: 103, 4: 104}

DOMAIN = "wazuhbots.local"

# ---------------------------------------------------------------------------
# Safety: IPs and rules that MUST NEVER appear in noise
# ---------------------------------------------------------------------------

BANNED_SRCIPS = {"198.51.100.23", "203.0.113.42", "203.0.113.100"}

BANNED_RULE_IDS = set(range(87900, 88003)) | {92052, 92310, 91802}

# Allowed rule IDs (severity 0-7 only) — benign infrastructure noise
ALLOWED_RULE_IDS = {
    # Syslog / PAM / SSH
    1002, 5501, 5502, 5104, 5715, 5710, 5402, 550, 554,
    # Web / Apache
    31100, 31101, 31108, 31120, 31103,
    # Syscheck / FIM
    550, 551, 554, 553,
    # MySQL
    2902,
    # Wazuh agent
    80700, 80784,
    # Windows
    600, 601, 18104, 18103,
    # Audit
    80700, 80784,
    # SCA / Vuln
    19108, 23504,
    # Windows logon/logoff/kerberos/process
    60104, 60106, 60108, 60109, 60110, 60112, 60118,
    60120, 60122, 60132, 60134, 60136, 60137, 60138,
    60140, 60144, 60150, 60152, 60154, 60156, 60158,
    60160, 60162, 60164, 60166,
    # Windows firewall
    91801,
    # Keepalive
    700,
    # Cron/systemd
    2830, 2831, 2832, 2833, 5104, 5100, 5103, 5107,
    # Auditd
    80700, 80784, 80792, 80790,
    # UFW/iptables
    2004, 2013,
    # NTP
    1002,
    # Disk
    1002, 5104,
    # Apt
    2902,
}

# Internal IPs safe for noise
INTERNAL_IPS = [
    "172.26.0.1", "172.26.0.10", "172.26.0.11", "172.26.0.12",
    "172.26.0.20", "172.26.0.21", "172.26.0.22", "172.26.0.30",
    "172.26.0.31", "172.26.0.32", "10.0.0.1", "10.0.0.5",
    "10.0.0.10", "10.0.0.50", "10.0.0.100", "192.168.1.1",
    "192.168.1.10", "192.168.1.50",
]

# Benign external IPs (crawlers, NTP, update servers — NOT attacker IPs)
BENIGN_EXTERNAL_IPS = [
    "66.249.66.1", "66.249.66.2",       # Googlebot
    "157.55.39.1", "157.55.39.2",       # Bingbot
    "17.253.144.10",                      # Apple
    "91.189.91.39", "91.189.91.40",      # Ubuntu archive
    "129.6.15.28", "129.6.15.29",        # NIST NTP
    "216.239.35.0",                       # Google NTP
]

# ---------------------------------------------------------------------------
# Content templates
# ---------------------------------------------------------------------------

WEB_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products",
    "/products/1", "/products/2", "/products/3",
    "/api/v1/status", "/api/v1/products", "/api/v1/users",
    "/login", "/register", "/dashboard", "/static/css/main.css",
    "/static/js/app.js", "/static/img/logo.png", "/blog",
    "/blog/post-1", "/blog/post-2", "/sitemap.xml", "/robots.txt",
    "/assets/fonts/roboto.woff2", "/api/v1/health",
    "/catalog", "/search?q=test", "/faq", "/terms", "/privacy",
]

WEB_404_PATHS = [
    "/favicon.ico", "/wp-login.php", "/wp-admin", "/.env",
    "/xmlrpc.php", "/admin", "/.git/config", "/phpmyadmin",
    "/server-status", "/.well-known/security.txt",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15",
    "curl/8.5.0",
    "python-requests/2.31.0",
]

CRAWLER_USER_AGENTS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
]

NORMAL_USERS_LINUX = ["deploy", "www-data", "root", "backup", "admin"]
NORMAL_USERS_WINDOWS = [
    "admin", "svc_backup", "svc_sql", "jsmith", "mlopez",
    "agarcia", "rjohnson", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
]

WIN_PROCESSES = [
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\csrss.exe",
    "C:\\Windows\\System32\\lsass.exe",
    "C:\\Windows\\System32\\services.exe",
    "C:\\Windows\\System32\\wininit.exe",
    "C:\\Windows\\System32\\spoolsv.exe",
    "C:\\Windows\\System32\\taskhostw.exe",
    "C:\\Windows\\System32\\dwm.exe",
    "C:\\Windows\\System32\\conhost.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Program Files\\Wazuh Agent\\wazuh-agent.exe",
    "C:\\Windows\\System32\\msiexec.exe",
    "C:\\Windows\\System32\\dllhost.exe",
    "C:\\Windows\\System32\\WmiPrvSE.exe",
]

WIN_SPNS = [
    f"MSSQLSvc/db-srv.{DOMAIN}:1433",
    f"HTTP/web-srv.{DOMAIN}",
    f"CIFS/file-srv.{DOMAIN}",
    f"HOST/dc-srv.{DOMAIN}",
    f"LDAP/dc-srv.{DOMAIN}",
    f"DNS/dc-srv.{DOMAIN}",
]

CRON_COMMANDS = [
    "/usr/sbin/logrotate /etc/logrotate.conf",
    "/usr/bin/apt-get -qq update",
    "/usr/local/bin/backup.sh",
    "/usr/bin/find /tmp -mtime +7 -delete",
    "/usr/bin/certbot renew --quiet",
    "/usr/local/bin/health_check.sh",
    "run-parts /etc/cron.hourly",
    "run-parts /etc/cron.daily",
    "/usr/bin/updatedb",
]

PYTHON_SCRIPTS = [
    "/opt/app/manage.py", "/opt/app/worker.py", "/opt/app/celery_beat.py",
    "/opt/app/cleanup.py", "/opt/app/sync_data.py", "/opt/app/report.py",
]

AUDITD_EXECUTABLES = [
    "/usr/bin/ls", "/usr/bin/cat", "/usr/bin/grep", "/usr/bin/find",
    "/usr/bin/ps", "/usr/bin/top", "/usr/bin/df", "/usr/bin/du",
    "/usr/bin/id", "/usr/bin/whoami", "/usr/bin/stat", "/usr/bin/file",
    "/usr/bin/head", "/usr/bin/tail", "/usr/bin/wc", "/usr/bin/sort",
    "/usr/bin/cut", "/usr/bin/awk", "/usr/bin/sed",
    "/usr/sbin/service", "/usr/bin/systemctl",
]

SCA_CHECKS = [
    ("28000", "Ensure permissions on /etc/passwd are configured", "pass"),
    ("28001", "Ensure permissions on /etc/shadow are configured", "pass"),
    ("28002", "Ensure no duplicate UIDs exist", "pass"),
    ("28003", "Ensure root is the only UID 0 account", "pass"),
    ("28004", "Ensure SSH MaxAuthTries is set to 4 or less", "fail"),
    ("28005", "Ensure SSH PermitRootLogin is disabled", "fail"),
    ("28006", "Ensure firewall is active", "pass"),
    ("28007", "Ensure audit log storage size is configured", "pass"),
    ("28008", "Ensure rsyslog is installed", "pass"),
    ("28009", "Ensure permissions on /etc/crontab are configured", "pass"),
]

WIN_SCA_CHECKS = [
    ("58000", "Ensure Windows Firewall is enabled", "pass"),
    ("58001", "Ensure Audit Logon events", "pass"),
    ("58002", "Ensure Remote Desktop is disabled", "fail"),
    ("58003", "Ensure password complexity is enabled", "pass"),
    ("58004", "Ensure account lockout threshold is set", "pass"),
    ("58005", "Ensure Windows Update is configured", "pass"),
    ("58006", "Ensure SMBv1 is disabled", "pass"),
    ("58007", "Ensure PowerShell logging is enabled", "pass"),
]

CVE_LIST = [
    ("CVE-2024-0001", "openssl", "3.0.13", "Medium"),
    ("CVE-2024-0010", "libcurl", "8.5.0", "Low"),
    ("CVE-2024-0020", "nginx", "1.24.0", "Medium"),
    ("CVE-2024-0030", "openssh", "9.6p1", "Low"),
    ("CVE-2024-0040", "python3.11", "3.11.8", "Low"),
]

DNS_QUERY_NAMES = [
    f"dc-srv.{DOMAIN}", f"web-srv.{DOMAIN}", f"lnx-srv.{DOMAIN}",
    f"file-srv.{DOMAIN}", "time.windows.com", "windowsupdate.com",
    "wazuh.com", "github.com", "google.com", "ubuntu.com",
]

FIM_NORMAL_PATHS = [
    "/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log",
    "/var/log/apache2/access.log", "/var/log/apache2/error.log",
    "/var/log/mysql/error.log", "/var/log/wazuh/ossec.log",
    "/tmp/sess_abc123", "/tmp/sess_def456",
]

SYSTEMD_SERVICES = [
    "apache2.service", "mysql.service", "cron.service",
    "wazuh-agent.service", "ssh.service", "rsyslog.service",
    "networkd-dispatcher.service", "unattended-upgrades.service",
    "logrotate.service", "fstrim.service",
]

WIN_SERVICES = [
    ("wuauserv", "Windows Update"),
    ("Spooler", "Print Spooler"),
    ("W32Time", "Windows Time"),
    ("WinDefend", "Windows Defender"),
    ("EventLog", "Windows Event Log"),
    ("Schedule", "Task Scheduler"),
    ("BITS", "Background Intelligent Transfer Service"),
    ("CryptSvc", "Cryptographic Services"),
]


# ---------------------------------------------------------------------------
# Time distribution helpers
# ---------------------------------------------------------------------------

def business_hours_timestamps(
    day: datetime, count: int, rng: random.Random,
    biz_start: int = 8, biz_end: int = 18, biz_ratio: float = 0.8,
) -> list[datetime]:
    """Generate timestamps weighted 80% business hours, 20% off-hours."""
    biz_count = int(count * biz_ratio)
    off_count = count - biz_count
    stamps = []
    # Business hours
    biz_s = day.replace(hour=biz_start, minute=0, second=0)
    biz_e = day.replace(hour=biz_end, minute=0, second=0)
    for _ in range(biz_count):
        secs = rng.uniform(0, (biz_e - biz_s).total_seconds())
        stamps.append(biz_s + timedelta(seconds=secs))
    # Off-hours: 00:00-08:00 and 18:00-23:59:59
    for _ in range(off_count):
        if rng.random() < 0.5:
            secs = rng.uniform(0, biz_start * 3600)
        else:
            secs = rng.uniform(biz_end * 3600, 86399)
        stamps.append(day + timedelta(seconds=secs))
    stamps.sort()
    return stamps


def uniform_timestamps(
    day: datetime, count: int, rng: random.Random,
) -> list[datetime]:
    """Generate uniformly distributed timestamps across a full day."""
    stamps = []
    for _ in range(count):
        secs = rng.uniform(0, 86399)
        stamps.append(day + timedelta(seconds=secs))
    stamps.sort()
    return stamps


def _clamp_to_day(day: datetime, ts: datetime) -> datetime:
    """Clamp a timestamp to stay within [day, day+24h)."""
    day_end = day + timedelta(seconds=86399)
    if ts < day:
        return day
    if ts > day_end:
        return day_end
    return ts


def regular_interval_timestamps(
    day: datetime, interval_seconds: int, rng: random.Random,
    jitter_seconds: int = 2,
) -> list[datetime]:
    """Generate timestamps at regular intervals with small jitter."""
    stamps = []
    current = day
    end = day + timedelta(days=1)
    while current < end:
        jitter = timedelta(seconds=rng.uniform(-jitter_seconds, jitter_seconds))
        stamps.append(_clamp_to_day(day, current + jitter))
        current += timedelta(seconds=interval_seconds)
    return stamps


def fixed_hour_timestamps(
    day: datetime, hours: list[int], rng: random.Random,
    jitter_seconds: int = 30,
) -> list[datetime]:
    """Generate timestamps at fixed hours with small jitter."""
    stamps = []
    for h in hours:
        t = day.replace(hour=h, minute=0, second=0)
        jitter = timedelta(seconds=rng.uniform(0, jitter_seconds))
        stamps.append(_clamp_to_day(day, t + jitter))
    return stamps


def burst_timestamps(
    day: datetime, center: datetime, count: int, rng: random.Random,
    spread_seconds: int = 300,
) -> list[datetime]:
    """Generate a burst of events around a center time."""
    stamps = []
    for _ in range(count):
        offset = timedelta(seconds=rng.gauss(0, spread_seconds / 3))
        stamps.append(_clamp_to_day(day, center + offset))
    stamps.sort()
    return stamps


# ---------------------------------------------------------------------------
# NoiseGenerator
# ---------------------------------------------------------------------------

class NoiseGenerator:
    """Generates realistic SIEM noise for all 3 hosts."""

    def __init__(self, datasets_dir: Path):
        self.datasets_dir = datasets_dir
        self.builders = {
            name: AlertBuilder(info["agent_id"], name, info["ip"])
            for name, info in HOSTS.items()
        }

    # ======================================================================
    # WEB-SRV factories (~4,000/day)
    # ======================================================================

    def _web_http_traffic(self, day: datetime, rng: random.Random) -> list[dict]:
        """Normal HTTP 200/301/304 responses. ~1,200 events."""
        ab = self.builders["web-srv"]
        stamps = business_hours_timestamps(day, 1200, rng)
        alerts = []
        for ts in stamps:
            path = rng.choice(WEB_PATHS)
            status = rng.choices([200, 301, 304], weights=[70, 15, 15])[0]
            method = rng.choices(["GET", "HEAD"], weights=[90, 10])[0]
            size = rng.randint(200, 50000) if status == 200 else rng.randint(0, 300)
            ua = rng.choice(USER_AGENTS)
            srcip = rng.choice(INTERNAL_IPS)
            full_log = (
                f'{srcip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="31100", rule_level=0,
                rule_description="Apache: Access log.",
                rule_groups=["web", "accesslog", "apache"],
                decoder_name="apache-access", location="/var/log/apache2/access.log",
                srcip=srcip, full_log=full_log,
                data={
                    "protocol": "GET", "url": path,
                    "http_method": method, "http_status_code": str(status),
                    "response_size": str(size), "user_agent": ua,
                },
            ))
        return alerts

    def _web_crawlers(self, day: datetime, rng: random.Random) -> list[dict]:
        """Googlebot/Bingbot crawlers. ~300 events."""
        ab = self.builders["web-srv"]
        stamps = uniform_timestamps(day, 300, rng)
        alerts = []
        for ts in stamps:
            path = rng.choice(WEB_PATHS + ["/sitemap.xml", "/robots.txt"])
            ua = rng.choice(CRAWLER_USER_AGENTS)
            srcip = rng.choice(BENIGN_EXTERNAL_IPS[:4])  # Google/Bing IPs
            full_log = (
                f'{srcip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"GET {path} HTTP/1.1" 200 {rng.randint(500, 15000)} "-" "{ua}"'
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="31100", rule_level=0,
                rule_description="Apache: Access log.",
                rule_groups=["web", "accesslog", "apache"],
                decoder_name="apache-access", location="/var/log/apache2/access.log",
                srcip=srcip, full_log=full_log,
                data={
                    "protocol": "GET", "url": path,
                    "http_method": "GET", "http_status_code": "200",
                    "user_agent": ua,
                },
            ))
        return alerts

    def _web_health_checks(self, day: datetime, rng: random.Random) -> list[dict]:
        """Health checks every 5 min. ~288 events."""
        ab = self.builders["web-srv"]
        stamps = regular_interval_timestamps(day, 300, rng, jitter_seconds=2)
        alerts = []
        for ts in stamps:
            full_log = (
                f'172.26.0.1 - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"GET /health HTTP/1.1" 200 15 "-" "HealthChecker/1.0"'
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="31100", rule_level=0,
                rule_description="Apache: Access log.",
                rule_groups=["web", "accesslog", "apache"],
                decoder_name="apache-access", location="/var/log/apache2/access.log",
                srcip="172.26.0.1", full_log=full_log,
                data={
                    "protocol": "GET", "url": "/health",
                    "http_method": "GET", "http_status_code": "200",
                    "user_agent": "HealthChecker/1.0",
                },
            ))
        return alerts

    def _web_404s(self, day: datetime, rng: random.Random) -> list[dict]:
        """Benign 404s. ~120 events."""
        ab = self.builders["web-srv"]
        stamps = uniform_timestamps(day, 120, rng)
        alerts = []
        for ts in stamps:
            path = rng.choice(WEB_404_PATHS)
            srcip = rng.choice(INTERNAL_IPS + BENIGN_EXTERNAL_IPS)
            ua = rng.choice(USER_AGENTS + CRAWLER_USER_AGENTS)
            full_log = (
                f'{srcip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"GET {path} HTTP/1.1" 404 {rng.randint(100, 500)} "-" "{ua}"'
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="31101", rule_level=5,
                rule_description="Apache: File not found (404).",
                rule_groups=["web", "accesslog", "apache"],
                decoder_name="apache-access", location="/var/log/apache2/access.log",
                srcip=srcip, full_log=full_log,
                data={
                    "protocol": "GET", "url": path,
                    "http_method": "GET", "http_status_code": "404",
                    "user_agent": ua,
                },
            ))
        return alerts

    def _web_apache_errors(self, day: datetime, rng: random.Random) -> list[dict]:
        """Apache error log — PHP warnings, timeouts. ~80 events."""
        ab = self.builders["web-srv"]
        stamps = business_hours_timestamps(day, 80, rng)
        errors = [
            "PHP Warning: Undefined variable $page in /var/www/html/index.php on line 42",
            "PHP Notice: Trying to access array offset on null in /var/www/html/api.php on line 115",
            "PHP Warning: file_get_contents(): Failed to open stream in /var/www/html/utils.php on line 88",
            "[warn] mod_fcgid: read data timeout in 40 seconds",
            "[error] [client 172.26.0.10] File does not exist: /var/www/html/.htaccess",
            "PHP Fatal error: Allowed memory size of 134217728 bytes exhausted",
        ]
        alerts = []
        for ts in stamps:
            msg = rng.choice(errors)
            full_log = f'[{ts.strftime("%a %b %d %H:%M:%S.%f %Y")}] [error] {msg}'
            alerts.append(ab.build(
                timestamp=ts, rule_id="31108", rule_level=5,
                rule_description="Apache: error log entry.",
                rule_groups=["web", "apache", "error"],
                decoder_name="apache-errorlog", location="/var/log/apache2/error.log",
                full_log=full_log,
            ))
        return alerts

    def _web_mysql_slow(self, day: datetime, rng: random.Random) -> list[dict]:
        """MySQL slow query log entries. ~40 events."""
        ab = self.builders["web-srv"]
        stamps = business_hours_timestamps(day, 40, rng)
        queries = [
            "SELECT * FROM products WHERE category_id = 5 ORDER BY created_at DESC",
            "SELECT u.*, o.* FROM users u JOIN orders o ON u.id = o.user_id WHERE o.status = 'pending'",
            "UPDATE sessions SET last_activity = NOW() WHERE session_id = 'abc123'",
            "SELECT COUNT(*) FROM access_logs WHERE date > '2026-02-01'",
        ]
        alerts = []
        for ts in stamps:
            query = rng.choice(queries)
            qtime = round(rng.uniform(2.0, 15.0), 2)
            full_log = (
                f"# Time: {ts.strftime('%Y-%m-%dT%H:%M:%S.%f+00:00')}\n"
                f"# User@Host: webapp[webapp] @ localhost []\n"
                f"# Query_time: {qtime} Lock_time: 0.00 Rows_sent: {rng.randint(0, 5000)} "
                f"Rows_examined: {rng.randint(1000, 500000)}\n"
                f"{query};"
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="2902", rule_level=3,
                rule_description="MySQL: Slow query.",
                rule_groups=["mysql", "database"],
                decoder_name="mysql_log", location="/var/log/mysql/slow-query.log",
                full_log=full_log,
            ))
        return alerts

    # ======================================================================
    # DC-SRV factories (~4,000/day)
    # ======================================================================

    def _dc_logon_logoff(self, day: datetime, rng: random.Random) -> list[dict]:
        """Windows logon 4624 / logoff 4634. ~1,180 events."""
        ab = self.builders["dc-srv"]
        logon_stamps = business_hours_timestamps(day, 600, rng)
        logoff_stamps = business_hours_timestamps(day, 580, rng)
        alerts = []
        for ts in logon_stamps:
            user = rng.choice(NORMAL_USERS_WINDOWS)
            srcip = rng.choice(INTERNAL_IPS[:8])
            logon_type = rng.choices([2, 3, 5, 7, 10], weights=[10, 60, 15, 10, 5])[0]
            alerts.append(ab.build(
                timestamp=ts, rule_id="60104", rule_level=3,
                rule_description="Windows: Logon success.",
                rule_groups=["windows", "logon"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Security",
                srcip=srcip, dstuser=user,
                full_log=f"WinEvtLog: Security: EVENT(4624): Microsoft-Windows-Security-Auditing: Logon Type {logon_type}",
                data={
                    "win": {
                        "system": {
                            "eventID": "4624",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "channel": "Security",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "targetUserName": user,
                            "logonType": str(logon_type),
                            "ipAddress": srcip,
                            "workstationName": f"WS-{rng.randint(1,20):03d}",
                        },
                    },
                },
            ))
        for ts in logoff_stamps:
            user = rng.choice(NORMAL_USERS_WINDOWS)
            alerts.append(ab.build(
                timestamp=ts, rule_id="60106", rule_level=3,
                rule_description="Windows: Logoff.",
                rule_groups=["windows", "logon"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Security",
                dstuser=user,
                full_log=f"WinEvtLog: Security: EVENT(4634): Microsoft-Windows-Security-Auditing: Logoff",
                data={
                    "win": {
                        "system": {
                            "eventID": "4634",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "channel": "Security",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "targetUserName": user,
                        },
                    },
                },
            ))
        return alerts

    def _dc_special_privs(self, day: datetime, rng: random.Random) -> list[dict]:
        """Special privileges assigned (4672). ~200 events."""
        ab = self.builders["dc-srv"]
        stamps = business_hours_timestamps(day, 200, rng)
        alerts = []
        for ts in stamps:
            user = rng.choice(["admin", "SYSTEM", "svc_backup", "svc_sql"])
            alerts.append(ab.build(
                timestamp=ts, rule_id="60110", rule_level=3,
                rule_description="Windows: Special privileges assigned to new logon.",
                rule_groups=["windows", "logon", "privilege"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Security",
                dstuser=user,
                full_log=f"WinEvtLog: Security: EVENT(4672): Special Logon: {user}",
                data={
                    "win": {
                        "system": {
                            "eventID": "4672",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "channel": "Security",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "subjectUserName": user,
                            "privilegeList": "SeBackupPrivilege SeRestorePrivilege SeSecurityPrivilege",
                        },
                    },
                },
            ))
        return alerts

    def _dc_kerberos_tgt(self, day: datetime, rng: random.Random) -> list[dict]:
        """Kerberos TGT requests (4768) with AES256. ~400 events."""
        ab = self.builders["dc-srv"]
        stamps = business_hours_timestamps(day, 400, rng)
        alerts = []
        for ts in stamps:
            user = rng.choice(NORMAL_USERS_WINDOWS[:7])  # Not service accounts
            srcip = rng.choice(INTERNAL_IPS[:8])
            alerts.append(ab.build(
                timestamp=ts, rule_id="60132", rule_level=3,
                rule_description="Windows: Kerberos TGT requested.",
                rule_groups=["windows", "kerberos", "authentication"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Security",
                srcip=srcip, dstuser=user,
                full_log=f"WinEvtLog: Security: EVENT(4768): Kerberos Authentication: {user}",
                data={
                    "win": {
                        "system": {
                            "eventID": "4768",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "channel": "Security",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "targetUserName": user,
                            "ipAddress": srcip,
                            "ticketEncryptionType": "0x12",  # AES-256
                            "status": "0x0",
                        },
                    },
                },
            ))
        return alerts

    def _dc_kerberos_tgs(self, day: datetime, rng: random.Random) -> list[dict]:
        """Kerberos TGS requests (4769) with AES256. ~350 events."""
        ab = self.builders["dc-srv"]
        stamps = business_hours_timestamps(day, 350, rng)
        alerts = []
        for ts in stamps:
            user = rng.choice(NORMAL_USERS_WINDOWS[:7])
            spn = rng.choice(WIN_SPNS)
            srcip = rng.choice(INTERNAL_IPS[:8])
            alerts.append(ab.build(
                timestamp=ts, rule_id="60134", rule_level=3,
                rule_description="Windows: Kerberos TGS requested.",
                rule_groups=["windows", "kerberos"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Security",
                srcip=srcip, dstuser=user,
                full_log=f"WinEvtLog: Security: EVENT(4769): Kerberos Service Ticket: {spn}",
                data={
                    "win": {
                        "system": {
                            "eventID": "4769",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "channel": "Security",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "targetUserName": user,
                            "serviceName": spn,
                            "ipAddress": srcip,
                            "ticketEncryptionType": "0x12",  # AES-256 (NOT RC4)
                            "status": "0x0",
                        },
                    },
                },
            ))
        return alerts

    def _dc_process_creation(self, day: datetime, rng: random.Random) -> list[dict]:
        """Process creation (4688). ~500 events."""
        ab = self.builders["dc-srv"]
        stamps = uniform_timestamps(day, 500, rng)
        alerts = []
        for ts in stamps:
            proc = rng.choice(WIN_PROCESSES)
            user = rng.choice(["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"])
            parent = rng.choice([
                "C:\\Windows\\System32\\services.exe",
                "C:\\Windows\\System32\\svchost.exe",
                "C:\\Windows\\System32\\wininit.exe",
            ])
            alerts.append(ab.build(
                timestamp=ts, rule_id="60112", rule_level=3,
                rule_description="Windows: New process created.",
                rule_groups=["windows", "process"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Security",
                dstuser=user,
                full_log=f"WinEvtLog: Security: EVENT(4688): Process Creation: {proc}",
                data={
                    "win": {
                        "system": {
                            "eventID": "4688",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "channel": "Security",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "newProcessName": proc,
                            "parentProcessName": parent,
                            "subjectUserName": user,
                            "commandLine": proc,
                        },
                    },
                },
            ))
        return alerts

    def _dc_ntlm(self, day: datetime, rng: random.Random) -> list[dict]:
        """NTLM authentication (4776). ~100 events."""
        ab = self.builders["dc-srv"]
        stamps = business_hours_timestamps(day, 100, rng)
        alerts = []
        for ts in stamps:
            user = rng.choice(NORMAL_USERS_WINDOWS[:7])
            alerts.append(ab.build(
                timestamp=ts, rule_id="60136", rule_level=3,
                rule_description="Windows: Credential validation (NTLM).",
                rule_groups=["windows", "authentication"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Security",
                dstuser=user,
                full_log=f"WinEvtLog: Security: EVENT(4776): Credential Validation: {user}",
                data={
                    "win": {
                        "system": {
                            "eventID": "4776",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "channel": "Security",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "targetUserName": user,
                            "workstation": f"WS-{rng.randint(1,20):03d}",
                            "status": "0x0",
                        },
                    },
                },
            ))
        return alerts

    def _dc_group_policy(self, day: datetime, rng: random.Random) -> list[dict]:
        """Group Policy updates (~48 events, every 30 min)."""
        ab = self.builders["dc-srv"]
        stamps = regular_interval_timestamps(day, 1800, rng, jitter_seconds=30)
        alerts = []
        for ts in stamps:
            alerts.append(ab.build(
                timestamp=ts, rule_id="60150", rule_level=3,
                rule_description="Windows: Group Policy update.",
                rule_groups=["windows", "policy"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:System",
                full_log="WinEvtLog: System: EVENT(1502): Group Policy: Completed.",
                data={
                    "win": {
                        "system": {
                            "eventID": "1502",
                            "providerName": "Microsoft-Windows-GroupPolicy",
                            "channel": "System",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "description": "Group policy processing completed successfully.",
                        },
                    },
                },
            ))
        return alerts

    def _dc_service_control(self, day: datetime, rng: random.Random) -> list[dict]:
        """Service start/stop (7036). ~80 events."""
        ab = self.builders["dc-srv"]
        stamps = uniform_timestamps(day, 80, rng)
        alerts = []
        for ts in stamps:
            svc_name, svc_display = rng.choice(WIN_SERVICES)
            state = rng.choice(["running", "stopped"])
            alerts.append(ab.build(
                timestamp=ts, rule_id="60152", rule_level=3,
                rule_description="Windows: Service state changed.",
                rule_groups=["windows", "service"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:System",
                full_log=f"WinEvtLog: System: EVENT(7036): Service Control Manager: {svc_display} entered {state} state.",
                data={
                    "win": {
                        "system": {
                            "eventID": "7036",
                            "providerName": "Service Control Manager",
                            "channel": "System",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "param1": svc_display,
                            "param2": state,
                        },
                    },
                },
            ))
        return alerts

    def _dc_scheduled_tasks(self, day: datetime, rng: random.Random) -> list[dict]:
        """Scheduled task execution. ~60 events."""
        ab = self.builders["dc-srv"]
        stamps = uniform_timestamps(day, 60, rng)
        tasks = [
            "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start",
            "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
            "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup",
            "\\Microsoft\\Windows\\Maintenance\\WinSAT",
            "\\WazuhBackup",
        ]
        alerts = []
        for ts in stamps:
            task = rng.choice(tasks)
            alerts.append(ab.build(
                timestamp=ts, rule_id="60154", rule_level=3,
                rule_description="Windows: Scheduled task executed.",
                rule_groups=["windows", "scheduled_task"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Security",
                full_log=f"WinEvtLog: Security: EVENT(4698): Task Scheduler: {task}",
                data={
                    "win": {
                        "system": {
                            "eventID": "4698",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "channel": "Security",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "taskName": task,
                            "subjectUserName": "SYSTEM",
                        },
                    },
                },
            ))
        return alerts

    def _dc_dns_queries(self, day: datetime, rng: random.Random) -> list[dict]:
        """DNS resolution queries. ~200 events."""
        ab = self.builders["dc-srv"]
        stamps = uniform_timestamps(day, 200, rng)
        alerts = []
        for ts in stamps:
            qname = rng.choice(DNS_QUERY_NAMES)
            srcip = rng.choice(INTERNAL_IPS[:8])
            alerts.append(ab.build(
                timestamp=ts, rule_id="60156", rule_level=3,
                rule_description="Windows: DNS query.",
                rule_groups=["windows", "dns"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Microsoft-Windows-DNS-Client/Operational",
                srcip=srcip,
                full_log=f"DNS Query: {qname} from {srcip}",
                data={
                    "win": {
                        "system": {
                            "eventID": "3006",
                            "providerName": "Microsoft-Windows-DNS-Client",
                            "channel": "Microsoft-Windows-DNS-Client/Operational",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "queryName": qname,
                            "queryType": "A",
                        },
                    },
                },
            ))
        return alerts

    def _dc_file_share(self, day: datetime, rng: random.Random) -> list[dict]:
        """File share access SYSVOL/NETLOGON. ~150 events."""
        ab = self.builders["dc-srv"]
        stamps = business_hours_timestamps(day, 150, rng)
        shares = [
            f"\\\\DC-SRV.{DOMAIN}\\SYSVOL",
            f"\\\\DC-SRV.{DOMAIN}\\NETLOGON",
            f"\\\\DC-SRV.{DOMAIN}\\shared$",
        ]
        alerts = []
        for ts in stamps:
            share = rng.choice(shares)
            user = rng.choice(NORMAL_USERS_WINDOWS[:7])
            srcip = rng.choice(INTERNAL_IPS[:8])
            alerts.append(ab.build(
                timestamp=ts, rule_id="60158", rule_level=3,
                rule_description="Windows: File share accessed.",
                rule_groups=["windows", "file_share"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Security",
                srcip=srcip, dstuser=user,
                full_log=f"WinEvtLog: Security: EVENT(5140): File Share: {share} by {user}",
                data={
                    "win": {
                        "system": {
                            "eventID": "5140",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "channel": "Security",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "shareName": share,
                            "subjectUserName": user,
                            "ipAddress": srcip,
                        },
                    },
                },
            ))
        return alerts

    def _dc_windows_update(self, day: datetime, rng: random.Random) -> list[dict]:
        """Windows Update checks. ~20 events."""
        ab = self.builders["dc-srv"]
        stamps = uniform_timestamps(day, 20, rng)
        kbs = ["KB5034441", "KB5034439", "KB5034467", "KB5034470"]
        alerts = []
        for ts in stamps:
            kb = rng.choice(kbs)
            alerts.append(ab.build(
                timestamp=ts, rule_id="60160", rule_level=3,
                rule_description="Windows: Update check.",
                rule_groups=["windows", "update"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:System",
                full_log=f"WinEvtLog: System: EVENT(19): Windows Update Agent: {kb} installed successfully.",
                data={
                    "win": {
                        "system": {
                            "eventID": "19",
                            "providerName": "Microsoft-Windows-WindowsUpdateClient",
                            "channel": "System",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "updateTitle": f"Security Update {kb}",
                        },
                    },
                },
            ))
        return alerts

    def _dc_powershell_normal(self, day: datetime, rng: random.Random) -> list[dict]:
        """Normal PowerShell commands. ~100 events."""
        ab = self.builders["dc-srv"]
        stamps = business_hours_timestamps(day, 100, rng)
        cmds = [
            "Get-Service", "Get-Process", "Get-EventLog -LogName System -Newest 10",
            "Get-ADUser -Filter *", "Get-ADComputer -Filter *",
            "Get-WmiObject Win32_LogicalDisk", "Test-Connection dc-srv",
            "Get-NetAdapter", "Get-DnsServerZone", "Get-ScheduledTask",
        ]
        alerts = []
        for ts in stamps:
            cmd = rng.choice(cmds)
            alerts.append(ab.build(
                timestamp=ts, rule_id="60162", rule_level=3,
                rule_description="Windows: PowerShell command executed.",
                rule_groups=["windows", "powershell"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Microsoft-Windows-PowerShell/Operational",
                dstuser="admin",
                full_log=f"WinEvtLog: PowerShell: EVENT(4104): ScriptBlock: {cmd}",
                data={
                    "win": {
                        "system": {
                            "eventID": "4104",
                            "providerName": "Microsoft-Windows-PowerShell",
                            "channel": "Microsoft-Windows-PowerShell/Operational",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "scriptBlockText": cmd,
                        },
                    },
                },
            ))
        return alerts

    def _dc_wfp(self, day: datetime, rng: random.Random) -> list[dict]:
        """Windows Filtering Platform connections (5156). ~200 events."""
        ab = self.builders["dc-srv"]
        stamps = uniform_timestamps(day, 200, rng)
        alerts = []
        for ts in stamps:
            srcip = rng.choice(INTERNAL_IPS[:8])
            dstport = rng.choice(["53", "88", "135", "389", "445", "636", "3268", "3389"])
            alerts.append(ab.build(
                timestamp=ts, rule_id="91801", rule_level=3,
                rule_description="Windows: Firewall connection allowed.",
                rule_groups=["windows", "firewall"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Security",
                srcip=srcip, dstip=HOSTS["dc-srv"]["ip"],
                srcport=str(rng.randint(49152, 65535)), dstport=dstport,
                full_log=f"WinEvtLog: Security: EVENT(5156): WFP: Allowed connection {srcip} -> {HOSTS['dc-srv']['ip']}:{dstport}",
                data={
                    "win": {
                        "system": {
                            "eventID": "5156",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "channel": "Security",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "direction": "Inbound",
                            "protocol": "6",
                            "sourceAddress": srcip,
                            "destAddress": HOSTS["dc-srv"]["ip"],
                            "destPort": dstport,
                        },
                    },
                },
            ))
        return alerts

    def _dc_explicit_creds(self, day: datetime, rng: random.Random) -> list[dict]:
        """Explicit credentials logon (4648). ~30 events."""
        ab = self.builders["dc-srv"]
        stamps = business_hours_timestamps(day, 30, rng)
        alerts = []
        for ts in stamps:
            user = rng.choice(["admin", "svc_backup"])
            target = rng.choice([f"file-srv.{DOMAIN}", f"web-srv.{DOMAIN}"])
            alerts.append(ab.build(
                timestamp=ts, rule_id="60164", rule_level=3,
                rule_description="Windows: Explicit credentials used.",
                rule_groups=["windows", "logon"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Security",
                dstuser=user,
                full_log=f"WinEvtLog: Security: EVENT(4648): Explicit Logon: {user} -> {target}",
                data={
                    "win": {
                        "system": {
                            "eventID": "4648",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "channel": "Security",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "subjectUserName": user,
                            "targetServerName": target,
                        },
                    },
                },
            ))
        return alerts

    def _dc_cred_fail(self, day: datetime, rng: random.Random) -> list[dict]:
        """Credential validation failures (benign typos). ~14 events."""
        ab = self.builders["dc-srv"]
        stamps = business_hours_timestamps(day, 14, rng)
        alerts = []
        for ts in stamps:
            user = rng.choice(NORMAL_USERS_WINDOWS[:7])
            alerts.append(ab.build(
                timestamp=ts, rule_id="60166", rule_level=5,
                rule_description="Windows: Logon failure.",
                rule_groups=["windows", "authentication_failed"],
                decoder_name="windows_eventlog",
                location="WinEvtLog:Security",
                dstuser=user,
                full_log=f"WinEvtLog: Security: EVENT(4625): Logon Failure: {user} (bad password)",
                data={
                    "win": {
                        "system": {
                            "eventID": "4625",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "channel": "Security",
                            "computer": f"DC-SRV.{DOMAIN}",
                            "systemTime": ab.ts_str(ts),
                        },
                        "eventdata": {
                            "targetUserName": user,
                            "failureReason": "%%2313",
                            "status": "0xc000006d",
                            "subStatus": "0xc000006a",
                            "logonType": "3",
                        },
                    },
                },
            ))
        return alerts

    # ======================================================================
    # LNX-SRV factories (~4,000/day)
    # ======================================================================

    def _lnx_ssh_accepted(self, day: datetime, rng: random.Random) -> list[dict]:
        """Accepted SSH logins from internal IPs. ~30 events."""
        ab = self.builders["lnx-srv"]
        stamps = business_hours_timestamps(day, 30, rng)
        alerts = []
        for ts in stamps:
            user = rng.choice(["deploy", "admin", "backup"])
            srcip = rng.choice(INTERNAL_IPS[:6])
            port = rng.randint(49152, 65535)
            full_log = (
                f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} lnx-srv sshd[{rng.randint(1000,9999)}]: "
                f"Accepted publickey for {user} from {srcip} port {port} ssh2: RSA SHA256:abc123"
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="5715", rule_level=3,
                rule_description="SSHD: authentication success.",
                rule_groups=["syslog", "sshd", "authentication_success"],
                decoder_name="sshd", location="/var/log/auth.log",
                srcip=srcip, srcuser=user, full_log=full_log,
                data={"program_name": "sshd"},
            ))
        return alerts

    def _lnx_ssh_failed_typos(self, day: datetime, rng: random.Random) -> list[dict]:
        """Failed SSH from internal IPs (typos). ~8 events."""
        ab = self.builders["lnx-srv"]
        stamps = business_hours_timestamps(day, 8, rng)
        alerts = []
        for ts in stamps:
            user = rng.choice(["backup", "monitor", "testuser", "sysadmin"])
            srcip = rng.choice(INTERNAL_IPS[:6])
            port = rng.randint(49152, 65535)
            full_log = (
                f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} lnx-srv sshd[{rng.randint(1000,9999)}]: "
                f"Failed password for {user} from {srcip} port {port} ssh2"
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="5710", rule_level=5,
                rule_description="Attempt to login using a non-existent user.",
                rule_groups=["syslog", "sshd", "authentication_failed"],
                decoder_name="sshd", location="/var/log/auth.log",
                srcip=srcip, srcuser=user, full_log=full_log,
                data={"program_name": "sshd"},
            ))
        return alerts

    def _lnx_cron(self, day: datetime, rng: random.Random) -> list[dict]:
        """Cron job executions. ~300 events."""
        ab = self.builders["lnx-srv"]
        # Cron runs at fixed intervals
        hourly = fixed_hour_timestamps(day, list(range(24)), rng, jitter_seconds=5)
        six_hourly = fixed_hour_timestamps(day, [0, 6, 12, 18], rng, jitter_seconds=10)
        # Plus some per-minute crons
        minute_stamps = regular_interval_timestamps(day, 300, rng, jitter_seconds=2)
        # Take enough to get ~300
        all_stamps = sorted(hourly + six_hourly + minute_stamps[:272])
        alerts = []
        for ts in all_stamps:
            user = rng.choice(["root", "www-data", "deploy"])
            cmd = rng.choice(CRON_COMMANDS)
            full_log = (
                f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} lnx-srv CRON[{rng.randint(1000,99999)}]: "
                f"({user}) CMD ({cmd})"
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="2830", rule_level=3,
                rule_description="Cron job executed.",
                rule_groups=["syslog", "cron"],
                decoder_name="cron", location="/var/log/syslog",
                srcuser=user, full_log=full_log,
            ))
        return alerts

    def _lnx_systemd(self, day: datetime, rng: random.Random) -> list[dict]:
        """Systemd service start/stop. ~120 events."""
        ab = self.builders["lnx-srv"]
        stamps = uniform_timestamps(day, 120, rng)
        alerts = []
        for ts in stamps:
            svc = rng.choice(SYSTEMD_SERVICES)
            action = rng.choice(["Started", "Stopped", "Reloaded"])
            full_log = (
                f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} lnx-srv systemd[1]: "
                f"{action} {svc}."
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="5104", rule_level=3,
                rule_description="Systemd: Service state changed.",
                rule_groups=["syslog", "systemd"],
                decoder_name="systemd", location="/var/log/syslog",
                full_log=full_log,
                data={"service": svc, "action": action.lower()},
            ))
        return alerts

    def _lnx_auditd(self, day: datetime, rng: random.Random) -> list[dict]:
        """Auditd syscall events. ~800 events."""
        ab = self.builders["lnx-srv"]
        stamps = uniform_timestamps(day, 800, rng)
        alerts = []
        for ts in stamps:
            exe = rng.choice(AUDITD_EXECUTABLES)
            user = rng.choice(NORMAL_USERS_LINUX)
            syscall = rng.choice(["execve", "open", "read", "write", "connect", "stat"])
            audit_id = f"{int(ts.timestamp())}.{rng.randint(100,999)}:{rng.randint(1,999)}"
            full_log = (
                f'type=SYSCALL msg=audit({audit_id}): arch=c000003e syscall=59 '
                f'success=yes exit=0 a0=0x55a1 a1=0x55a2 a2=0x55a3 a3=0x7ff '
                f'items=2 ppid={rng.randint(1,9999)} pid={rng.randint(1000,99999)} '
                f'auid={rng.randint(1000,1005)} uid=0 gid=0 euid=0 '
                f'exe="{exe}" key="normal_ops"'
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="80700", rule_level=3,
                rule_description="Auditd: Syscall event.",
                rule_groups=["audit", "audit_command"],
                decoder_name="auditd", location="/var/log/audit/audit.log",
                srcuser=user, full_log=full_log,
                data={
                    "audit": {
                        "type": "SYSCALL",
                        "id": audit_id,
                        "syscall": syscall,
                        "exe": exe,
                        "success": "yes",
                        "key": "normal_ops",
                    },
                },
            ))
        return alerts

    def _lnx_python_scripts(self, day: datetime, rng: random.Random) -> list[dict]:
        """Python app script executions. ~200 events."""
        ab = self.builders["lnx-srv"]
        stamps = business_hours_timestamps(day, 200, rng)
        alerts = []
        for ts in stamps:
            script = rng.choice(PYTHON_SCRIPTS)
            pid = rng.randint(1000, 99999)
            full_log = (
                f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} lnx-srv python3[{pid}]: "
                f"INFO: Running {script} completed successfully"
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="1002", rule_level=2,
                rule_description="Syslog: Application log.",
                rule_groups=["syslog", "application"],
                decoder_name="syslog", location="/var/log/syslog",
                full_log=full_log,
            ))
        return alerts

    def _lnx_kernel(self, day: datetime, rng: random.Random) -> list[dict]:
        """Kernel messages. ~60 events."""
        ab = self.builders["lnx-srv"]
        stamps = uniform_timestamps(day, 60, rng)
        msgs = [
            "NET: Registered PF_PACKET protocol family",
            "EXT4-fs (sda1): re-mounted. Opts: errors=remount-ro",
            "TCP: out of memory -- consider tuning tcp_mem",
            "audit: type=1400 audit(0): apparmor=\"STATUS\" operation=\"profile_load\"",
            "ACPI: Power Button [PWRF]",
            "device veth1234: entered promiscuous mode",
            "br-abcd1234: port 1(veth5678) entered forwarding state",
        ]
        alerts = []
        for ts in stamps:
            msg = rng.choice(msgs)
            full_log = f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} lnx-srv kernel: [{rng.uniform(100,99999):.6f}] {msg}"
            alerts.append(ab.build(
                timestamp=ts, rule_id="1002", rule_level=2,
                rule_description="Syslog: Kernel message.",
                rule_groups=["syslog", "kernel"],
                decoder_name="syslog", location="/var/log/kern.log",
                full_log=full_log,
            ))
        return alerts

    def _lnx_ntp(self, day: datetime, rng: random.Random) -> list[dict]:
        """NTP sync events. ~24 events (hourly)."""
        ab = self.builders["lnx-srv"]
        stamps = fixed_hour_timestamps(day, list(range(24)), rng, jitter_seconds=60)
        alerts = []
        for ts in stamps:
            offset = round(rng.uniform(-0.05, 0.05), 6)
            server = rng.choice(BENIGN_EXTERNAL_IPS[8:])  # NIST/Google NTP
            full_log = (
                f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} lnx-srv ntpd[{rng.randint(100,999)}]: "
                f"adjust time server {server} offset {offset} sec"
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="1002", rule_level=2,
                rule_description="Syslog: NTP sync.",
                rule_groups=["syslog", "ntp"],
                decoder_name="syslog", location="/var/log/syslog",
                full_log=full_log,
            ))
        return alerts

    def _lnx_ufw(self, day: datetime, rng: random.Random) -> list[dict]:
        """UFW/iptables blocked connections. ~300 events."""
        ab = self.builders["lnx-srv"]
        stamps = uniform_timestamps(day, 300, rng)
        alerts = []
        for ts in stamps:
            srcip = rng.choice(BENIGN_EXTERNAL_IPS + INTERNAL_IPS[:4])
            dstport = rng.choice(["22", "80", "443", "3306", "8080", "25", "53", "5601"])
            proto = rng.choice(["TCP", "UDP"])
            full_log = (
                f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} lnx-srv kernel: "
                f"[UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC={srcip} "
                f"DST={HOSTS['lnx-srv']['ip']} LEN=60 TOS=0x00 PROTO={proto} "
                f"SPT={rng.randint(1024,65535)} DPT={dstport}"
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="2004", rule_level=5,
                rule_description="Firewall: Connection blocked.",
                rule_groups=["firewall", "iptables"],
                decoder_name="iptables", location="/var/log/kern.log",
                srcip=srcip, dstip=HOSTS["lnx-srv"]["ip"],
                srcport=str(rng.randint(1024, 65535)), dstport=dstport,
                full_log=full_log,
            ))
        return alerts

    def _lnx_systemd_journal(self, day: datetime, rng: random.Random) -> list[dict]:
        """Systemd journal misc entries. ~86 events."""
        ab = self.builders["lnx-srv"]
        stamps = uniform_timestamps(day, 86, rng)
        msgs = [
            "systemd-resolved[234]: Positive Trust Anchors: . IN DS 20326",
            "systemd-logind[456]: New session 42 of user deploy.",
            "systemd-logind[456]: Removed session 42.",
            "systemd-timesyncd[123]: Synchronized to time server 129.6.15.28:123.",
            "dbus-daemon[234]: [system] Successfully activated service 'org.freedesktop.login1'",
            "networkd-dispatcher[345]: WARNING: systemd-networkd is not running.",
        ]
        alerts = []
        for ts in stamps:
            msg = rng.choice(msgs)
            full_log = f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} lnx-srv {msg}"
            alerts.append(ab.build(
                timestamp=ts, rule_id="1002", rule_level=2,
                rule_description="Syslog: Systemd journal entry.",
                rule_groups=["syslog", "systemd"],
                decoder_name="syslog", location="/var/log/syslog",
                full_log=full_log,
            ))
        return alerts

    def _lnx_sudo_normal(self, day: datetime, rng: random.Random) -> list[dict]:
        """Normal sudo commands. ~60 events."""
        ab = self.builders["lnx-srv"]
        stamps = business_hours_timestamps(day, 60, rng)
        cmds = [
            "systemctl restart apache2", "apt update", "journalctl -u ssh",
            "tail -f /var/log/syslog", "service mysql status",
            "cat /etc/hosts", "netstat -tlnp", "df -h", "free -m",
            "iptables -L", "ufw status",
        ]
        alerts = []
        for ts in stamps:
            user = rng.choice(["deploy", "admin"])
            cmd = rng.choice(cmds)
            full_log = (
                f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} lnx-srv sudo: "
                f"  {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/{cmd.split()[0]} {' '.join(cmd.split()[1:])}"
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="5402", rule_level=3,
                rule_description="Sudo: Command executed.",
                rule_groups=["syslog", "sudo"],
                decoder_name="sudo", location="/var/log/auth.log",
                srcuser=user, full_log=full_log,
                data={"command": cmd},
            ))
        return alerts

    # ======================================================================
    # Common factories (all hosts)
    # ======================================================================

    def _pam_sessions(self, host: str, day: datetime, rng: random.Random) -> list[dict]:
        """PAM session open/close. ~400-500 events."""
        ab = self.builders[host]
        count = 400 if host != "dc-srv" else 0  # DC uses Windows logon, not PAM
        if count == 0:
            return []
        stamps = business_hours_timestamps(day, count, rng)
        alerts = []
        for ts in stamps:
            user = rng.choice(NORMAL_USERS_LINUX if host != "dc-srv" else NORMAL_USERS_WINDOWS)
            action = rng.choice(["opened", "closed"])
            full_log = (
                f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} {host} "
                f"systemd-logind[{rng.randint(100,999)}]: "
                f"pam_unix(systemd-user:session): session {action} for user {user}"
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="5501", rule_level=3,
                rule_description="PAM: Session opened/closed.",
                rule_groups=["pam", "syslog", "authentication"],
                decoder_name="pam", location="/var/log/auth.log",
                srcuser=user, full_log=full_log,
            ))
        return alerts

    def _wazuh_keepalive(self, host: str, day: datetime, rng: random.Random) -> list[dict]:
        """Wazuh agent keepalive every 5 min. ~288 events."""
        ab = self.builders[host]
        stamps = regular_interval_timestamps(day, 300, rng, jitter_seconds=2)
        alerts = []
        for ts in stamps:
            alerts.append(ab.build(
                timestamp=ts, rule_id="700", rule_level=0,
                rule_description="Wazuh: Agent keepalive.",
                rule_groups=["wazuh", "agent"],
                decoder_name="wazuh", location="wazuh-agent",
                full_log=f"Agent {HOSTS[host]['agent_id']} keepalive",
            ))
        return alerts

    def _sca_scan(self, host: str, day: datetime, rng: random.Random) -> list[dict]:
        """SCA compliance scans — 2 bursts/day. ~60 events."""
        ab = self.builders[host]
        checks = WIN_SCA_CHECKS if host == "dc-srv" else SCA_CHECKS
        morning = burst_timestamps(
            day, day.replace(hour=6, minute=0), len(checks), rng, spread_seconds=120,
        )
        evening = burst_timestamps(
            day, day.replace(hour=18, minute=0), len(checks), rng, spread_seconds=120,
        )
        all_stamps = morning + evening
        # Pad to ~60 with extra random checks
        while len(all_stamps) < 60:
            ts = uniform_timestamps(day, 1, rng)[0]
            all_stamps.append(ts)
        all_stamps.sort()
        alerts = []
        for i, ts in enumerate(all_stamps):
            check = checks[i % len(checks)]
            check_id, check_title, result = check
            alerts.append(ab.build(
                timestamp=ts, rule_id="19108", rule_level=3,
                rule_description=f"SCA: {check_title}",
                rule_groups=["sca", "compliance"],
                decoder_name="sca", location="sca",
                full_log=f"SCA check {check_id}: {check_title} - {result}",
                data={
                    "sca": {
                        "check": {"id": check_id, "title": check_title, "result": result},
                        "policy": "CIS Benchmark",
                    },
                },
            ))
        return alerts

    def _vuln_scan(self, host: str, day: datetime, rng: random.Random) -> list[dict]:
        """Vulnerability detection events. ~40 events."""
        ab = self.builders[host]
        stamps = uniform_timestamps(day, 40, rng)
        alerts = []
        for ts in stamps:
            cve_id, pkg, ver, sev = rng.choice(CVE_LIST)
            alerts.append(ab.build(
                timestamp=ts, rule_id="23504", rule_level=5,
                rule_description=f"Vulnerability detected: {cve_id}",
                rule_groups=["vulnerability-detector"],
                decoder_name="json", location="vulnerability-detector",
                full_log=f"Vulnerability: {cve_id} in {pkg} {ver} ({sev})",
                data={
                    "vulnerability": {
                        "cve": cve_id,
                        "package": {"name": pkg, "version": ver},
                        "severity": sev,
                        "status": "Active",
                    },
                },
            ))
        return alerts

    def _fim_routine(self, host: str, day: datetime, rng: random.Random) -> list[dict]:
        """FIM log rotation events. ~100 events."""
        ab = self.builders[host]
        stamps = uniform_timestamps(day, 100, rng)
        alerts = []
        for ts in stamps:
            path = rng.choice(FIM_NORMAL_PATHS)
            event = "modified"
            alerts.append(ab.build(
                timestamp=ts, rule_id="551", rule_level=5,
                rule_description="Integrity checksum changed again (2nd time).",
                rule_groups=["ossec", "syscheck", "syscheck_entry_modified"],
                decoder_name="syscheck", location="syscheck",
                full_log=f"File '{path}' checksum changed",
                syscheck={
                    "path": path,
                    "event": event,
                    "sha256_after": f"{rng.randint(0, 2**128):064x}",
                    "size_after": str(rng.randint(100, 500000)),
                    "mtime_after": ab.ts_str(ts),
                },
            ))
        return alerts

    def _disk_warnings(self, host: str, day: datetime, rng: random.Random) -> list[dict]:
        """Disk space warnings. ~4 events."""
        ab = self.builders[host]
        stamps = fixed_hour_timestamps(day, [3, 9, 15, 21], rng, jitter_seconds=120)
        alerts = []
        for ts in stamps:
            usage = rng.randint(80, 92)
            full_log = (
                f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} {host} "
                f"disk-check[{rng.randint(100,999)}]: "
                f"WARNING: /var/log disk usage at {usage}%"
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="1002", rule_level=7,
                rule_description="Disk space warning.",
                rule_groups=["syslog", "disk"],
                decoder_name="syslog", location="/var/log/syslog",
                full_log=full_log,
                data={"disk_usage_pct": str(usage)},
            ))
        return alerts

    def _cron_common(self, host: str, day: datetime, rng: random.Random) -> list[dict]:
        """Common cron jobs (logrotate, backup). ~200 events for web/dc, 0 for lnx (has its own)."""
        if host == "lnx-srv":
            return []
        ab = self.builders[host]
        stamps = uniform_timestamps(day, 200, rng)
        alerts = []
        for ts in stamps:
            cmd = rng.choice(CRON_COMMANDS[:4])
            user = "root"
            full_log = (
                f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} {host} CRON[{rng.randint(1000,99999)}]: "
                f"({user}) CMD ({cmd})"
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="2830", rule_level=3,
                rule_description="Cron job executed.",
                rule_groups=["syslog", "cron"],
                decoder_name="cron", location="/var/log/syslog",
                srcuser=user, full_log=full_log,
            ))
        return alerts

    def _apt_updates(self, host: str, day: datetime, rng: random.Random) -> list[dict]:
        """APT update checks. ~20-30 events."""
        if host == "dc-srv":
            return []  # Windows uses Windows Update
        ab = self.builders[host]
        count = rng.randint(20, 30)
        stamps = uniform_timestamps(day, count, rng)
        pkgs = [
            "libc6", "openssl", "libssl3", "python3", "curl",
            "nginx", "apache2", "mysql-common", "wazuh-agent",
        ]
        alerts = []
        for ts in stamps:
            pkg = rng.choice(pkgs)
            full_log = (
                f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} {host} "
                f"apt[{rng.randint(1000,9999)}]: "
                f"Inst {pkg} [{rng.randint(1,9)}.{rng.randint(0,99)}.{rng.randint(0,9)}-{rng.randint(1,3)}ubuntu1]"
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="2902", rule_level=3,
                rule_description="APT: Package operation.",
                rule_groups=["syslog", "apt"],
                decoder_name="dpkg", location="/var/log/dpkg.log",
                full_log=full_log,
            ))
        return alerts

    # ======================================================================
    # Orchestrator
    # ======================================================================

    def generate_baseline(self, num_days: int = BASELINE_DAYS) -> list[dict]:
        """Generate continuous baseline noise for N days (default 7).

        Returns sorted alerts list: num_days × 3 hosts × 4,000 = N×12,000.
        """
        rng = random.Random(BASELINE_SEED)
        all_alerts: list[dict] = []

        for day_offset in range(num_days):
            day = BASELINE_START + timedelta(days=day_offset)
            for host in HOSTS:
                alerts = self._generate_host_day(host, day, rng)
                all_alerts.extend(alerts)

        all_alerts.sort(key=lambda a: a["timestamp"])
        return all_alerts

    def generate_for_scenario(self, scenario_id: int) -> list[dict]:
        """Generate noise for a single scenario's dates (legacy mode)."""
        seed = NOISE_SEEDS[scenario_id]
        rng = random.Random(seed)
        days = SCENARIO_DATES[scenario_id]

        all_alerts: list[dict] = []

        for day in days:
            for host in HOSTS:
                alerts = self._generate_host_day(host, day, rng)
                all_alerts.extend(alerts)

        all_alerts.sort(key=lambda a: a["timestamp"])
        return all_alerts

    def _generate_host_day(
        self, host: str, day: datetime, rng: random.Random,
    ) -> list[dict]:
        """Generate ~4,000 events for one host on one day."""
        alerts: list[dict] = []

        if host == "web-srv":
            alerts.extend(self._web_http_traffic(day, rng))       # 1200
            alerts.extend(self._web_crawlers(day, rng))            # 300
            alerts.extend(self._web_health_checks(day, rng))       # 288
            alerts.extend(self._web_404s(day, rng))                # 120
            alerts.extend(self._web_apache_errors(day, rng))       # 80
            alerts.extend(self._web_mysql_slow(day, rng))          # 40

        elif host == "dc-srv":
            alerts.extend(self._dc_logon_logoff(day, rng))         # 1180
            alerts.extend(self._dc_special_privs(day, rng))        # 200
            alerts.extend(self._dc_kerberos_tgt(day, rng))         # 400
            alerts.extend(self._dc_kerberos_tgs(day, rng))         # 350
            alerts.extend(self._dc_process_creation(day, rng))     # 500
            alerts.extend(self._dc_ntlm(day, rng))                 # 100
            alerts.extend(self._dc_group_policy(day, rng))         # 48
            alerts.extend(self._dc_service_control(day, rng))      # 80
            alerts.extend(self._dc_scheduled_tasks(day, rng))      # 60
            alerts.extend(self._dc_dns_queries(day, rng))          # 200
            alerts.extend(self._dc_file_share(day, rng))           # 150
            alerts.extend(self._dc_windows_update(day, rng))       # 20
            alerts.extend(self._dc_powershell_normal(day, rng))    # 100
            alerts.extend(self._dc_wfp(day, rng))                  # 200
            alerts.extend(self._dc_explicit_creds(day, rng))       # 30
            alerts.extend(self._dc_cred_fail(day, rng))            # 14

        elif host == "lnx-srv":
            alerts.extend(self._lnx_ssh_accepted(day, rng))        # 30
            alerts.extend(self._lnx_ssh_failed_typos(day, rng))    # 8
            alerts.extend(self._lnx_cron(day, rng))                # 300
            alerts.extend(self._lnx_systemd(day, rng))             # 120
            alerts.extend(self._lnx_auditd(day, rng))              # 800
            alerts.extend(self._lnx_python_scripts(day, rng))      # 200
            alerts.extend(self._lnx_kernel(day, rng))              # 60
            alerts.extend(self._lnx_ntp(day, rng))                 # 24
            alerts.extend(self._lnx_ufw(day, rng))                 # 300
            alerts.extend(self._lnx_systemd_journal(day, rng))     # 86
            alerts.extend(self._lnx_sudo_normal(day, rng))         # 60

        # Common factories for all hosts
        alerts.extend(self._pam_sessions(host, day, rng))          # 400 (not dc-srv)
        alerts.extend(self._wazuh_keepalive(host, day, rng))       # 288
        alerts.extend(self._sca_scan(host, day, rng))              # 60
        alerts.extend(self._vuln_scan(host, day, rng))             # 40
        alerts.extend(self._fim_routine(host, day, rng))           # 100
        alerts.extend(self._disk_warnings(host, day, rng))         # 4
        alerts.extend(self._cron_common(host, day, rng))           # 200 (not lnx-srv)
        alerts.extend(self._apt_updates(host, day, rng))           # ~25 (not dc-srv)

        # Pad to exactly EVENTS_PER_HOST_PER_DAY
        alerts = self._pad_to_target(host, day, rng, alerts, EVENTS_PER_HOST_PER_DAY)
        return alerts

    def _pad_to_target(
        self, host: str, day: datetime, rng: random.Random,
        alerts: list[dict], target: int,
    ) -> list[dict]:
        """Pad (or trim) to exactly *target* events using generic keepalives."""
        current = len(alerts)
        if current >= target:
            # Trim excess by removing from end (lowest priority = keepalives)
            alerts.sort(key=lambda a: a["timestamp"])
            return alerts[:target]

        # Pad with extra keepalives/syslog entries
        ab = self.builders[host]
        deficit = target - current
        stamps = uniform_timestamps(day, deficit, rng)
        for ts in stamps:
            full_log = (
                f"Mar  {ts.day} {ts.strftime('%H:%M:%S')} {host} "
                f"wazuh-agent[{rng.randint(100,999)}]: "
                f"Agent keepalive - status OK"
            )
            alerts.append(ab.build(
                timestamp=ts, rule_id="700", rule_level=0,
                rule_description="Wazuh: Agent keepalive.",
                rule_groups=["wazuh", "agent"],
                decoder_name="wazuh", location="wazuh-agent",
                full_log=full_log,
            ))
        return alerts

    # ======================================================================
    # Safety verification
    # ======================================================================

    @staticmethod
    def verify_noise_safety(alerts: list[dict]) -> list[str]:
        """Verify that noise alerts don't contaminate attack data.
        Returns list of error messages (empty = safe).
        """
        errors = []
        for i, alert in enumerate(alerts):
            rule_id = int(alert["rule"]["id"])
            rule_level = alert["rule"]["level"]

            # Check banned rule IDs (BOTS custom rules)
            if rule_id in BANNED_RULE_IDS:
                errors.append(
                    f"Alert #{i}: Banned rule ID {rule_id} "
                    f"(desc: {alert['rule']['description'][:60]})"
                )

            # Check severity (must be ≤7)
            if rule_level > 7:
                errors.append(
                    f"Alert #{i}: Rule level {rule_level} > 7 "
                    f"(rule {rule_id}: {alert['rule']['description'][:60]})"
                )

            # Check banned source IPs
            data = alert.get("data", {})
            srcip = data.get("srcip", "")
            if srcip in BANNED_SRCIPS:
                errors.append(
                    f"Alert #{i}: Banned srcip {srcip} "
                    f"(rule {rule_id}: {alert['rule']['description'][:60]})"
                )

        return errors

    # ======================================================================
    # Output
    # ======================================================================

    def write_baseline(self, alerts: list[dict]) -> Path:
        """Write baseline noise to datasets/baseline_noise/noise-alerts.json."""
        out_dir = self.datasets_dir / "baseline_noise"
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / "noise-alerts.json"
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=None, ensure_ascii=False)
        return out

    def write_output(self, scenario_id: int, alerts: list[dict]) -> Path:
        """Write per-scenario noise to noise-alerts.json (legacy)."""
        scenario_names = {
            1: "scenario1_dark_harvest",
            2: "scenario2_iron_gate",
            3: "scenario3_ghost_shell",
            4: "scenario4_supply_chain",
        }
        out_dir = self.datasets_dir / scenario_names[scenario_id]
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / "noise-alerts.json"
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=None, ensure_ascii=False)
        return out
