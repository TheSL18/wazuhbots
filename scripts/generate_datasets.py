#!/usr/bin/env python3
"""
WazuhBOTS -- Generate CTF Datasets
===================================
Generates realistic Wazuh alert datasets for all 4 attack scenarios.
Each scenario produces a wazuh-alerts.json file under datasets/.

Usage:
    python3 scripts/generate_datasets.py --all
    python3 scripts/generate_datasets.py --scenario 1
    python3 scripts/generate_datasets.py --all --validate-only

Author: MrHacker (Kevin Munoz) -- Wazuh Technology Ambassador
"""

import argparse
import json
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DATASETS_DIR = PROJECT_ROOT / "datasets"
CHALLENGES_DIR = PROJECT_ROOT / "ctfd" / "challenges"

# Ensure generators package is importable
sys.path.insert(0, str(SCRIPT_DIR))

from generators.scenario1_dark_harvest import DarkHarvestGenerator
from generators.scenario2_iron_gate import IronGateGenerator
from generators.scenario3_ghost_shell import GhostShellGenerator
from generators.scenario4_supply_chain import SupplyChainGenerator
from generators.noise import NoiseGenerator

GENERATORS = {
    1: DarkHarvestGenerator,
    2: IronGateGenerator,
    3: GhostShellGenerator,
    4: SupplyChainGenerator,
}

SCENARIO_DIRS = {
    1: "scenario1_dark_harvest",
    2: "scenario2_iron_gate",
    3: "scenario3_ghost_shell",
    4: "scenario4_supply_chain",
}


# ==============================================================================
# Flag validation
# ==============================================================================

def load_ctfd_flags(scenario_id: int) -> dict[str, str]:
    """Load expected flags from CTFd challenge JSON."""
    files = {
        1: "scenario1_dark_harvest.json",
        2: "scenario2_iron_gate.json",
        3: "scenario3_ghost_shell.json",
        4: "scenario4_supply_chain.json",
    }
    path = CHALLENGES_DIR / files[scenario_id]
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    flags = {}
    challenges = data if isinstance(data, list) else data.get("challenges", [])
    for ch in challenges:
        cid = ch.get("id", ch.get("name", "unknown"))
        flag_val = ch.get("flags", [{}])
        if isinstance(flag_val, list) and flag_val:
            f = flag_val[0]
            if isinstance(f, dict):
                flags[cid] = f.get("content", f.get("flag", ""))
            elif isinstance(f, str):
                flags[cid] = f
        elif isinstance(flag_val, str):
            flags[cid] = flag_val
    return flags


def validate_scenario(scenario_id: int, alerts: list[dict]) -> list[str]:
    """Validate that CTFd flags are discoverable in the generated alerts.
    Returns a list of validation error messages (empty = all passed)."""
    errors = []

    if scenario_id == 1:
        # S1-PUP-01: exactly 247 alerts with rule.level >= 10
        high = sum(1 for a in alerts if a["rule"]["level"] >= 10)
        if high != 247:
            errors.append(f"S1-PUP-01: Expected 247 high-severity alerts, got {high}")

        # S1-PUP-02: attacker IP 198.51.100.23
        ips = {a.get("data", {}).get("srcip", "") for a in alerts}
        if "198.51.100.23" not in ips:
            errors.append("S1-PUP-02: Attacker IP 198.51.100.23 not found")

        # S1-PUP-03: first SQLi rule = 31103
        sqli = [a for a in alerts if a["rule"]["id"] == "31103"]
        if not sqli:
            errors.append("S1-PUP-03: No rule 31103 alerts found")

        # S1-HNT-01: Nikto/2.1.6 user-agent
        nikto = [a for a in alerts if "Nikto/2.1.6" in a.get("full_log", "")]
        if not nikto:
            errors.append("S1-HNT-01: Nikto/2.1.6 not found in full_log")

        # S1-HNT-02: cmd.php in syscheck
        cmdphp = [a for a in alerts if "cmd.php" in a.get("syscheck", {}).get("path", "")]
        if not cmdphp:
            errors.append("S1-HNT-02: cmd.php not found in syscheck paths")

        # S1-HNT-03: post-escalation command = id
        sudo_id = [a for a in alerts
                    if a["rule"]["id"] == "5402"
                    and a.get("data", {}).get("command") == "id"]
        if not sudo_id:
            errors.append("S1-HNT-03: 'id' command after sudo not found")

        # S1-ALP-01: T1053.003 in MITRE
        cron = [a for a in alerts if "T1053.003" in str(a["rule"].get("mitre", {}).get("id", []))]
        if not cron:
            errors.append("S1-ALP-01: MITRE T1053.003 not found")

        # S1-ALP-02: rule 87901
        r87901 = [a for a in alerts if a["rule"]["id"] == "87901"]
        if not r87901:
            errors.append("S1-ALP-02: Rule 87901 not found")

        # S1-ALP-03: mysqldump -u root dvwa users
        exfil = [a for a in alerts if "mysqldump -u root dvwa users" in a.get("data", {}).get("command", "")]
        if not exfil:
            errors.append("S1-ALP-03: mysqldump command not found")

        # S1-FNR-02: timeline 08:14:23 → 19:47:51
        timestamps = sorted(a["timestamp"] for a in alerts if a.get("data", {}).get("srcip") == "198.51.100.23")
        if timestamps:
            if not timestamps[0].startswith("2026-03-01T08:14:23"):
                errors.append(f"S1-FNR-02: First attack timestamp = {timestamps[0]}, expected 08:14:23")
            if not timestamps[-1].startswith("2026-03-01T19:47:51"):
                errors.append(f"S1-FNR-02: Last attack timestamp = {timestamps[-1]}, expected 19:47:51")

    elif scenario_id == 2:
        # S2-PUP-01: user jmartin
        jm = [a for a in alerts if "jmartin" in str(a.get("data", {}))]
        if not jm:
            errors.append("S2-PUP-01: User jmartin not found")

        # S2-PUP-02: workstation IP 172.25.0.104
        ws = [a for a in alerts if "172.25.0.104" in str(a.get("data", {}))]
        if not ws:
            errors.append("S2-PUP-02: Workstation IP 172.25.0.104 not found")

        # S2-PUP-03: rule 92052
        r92 = [a for a in alerts if a["rule"]["id"] == "92052"]
        if not r92:
            errors.append("S2-PUP-03: Rule 92052 not found")

        # S2-HNT-01: mimikatz.exe
        mimi = [a for a in alerts if "mimikatz.exe" in a.get("full_log", "")]
        if not mimi:
            errors.append("S2-HNT-01: mimikatz.exe not found")

        # S2-HNT-02: 4 unique lateral hosts
        lateral_ips = set()
        for a in alerts:
            d = a.get("data", {})
            if d.get("dstip") and d["dstip"] != "172.26.0.32":
                lateral_ips.add(d["dstip"])
        if len(lateral_ips) < 4:
            errors.append(f"S2-HNT-02: Expected 4 unique lateral hosts, found {len(lateral_ips)}")

        # S2-HNT-03: Kerberoasting SPN
        spn = [a for a in alerts if "MSSQLSvc/db-srv.wazuhbots.local:1433" in str(a.get("data", {}))]
        if not spn:
            errors.append("S2-HNT-03: Kerberoasting SPN not found")

        # S2-ALP-01: EID 4624
        e4624 = [a for a in alerts if a.get("data", {}).get("win", {}).get("system", {}).get("eventID") == "4624"]
        if not e4624:
            errors.append("S2-ALP-01: Event ID 4624 not found")

        # S2-ALP-02: rule 87905
        r87905 = [a for a in alerts if a["rule"]["id"] == "87905"]
        if not r87905:
            errors.append("S2-ALP-02: Rule 87905 not found")

        # S2-ALP-03: ransomware SHA256
        sha = [a for a in alerts if "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890" in str(a)]
        if not sha:
            errors.append("S2-ALP-03: Ransomware SHA256 not found")

        # S2-FNR-01: AmsiScanBuffer
        amsi = [a for a in alerts if "AmsiScanBuffer" in str(a.get("data", {}))]
        if not amsi:
            errors.append("S2-FNR-01: AmsiScanBuffer not found")

        # S2-FNR-02: rule 87910
        r87910 = [a for a in alerts if a["rule"]["id"] == "87910"]
        if not r87910:
            errors.append("S2-FNR-02: Rule 87910 not found")

    elif scenario_id == 3:
        # S3-PUP-01: exactly 8347 failed SSH
        ssh_fail = sum(1 for a in alerts if a["rule"]["id"] in ("5710", "5716"))
        if ssh_fail != 8347:
            errors.append(f"S3-PUP-01: Expected 8347 SSH failures, got {ssh_fail}")

        # S3-PUP-02: country = Russia
        geo = [a for a in alerts
               if a.get("data", {}).get("GeoLocation", {}).get("country_name") == "Russia"]
        if not geo:
            errors.append("S3-PUP-02: GeoIP Russia not found")

        # S3-PUP-03: login at 05:23:41Z
        login = [a for a in alerts
                 if a["rule"]["id"] == "5715"
                 and a["timestamp"].startswith("2026-03-03T05:23:41")]
        if not login:
            errors.append("S3-PUP-03: Successful login at 05:23:41Z not found")

        # S3-HNT-01: user = deploy
        deploy = [a for a in alerts
                  if a["rule"]["id"] == "5715"
                  and a.get("data", {}).get("srcuser") == "deploy"]
        if not deploy:
            errors.append("S3-HNT-01: User 'deploy' SSH login not found")

        # S3-HNT-02: toolkit URL
        tk = [a for a in alerts
              if f"http://203.0.113.100/tools/linpeas_kit.tar.gz" in a.get("data", {}).get("command", "")]
        if not tk:
            errors.append("S3-HNT-02: Toolkit URL not found")

        # S3-HNT-03: rule 550
        r550 = [a for a in alerts if a["rule"]["id"] == "550"]
        if not r550:
            errors.append("S3-HNT-03: Rule 550 not found")

        # S3-ALP-01: syshook.ko
        rk = [a for a in alerts if "syshook.ko" in a.get("full_log", "")]
        if not rk:
            errors.append("S3-ALP-01: syshook.ko not found")

        # S3-ALP-02: C2 port 8443/tcp
        c2 = [a for a in alerts if a.get("data", {}).get("dstport") == "8443"]
        if not c2:
            errors.append("S3-ALP-02: C2 port 8443 not found")

        # S3-ALP-03: auditd key=modules
        mod = [a for a in alerts if a.get("data", {}).get("audit", {}).get("key") == "modules"]
        if not mod:
            errors.append("S3-ALP-03: Auditd key 'modules' not found")

        # S3-FNR-01: auth.log timestomping with 7200s diff
        stomp = [a for a in alerts
                 if a.get("syscheck", {}).get("path") == "/var/log/auth.log"
                 and a.get("syscheck", {}).get("diff_seconds") == "7200"]
        if not stomp:
            errors.append("S3-FNR-01: auth.log timestomping with 7200s diff not found")

        # S3-FNR-02: IOC chain IPs/domains
        all_text = str(alerts)
        for ioc in ["203.0.113.42", "203.0.113.100", "update.systemnodes.net", "stratum.cryptopool.xyz"]:
            if ioc not in all_text:
                errors.append(f"S3-FNR-02: IOC '{ioc}' not found")

    elif scenario_id == 4:
        # S4-ALP-01: wazuhbots-utils
        pkg = [a for a in alerts if PACKAGE_NAME in a.get("data", {}).get("command", "")]
        if not pkg:
            errors.append("S4-ALP-01: Package 'wazuhbots-utils' not found")

        # S4-ALP-02: backdoor path
        bd = [a for a in alerts if a.get("syscheck", {}).get("path", "").endswith("svc_update.py")]
        if not bd:
            errors.append("S4-ALP-02: Backdoor svc_update.py not found")

        # S4-ALP-03: DNS tunneling domain
        dns = [a for a in alerts if DNS_TUNNEL_DOMAIN in a.get("full_log", "")]
        if not dns:
            errors.append("S4-ALP-03: DNS tunnel domain not found")

        # S4-ALP-04: first affected host = web-srv
        pkg_alerts = sorted(
            [a for a in alerts if PACKAGE_NAME in a.get("data", {}).get("command", "")],
            key=lambda a: a["timestamp"]
        )
        if pkg_alerts and pkg_alerts[0]["agent"]["name"] != "web-srv":
            errors.append(f"S4-ALP-04: First affected host = {pkg_alerts[0]['agent']['name']}, expected web-srv")

        # S4-FNR-01: multi-host timeline
        for host, expected_ts in [
            ("web-srv", "2026-03-05T02:14:33"),
            ("dc-srv", "2026-03-05T06:31:07"),
            ("lnx-srv", "2026-03-05T08:45:22"),
        ]:
            match = [a for a in alerts
                     if a["agent"]["name"] == host
                     and PACKAGE_NAME in a.get("data", {}).get("command", "")
                     and a["timestamp"].startswith(expected_ts)]
            if not match:
                errors.append(f"S4-FNR-01: {host} infection at {expected_ts} not found")

        # S4-FNR-02: exfil URL
        exfil = [a for a in alerts if EXFIL_URL in a.get("data", {}).get("url", "")]
        if not exfil:
            errors.append("S4-FNR-02: Exfil URL not found")
        else:
            total_bytes = sum(int(a.get("data", {}).get("bytes_sent", "0")) for a in exfil)
            total_mb = total_bytes / (1024 * 1024)
            if total_mb < 800 or total_mb > 900:
                errors.append(f"S4-FNR-02: Total exfil = {total_mb:.0f}MB, expected ~847MB")

        # S4-FNR-03: logrotate manipulation on web-srv and lnx-srv
        for host in ["web-srv", "lnx-srv"]:
            lr = [a for a in alerts
                  if a["agent"]["name"] == host
                  and "/etc/logrotate.d/wazuh" in a.get("syscheck", {}).get("path", "")]
            if not lr:
                errors.append(f"S4-FNR-03: Logrotate manipulation on {host} not found")

    return errors


PACKAGE_NAME = "wazuhbots-utils"
DNS_TUNNEL_DOMAIN = "cdn-analytics.cloud-metrics.net"
EXFIL_URL = "https://cdn-static.cloud-metrics.net/api/v2/upload"


# ==============================================================================
# Main
# ==============================================================================

def run_scenario(scenario_id: int, validate_only: bool = False) -> bool:
    """Generate (or validate) a single scenario. Returns True on success."""
    name = SCENARIO_DIRS[scenario_id]
    gen_cls = GENERATORS[scenario_id]
    gen = gen_cls(DATASETS_DIR)

    print(f"\n{'='*60}")
    print(f"  Scenario {scenario_id}: {name}")
    print(f"{'='*60}")

    if validate_only:
        # Load existing dataset
        path = DATASETS_DIR / name / "wazuh-alerts.json"
        if not path.exists():
            print(f"  [!] No dataset file at {path}")
            return False
        print(f"  [*] Loading {path}...")
        alerts = json.loads(path.read_text(encoding="utf-8"))
    else:
        print(f"  [*] Generating alerts...")
        t0 = time.time()
        alerts = gen.generate()
        elapsed = time.time() - t0
        print(f"  [+] Generated {len(alerts)} alerts in {elapsed:.1f}s")

        # Write output
        out = gen.write_output(alerts)
        size_mb = out.stat().st_size / (1024 * 1024)
        print(f"  [+] Written to {out} ({size_mb:.1f} MB)")

    # Validate flags
    print(f"  [*] Validating flags...")
    errs = validate_scenario(scenario_id, alerts)
    if errs:
        for e in errs:
            print(f"  [!] FAIL: {e}")
        return False
    else:
        print(f"  [+] All flags validated successfully!")
        return True


def run_noise_baseline(num_days: int) -> bool:
    """Generate 7-day baseline noise. Returns True on success."""
    gen = NoiseGenerator(DATASETS_DIR)

    print(f"\n{'='*60}")
    print(f"  Baseline Noise: {num_days} days (Mar 1-{num_days})")
    print(f"  3 hosts x 4,000/day = {num_days * 12000:,} events")
    print(f"{'='*60}")

    print(f"  [*] Generating baseline noise...")
    t0 = time.time()
    alerts = gen.generate_baseline(num_days)
    elapsed = time.time() - t0
    print(f"  [+] Generated {len(alerts):,} noise alerts in {elapsed:.1f}s")

    # Safety check
    print(f"  [*] Running safety verification...")
    safety_errors = NoiseGenerator.verify_noise_safety(alerts)
    if safety_errors:
        for e in safety_errors[:20]:
            print(f"  [!] SAFETY FAIL: {e}")
        if len(safety_errors) > 20:
            print(f"  [!] ... and {len(safety_errors) - 20} more errors")
        return False

    print(f"  [+] Safety check passed (no banned rules/IPs/levels)")

    # Verify date distribution
    from collections import Counter
    date_counts = Counter(a["timestamp"][:10] for a in alerts)
    for date, count in sorted(date_counts.items()):
        print(f"      {date}: {count:,} events")

    # Write output
    out = gen.write_baseline(alerts)
    size_mb = out.stat().st_size / (1024 * 1024)
    print(f"  [+] Written to {out} ({size_mb:.1f} MB)")

    # Clean up old per-scenario noise files
    cleaned = 0
    for name in SCENARIO_DIRS.values():
        old_noise = DATASETS_DIR / name / "noise-alerts.json"
        if old_noise.exists():
            old_noise.unlink()
            cleaned += 1
    if cleaned:
        print(f"  [*] Cleaned up {cleaned} old per-scenario noise files")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="WazuhBOTS -- CTF Dataset Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --all                    Generate all 4 scenarios
  %(prog)s --scenario 1             Generate scenario 1 only
  %(prog)s --all --validate-only    Validate existing datasets
  %(prog)s --noise --all            Generate attacks + 7-day baseline noise
  %(prog)s --noise-only             Generate baseline noise only
  %(prog)s --noise-only --days 10   Generate 10 days of noise
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="Generate all scenarios")
    group.add_argument("--scenario", type=int, choices=[1, 2, 3, 4], help="Scenario number")
    group.add_argument("--noise-only", action="store_true",
                        help="Only generate baseline noise (skip attacks)")
    parser.add_argument("--validate-only", action="store_true",
                        help="Only validate existing datasets, don't regenerate")
    parser.add_argument("--noise", action="store_true",
                        help="Also generate baseline noise after attack data")
    parser.add_argument("--days", type=int, default=7,
                        help="Number of days for baseline noise (default: 7)")
    args = parser.parse_args()

    print("=" * 60)
    print("  WazuhBOTS -- CTF Dataset Generator")
    print("=" * 60)

    results = {}
    noise_ok = None

    # Generate/validate attack data (unless --noise-only)
    if not args.noise_only:
        scenarios = [1, 2, 3, 4] if args.all else [args.scenario]
        for sid in scenarios:
            ok = run_scenario(sid, args.validate_only)
            results[sid] = ok

    # Generate baseline noise (if --noise or --noise-only)
    if args.noise or args.noise_only:
        noise_ok = run_noise_baseline(args.days)

    # Summary
    print(f"\n{'='*60}")
    print("  Summary")
    print(f"{'='*60}")
    all_ok = True

    if results:
        for sid, ok in results.items():
            status = "PASS" if ok else "FAIL"
            print(f"  Scenario {sid} (attacks): {status}")
            if not ok:
                all_ok = False

    if noise_ok is not None:
        status = "PASS" if noise_ok else "FAIL"
        print(f"  Baseline noise ({args.days} days): {status}")
        if not noise_ok:
            all_ok = False

    if all_ok:
        print(f"\n  All tasks completed successfully!")
    else:
        print(f"\n  [!] Some tasks had errors.")
        sys.exit(1)


if __name__ == "__main__":
    main()
