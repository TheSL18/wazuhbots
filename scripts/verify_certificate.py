#!/usr/bin/env python3
"""
WazuhBOTS -- Certificate Verification

Verifies the authenticity of WazuhBOTS certificates using two methods:
  1. Registry lookup  — checks the cert ID against the local registry.json
  2. HMAC re-derivation — re-computes the cert ID from participant data + secret

Usage:
    python3 scripts/verify_certificate.py WBOTS-A1B2C3D4E5F6
    python3 scripts/verify_certificate.py --file cert_Alice.svg
    python3 scripts/verify_certificate.py --name "Alice" --score 15000 --rank 3 --solved 80
    python3 scripts/verify_certificate.py --all

Environment variables:
    WBOTS_CERT_SECRET   HMAC secret used to sign certificates

Author: MrHacker (Kevin Munoz) -- Wazuh Technology Ambassador
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# ==============================================================================
# Configuration
# ==============================================================================

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
REGISTRY_PATH = PROJECT_ROOT / "branding" / "certificates" / "registry.json"

# Load .env before reading env vars
from dotenv import load_dotenv  # noqa: E402 — local module, not python-dotenv
load_dotenv()

SIGNING_SECRET = os.getenv("WBOTS_CERT_SECRET", "")

# ANSI colors
BLUE = "\033[38;2;59;130;246m"
CYAN = "\033[38;2;6;182;212m"
GREEN = "\033[38;2;34;197;94m"
AMBER = "\033[38;2;245;158;11m"
RED = "\033[38;2;239;68;68m"
DIM = "\033[38;2;148;163;184m"
BOLD = "\033[1m"
RESET = "\033[0m"

CERT_ID_PATTERN = re.compile(r"WBOTS-[A-F0-9]{12}")

GPG_FINGERPRINT = "8862AB060D18A07560CFD5E5E5616555DD4EDAAE"


# ==============================================================================
# Core Functions
# ==============================================================================

def load_registry() -> dict:
    """Load the certificate registry."""
    if not REGISTRY_PATH.exists():
        return {"version": 1, "certificates": {}}
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def recompute_cert_id(name: str, score: int, rank: int, solved: int, secret: str) -> str:
    """Re-derive a cert ID from participant data + secret."""
    payload = f"WazuhBOTS-v1|{name}|{score}|{rank}|{solved}"
    if secret:
        sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()[:12]
    else:
        sig = hashlib.sha256(payload.encode()).hexdigest()[:12]
    return f"WBOTS-{sig.upper()}"


def extract_cert_id_from_svg(svg_path: Path) -> str | None:
    """Extract the WBOTS-XXXXXXXXXXXX cert ID from an SVG file."""
    if not svg_path.exists():
        return None
    content = svg_path.read_text(encoding="utf-8")
    match = CERT_ID_PATTERN.search(content)
    return match.group(0) if match else None


def extract_data_from_svg(svg_path: Path) -> dict | None:
    """Try to extract participant data from a rendered certificate SVG."""
    if not svg_path.exists():
        return None
    content = svg_path.read_text(encoding="utf-8")

    cert_id_match = CERT_ID_PATTERN.search(content)
    if not cert_id_match:
        return None

    # Extract name: appears between "This certifies that" and the underline
    # The name is in a <text> tag right after the "This certifies that" text
    name_match = re.search(
        r'font-size="42"[^>]*>\s*\n?\s*(.+?)\s*\n?\s*</text>',
        content,
    )

    # Extract score line: "Score: X,XXX / 39,200 pts  |  Rank: #N  |  Challenges: N / 150"
    score_match = re.search(
        r'Score:\s*([\d,]+)\s*/\s*[\d,]+\s*pts\s*\|\s*Rank:\s*#(\d+)\s*\|\s*Challenges:\s*(\d+)',
        content,
    )

    if not name_match or not score_match:
        return None

    return {
        "cert_id": cert_id_match.group(0),
        "name": name_match.group(1).strip(),
        "score": int(score_match.group(1).replace(",", "")),
        "rank": int(score_match.group(2)),
        "solved": int(score_match.group(3)),
    }


# ==============================================================================
# Verification Methods
# ==============================================================================

def verify_by_registry(cert_id: str) -> dict | None:
    """Look up a certificate in the registry."""
    registry = load_registry()
    return registry["certificates"].get(cert_id)


def verify_by_hmac(name: str, score: int, rank: int, solved: int,
                   expected_cert_id: str, secret: str) -> bool:
    """Re-derive the cert ID and compare."""
    computed = recompute_cert_id(name, score, rank, solved, secret)
    return hmac.compare_digest(computed, expected_cert_id)


def verify_gpg_signature(file_path: Path) -> dict:
    """Verify a detached GPG signature (.asc) for a file.

    Returns dict with keys: valid, signer, fingerprint, error
    """
    sig_path = file_path.with_suffix(file_path.suffix + ".asc")
    if not sig_path.exists():
        return {"valid": None, "error": "No .asc signature file found"}

    result = subprocess.run(
        ["gpg", "--batch", "--verify", str(sig_path), str(file_path)],
        capture_output=True, text=True,
    )

    output = result.stderr  # gpg outputs to stderr

    if result.returncode == 0:
        # Extract signer info (supports English, Spanish, and other locales)
        signer = "Unknown"
        fingerprint = ""
        for line in output.splitlines():
            # Match quoted name in any language:
            #   EN: Good signature from "Kevin Muñoz"
            #   ES: Firma correcta de "Kevin Muñoz"
            #   DE: Korrekte Signatur von "Kevin Muñoz"
            quoted = re.search(r'"(.+?)"', line)
            if quoted and ("signature" in line.lower() or "firma" in line.lower()
                          or "signatur" in line.lower()):
                signer = quoted.group(1)
            # Match key fingerprint/ID
            if re.search(r'(?:key|clave|schlüssel)', line, re.I):
                key_match = re.search(r'([A-F0-9]{16,})', line, re.I)
                if key_match:
                    fingerprint = key_match.group(1)
        return {"valid": True, "signer": signer, "fingerprint": fingerprint, "error": None}
    else:
        return {"valid": False, "signer": None, "fingerprint": None, "error": output.strip()}


def print_verification_result(cert_id: str, registry_record: dict | None,
                               hmac_ok: bool | None, data: dict | None,
                               gpg_result: dict | None = None):
    """Pretty-print the verification result."""
    print()
    print(f"  {CYAN}Certificate Verification Report{RESET}")
    print(f"  {'─' * 45}")
    print(f"  {DIM}Cert ID:{RESET}  {BOLD}{cert_id}{RESET}")
    print()

    # Method 1: Registry
    print(f"  {BLUE}[1] Registry Lookup{RESET}")
    if registry_record:
        print(f"      Status:  {GREEN}VALID — Found in registry{RESET}")
        print(f"      Name:    {registry_record['name']}")
        print(f"      Score:   {registry_record['score']:,} pts")
        print(f"      Rank:    #{registry_record['rank']}")
        print(f"      Solved:  {registry_record['solved']} / 150")
        print(f"      Level:   {registry_record['level']}")
        print(f"      Date:    {registry_record['date']}")
        print(f"      Issued:  {registry_record.get('issued_at', 'N/A')}")
        print(f"      Signed:  {'Yes (HMAC)' if registry_record.get('signed') else 'No (SHA-256)'}")
    else:
        print(f"      Status:  {RED}NOT FOUND in registry{RESET}")
        if not REGISTRY_PATH.exists():
            print(f"      {DIM}(registry.json does not exist){RESET}")
    print()

    # Method 2: HMAC
    print(f"  {BLUE}[2] Cryptographic Verification (HMAC){RESET}")
    if hmac_ok is True:
        print(f"      Status:  {GREEN}VALID — HMAC signature matches{RESET}")
    elif hmac_ok is False:
        print(f"      Status:  {RED}INVALID — HMAC signature mismatch{RESET}")
        print(f"      {DIM}The data does not match this cert ID.{RESET}")
        print(f"      {DIM}Either the cert was tampered with or the secret is different.{RESET}")
    else:
        if not data:
            print(f"      Status:  {AMBER}SKIPPED — no participant data provided{RESET}")
            print(f"      {DIM}Use --name/--score/--rank/--solved or --file to enable{RESET}")
        elif not SIGNING_SECRET:
            print(f"      Status:  {AMBER}SKIPPED — no signing secret available{RESET}")
            print(f"      {DIM}Set WBOTS_CERT_SECRET to enable HMAC verification{RESET}")
    print()

    # Method 3: GPG
    print(f"  {BLUE}[3] GPG Signature Verification{RESET}")
    if gpg_result is None:
        print(f"      Status:  {DIM}SKIPPED — no file provided for GPG check{RESET}")
        print(f"      {DIM}Use --file to verify the GPG signature{RESET}")
    elif gpg_result.get("valid") is None:
        print(f"      Status:  {AMBER}NO SIGNATURE — .asc file not found{RESET}")
        print(f"      {DIM}Certificate was not GPG-signed{RESET}")
    elif gpg_result["valid"]:
        print(f"      Status:  {GREEN}VALID — GPG signature verified{RESET}")
        print(f"      Signer:  {gpg_result.get('signer', 'Unknown')}")
        if gpg_result.get("fingerprint"):
            print(f"      Key:     {gpg_result['fingerprint']}")
    else:
        print(f"      Status:  {RED}INVALID — GPG signature verification failed{RESET}")
        if gpg_result.get("error"):
            for line in gpg_result["error"].splitlines()[:3]:
                print(f"      {DIM}{line}{RESET}")
    print()

    # Final verdict — GPG is the strongest signal
    gpg_valid = gpg_result and gpg_result.get("valid") is True
    gpg_invalid = gpg_result and gpg_result.get("valid") is False
    registry_ok = registry_record is not None
    hmac_bad = hmac_ok is False

    if gpg_valid and registry_ok:
        print(f"  {GREEN}{'═' * 50}{RESET}")
        print(f"  {GREEN}  CERTIFICATE IS VALID (GPG + Registry){RESET}")
        print(f"  {GREEN}{'═' * 50}{RESET}")
    elif gpg_valid:
        print(f"  {GREEN}{'═' * 50}{RESET}")
        print(f"  {GREEN}  CERTIFICATE IS VALID (GPG verified){RESET}")
        print(f"  {GREEN}{'═' * 50}{RESET}")
    elif gpg_invalid:
        print(f"  {RED}{'═' * 50}{RESET}")
        print(f"  {RED}  INVALID — GPG signature does not match{RESET}")
        print(f"  {RED}  Certificate file has been tampered with{RESET}")
        print(f"  {RED}{'═' * 50}{RESET}")
    elif registry_ok and not hmac_bad:
        print(f"  {GREEN}{'═' * 50}{RESET}")
        print(f"  {GREEN}  CERTIFICATE IS VALID (Registry){RESET}")
        print(f"  {GREEN}{'═' * 50}{RESET}")
    elif registry_ok and hmac_bad:
        print(f"  {RED}{'═' * 50}{RESET}")
        print(f"  {RED}  WARNING: Registry match but HMAC mismatch{RESET}")
        print(f"  {RED}  Possible data tampering detected{RESET}")
        print(f"  {RED}{'═' * 50}{RESET}")
    elif not registry_ok and hmac_ok is True:
        print(f"  {AMBER}{'═' * 50}{RESET}")
        print(f"  {AMBER}  HMAC valid but not in registry{RESET}")
        print(f"  {AMBER}{'═' * 50}{RESET}")
    else:
        print(f"  {RED}{'═' * 50}{RESET}")
        print(f"  {RED}  CERTIFICATE COULD NOT BE VERIFIED{RESET}")
        print(f"  {RED}{'═' * 50}{RESET}")
    print()


# ==============================================================================
# Commands
# ==============================================================================

def cmd_verify_id(cert_id: str, secret: str, data: dict | None = None,
                  gpg_result: dict | None = None):
    """Verify a certificate by its ID."""
    # Method 1: Registry lookup
    registry_record = verify_by_registry(cert_id)

    # Method 2: HMAC (if we have data)
    hmac_ok = None
    verify_data = data

    # If no explicit data but found in registry, use registry data for HMAC check
    if not verify_data and registry_record:
        verify_data = registry_record

    if verify_data and secret:
        hmac_ok = verify_by_hmac(
            name=verify_data["name"],
            score=verify_data["score"],
            rank=verify_data["rank"],
            solved=verify_data["solved"],
            expected_cert_id=cert_id,
            secret=secret,
        )

    # Method 3: GPG (passed in from file verification)
    print_verification_result(cert_id, registry_record, hmac_ok, verify_data, gpg_result)


def extract_cert_id_from_binary(file_path: Path) -> str | None:
    """Try to find a cert ID in a binary file (PDF/PNG) via raw bytes."""
    try:
        raw = file_path.read_bytes()
        match = CERT_ID_PATTERN.search(raw.decode("latin-1"))
        return match.group(0) if match else None
    except Exception:
        return None


def resolve_companion_svg(file_path: Path) -> Path | None:
    """Find the .svg sibling of a .pdf or .png certificate."""
    svg_path = file_path.with_suffix(".svg")
    if svg_path.exists():
        return svg_path
    # Try stripping double suffix like cert_Name.pdf -> cert_Name.svg
    stem = file_path.stem  # cert_Name
    parent = file_path.parent
    candidate = parent / f"{stem}.svg"
    return candidate if candidate.exists() else None


def cmd_verify_file(file_path: Path, secret: str):
    """Verify a certificate file (SVG, PDF, or PNG)."""
    print(f"  {DIM}Reading {file_path}...{RESET}")

    suffix = file_path.suffix.lower()
    is_svg = suffix == ".svg"

    # GPG verification (works on any file type)
    gpg_result = verify_gpg_signature(file_path)

    # For non-SVG files, try to extract data from companion SVG or binary
    if is_svg:
        data = extract_data_from_svg(file_path)
        if not data:
            cert_id = extract_cert_id_from_svg(file_path)
            if cert_id:
                print(f"  {AMBER}Could not parse participant data, verifying ID only{RESET}")
                cmd_verify_id(cert_id, secret, gpg_result=gpg_result)
            else:
                print(f"  {RED}[!] No certificate ID found in {file_path}{RESET}")
                sys.exit(1)
            return
        print(f"  {GREEN}Extracted:{RESET} {data['name']} | {data['score']:,} pts | #{data['rank']} | {data['solved']} solved")
        cmd_verify_id(data["cert_id"], secret, data, gpg_result=gpg_result)
    else:
        # PDF or PNG — try companion SVG first, then binary scan
        print(f"  {DIM}Binary file ({suffix}) — looking for data...{RESET}")
        companion = resolve_companion_svg(file_path)
        data = None
        cert_id = None

        if companion:
            print(f"  {GREEN}Found companion:{RESET} {companion.name}")
            data = extract_data_from_svg(companion)

        if not data:
            # Try extracting cert ID from binary content
            cert_id = extract_cert_id_from_binary(file_path)

        if data:
            print(f"  {GREEN}Extracted:{RESET} {data['name']} | {data['score']:,} pts | #{data['rank']} | {data['solved']} solved")
            cmd_verify_id(data["cert_id"], secret, data, gpg_result=gpg_result)
        elif cert_id:
            print(f"  {GREEN}Found cert ID:{RESET} {cert_id}")
            cmd_verify_id(cert_id, secret, gpg_result=gpg_result)
        else:
            # Last resort: look up by filename in registry
            registry = load_registry()
            stem = file_path.stem.replace("cert_", "")
            for cid, record in registry["certificates"].items():
                safe = record["name"].replace(" ", "_")
                safe = "".join(c if c.isalnum() or c in "_-" else "_" for c in safe)
                if safe == stem:
                    print(f"  {GREEN}Matched by filename:{RESET} {record['name']}")
                    cmd_verify_id(cid, secret, record, gpg_result=gpg_result)
                    return
            print(f"  {RED}[!] Could not extract certificate data from {file_path.name}{RESET}")
            print(f"  {DIM}Tip: verify the .svg version instead, or pass the cert ID directly{RESET}")
            sys.exit(1)


def cmd_list_all():
    """List all certificates in the registry."""
    registry = load_registry()
    certs = registry.get("certificates", {})

    if not certs:
        print(f"  {AMBER}Registry is empty.{RESET}")
        return

    print(f"\n  {CYAN}Certificate Registry ({len(certs)} entries){RESET}\n")
    print(f"  {'Cert ID':<20}  {'Name':<25}  {'Score':>8}  {'Rank':>5}  {'Level':<30}  {'Signed'}")
    print(f"  {'─'*20}  {'─'*25}  {'─'*8}  {'─'*5}  {'─'*30}  {'─'*6}")

    for cert_id, record in sorted(certs.items(), key=lambda x: x[1].get("rank", 999)):
        signed = f"{GREEN}HMAC{RESET}" if record.get("signed") else f"{DIM}SHA{RESET}"
        print(f"  {cert_id:<20}  {record['name']:<25}  {record['score']:>8,}  #{record['rank']:>4}  {record['level']:<30}  {signed}")

    print()


# ==============================================================================
# Main
# ==============================================================================

def main():
    print()
    print(f"  {BLUE}╔══════════════════════════════════════════╗{RESET}")
    print(f"  {BLUE}║{RESET}  {CYAN}WazuhBOTS Certificate Verifier{RESET}          {BLUE}║{RESET}")
    print(f"  {BLUE}╚══════════════════════════════════════════╝{RESET}")
    print()

    parser = argparse.ArgumentParser(
        description="Verify WazuhBOTS certificate authenticity",
    )
    parser.add_argument("cert_id", nargs="?",
                        help="Certificate ID to verify (e.g., WBOTS-A1B2C3D4E5F6)")
    parser.add_argument("--file", type=Path,
                        help="Path to a certificate SVG file to verify")
    parser.add_argument("--name", help="Participant name (for HMAC re-derivation)")
    parser.add_argument("--score", type=int, help="Participant score")
    parser.add_argument("--rank", type=int, help="Participant rank")
    parser.add_argument("--solved", type=int, help="Challenges solved")
    parser.add_argument("--secret", default=SIGNING_SECRET,
                        help="HMAC signing secret (or set WBOTS_CERT_SECRET)")
    parser.add_argument("--all", action="store_true",
                        help="List all certificates in the registry")

    args = parser.parse_args()

    if args.all:
        cmd_list_all()
        return

    if args.file:
        cmd_verify_file(args.file, args.secret)
        return

    if args.cert_id:
        # Validate format
        if not CERT_ID_PATTERN.fullmatch(args.cert_id):
            print(f"  {RED}[!] Invalid cert ID format. Expected: WBOTS-XXXXXXXXXXXX{RESET}")
            sys.exit(1)

        # Build data dict if manual params provided
        data = None
        if args.name and args.score is not None and args.rank is not None and args.solved is not None:
            data = {
                "name": args.name,
                "score": args.score,
                "rank": args.rank,
                "solved": args.solved,
            }

        cmd_verify_id(args.cert_id, args.secret, data)
        return

    parser.print_help()
    print()
    print(f"  {CYAN}Examples:{RESET}")
    print(f"    python3 {Path(__file__).name} WBOTS-A1B2C3D4E5F6")
    print(f"    python3 {Path(__file__).name} --file cert_Alice.svg")
    print(f'    python3 {Path(__file__).name} WBOTS-A1B2C3D4E5F6 --name "Alice" --score 15000 --rank 3 --solved 80')
    print(f"    python3 {Path(__file__).name} --all")
    print()


if __name__ == "__main__":
    main()
