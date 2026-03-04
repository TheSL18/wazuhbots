#!/usr/bin/env python3
"""
WazuhBOTS -- Generate Certificates from CTFd User Data

Pulls participant data from the CTFd API and renders personalised
certificates using the SVG template in branding/certificates/.

Usage:
    python3 scripts/generate_certificates.py                      # All users
    python3 scripts/generate_certificates.py --user 1             # Single user by ID
    python3 scripts/generate_certificates.py --user-name "Alice"  # Single user by name
    python3 scripts/generate_certificates.py --team 1             # Single team by ID
    python3 scripts/generate_certificates.py --top 10             # Top N from scoreboard
    python3 scripts/generate_certificates.py --min-score 1000     # Minimum score filter
    python3 scripts/generate_certificates.py --export png         # Also export to PNG
    python3 scripts/generate_certificates.py --list               # List all users (no certs)

Environment variables:
    CTFD_URL            Base URL for CTFd (default: http://localhost:8000)
    CTFD_ACCESS_TOKEN   API access token (admin)

Author: MrHacker (Kevin Munoz) -- Wazuh Technology Ambassador
"""

import argparse
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    print("[!] The 'requests' library is required. Install it with: pip3 install requests")
    sys.exit(1)


# ==============================================================================
# Configuration
# ==============================================================================

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
TEMPLATE_PATH = PROJECT_ROOT / "branding" / "certificates" / "certificate-template.svg"
OUTPUT_DIR = PROJECT_ROOT / "branding" / "certificates" / "generated"

# Load .env before reading env vars
from dotenv import load_dotenv  # noqa: E402 — local module, not python-dotenv
load_dotenv()

DEFAULT_CTFD_URL = os.getenv("CTFD_URL", "http://localhost:8000")
DEFAULT_ACCESS_TOKEN = os.getenv("CTFD_ACCESS_TOKEN", "")
SIGNING_SECRET = os.getenv("WBOTS_CERT_SECRET", "")

REGISTRY_PATH = PROJECT_ROOT / "branding" / "certificates" / "registry.json"
TOTAL_CHALLENGES = 150
TOTAL_POINTS = 39_200

# Achievement levels based on score percentage
ACHIEVEMENT_LEVELS = [
    (0.90, "Fenrir — Legendary Analyst"),
    (0.70, "Alpha — Senior Analyst"),
    (0.40, "Hunter — SOC Analyst"),
    (0.01, "Pup — Junior Analyst"),
    (0.00, "Participant"),
]

# ANSI colors
BLUE = "\033[38;2;59;130;246m"
CYAN = "\033[38;2;6;182;212m"
GREEN = "\033[38;2;34;197;94m"
AMBER = "\033[38;2;245;158;11m"
RED = "\033[38;2;239;68;68m"
DIM = "\033[38;2;148;163;184m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ==============================================================================
# CTFd API Client
# ==============================================================================

class CTFdClient:
    """CTFd REST API client for reading participant data."""

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
        })

    def _api(self, method: str, endpoint: str, **kwargs) -> dict:
        url = f"{self.base_url}/api/v1{endpoint}"
        resp = self.session.request(method, url, timeout=15, **kwargs)
        if resp.status_code == 403:
            print(f"{RED}[!] 403 Forbidden on {method} {endpoint}. Check your API token.{RESET}")
            sys.exit(1)
        if resp.status_code == 404:
            return {"data": None}
        resp.raise_for_status()
        return resp.json()

    def _paginate(self, endpoint: str) -> list:
        """Fetch all pages from a paginated endpoint."""
        results = []
        page = 1
        while True:
            data = self._api("GET", endpoint, params={"page": page})
            items = data.get("data", [])
            if not items:
                break
            results.extend(items)
            meta = data.get("meta", {}).get("pagination", {})
            if page >= meta.get("pages", 1):
                break
            page += 1
        return results

    def health_check(self) -> bool:
        try:
            resp = self.session.get(f"{self.base_url}/api/v1/challenges", timeout=10)
            return resp.status_code in (200, 403)
        except requests.ConnectionError:
            return False

    # -- Users --
    def get_users(self) -> list:
        return self._paginate("/users")

    def get_user(self, user_id: int) -> Optional[dict]:
        data = self._api("GET", f"/users/{user_id}")
        return data.get("data")

    def get_user_solves(self, user_id: int) -> list:
        data = self._api("GET", f"/users/{user_id}/solves")
        return data.get("data", [])

    # -- Teams --
    def get_teams(self) -> list:
        return self._paginate("/teams")

    def get_team(self, team_id: int) -> Optional[dict]:
        data = self._api("GET", f"/teams/{team_id}")
        return data.get("data")

    def get_team_solves(self, team_id: int) -> list:
        data = self._api("GET", f"/teams/{team_id}/solves")
        return data.get("data", [])

    # -- Scoreboard --
    def get_scoreboard(self) -> list:
        data = self._api("GET", "/scoreboard")
        return data.get("data", [])

    # -- Challenges (for total count) --
    def get_challenges(self) -> list:
        data = self._api("GET", "/challenges")
        return data.get("data", [])


# ==============================================================================
# Certificate Generation
# ==============================================================================

def get_achievement_level(score: int) -> str:
    """Determine achievement level based on score percentage."""
    pct = score / TOTAL_POINTS if TOTAL_POINTS > 0 else 0
    for threshold, label in ACHIEVEMENT_LEVELS:
        if pct >= threshold:
            return label
    return "Participant"


def generate_cert_id(name: str, score: int, rank: int, solved: int, secret: str = "") -> str:
    """Generate a deterministic, HMAC-signed certificate ID.

    If a secret is provided, uses HMAC-SHA256 (tamper-proof).
    Otherwise falls back to plain SHA-256 (still deterministic).
    """
    payload = f"WazuhBOTS-v1|{name}|{score}|{rank}|{solved}"
    if secret:
        sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()[:12]
    else:
        sig = hashlib.sha256(payload.encode()).hexdigest()[:12]
    return f"WBOTS-{sig.upper()}"


def render_certificate(
    name: str,
    score: int,
    rank: int,
    solved: int,
    date: Optional[str] = None,
    secret: str = "",
) -> tuple[str, dict]:
    """Read the SVG template and replace placeholders.

    Returns (svg_content, cert_record) where cert_record contains
    all the data needed for registry and verification.
    """
    if not TEMPLATE_PATH.exists():
        print(f"{RED}[!] Certificate template not found: {TEMPLATE_PATH}{RESET}")
        sys.exit(1)

    template = TEMPLATE_PATH.read_text(encoding="utf-8")

    if date is None:
        date = datetime.now().strftime("%B %d, %Y")

    achievement = get_achievement_level(score)
    cert_id = generate_cert_id(name, score, rank, solved, secret)

    cert_record = {
        "cert_id": cert_id,
        "name": name,
        "score": score,
        "rank": rank,
        "solved": solved,
        "level": achievement,
        "date": date,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "signed": bool(secret),
    }

    replacements = {
        "{{PARTICIPANT_NAME}}": name,
        "{{ACHIEVEMENT_LEVEL}}": achievement,
        "{{SCORE}}": f"{score:,}",
        "{{RANK}}": f"#{rank}",
        "{{SOLVED}}": str(solved),
        "{{DATE}}": date,
        "{{CERT_ID}}": cert_id,
    }

    svg = template
    for placeholder, value in replacements.items():
        svg = svg.replace(placeholder, value)

    return svg, cert_record


def load_registry() -> dict:
    """Load the certificate registry from disk."""
    if REGISTRY_PATH.exists():
        return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    return {"version": 1, "certificates": {}}


def save_registry(registry: dict) -> None:
    """Save the certificate registry to disk."""
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY_PATH.write_text(
        json.dumps(registry, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


# ==============================================================================
# GPG Signing
# ==============================================================================

GPG_KEY_ID = os.getenv("WBOTS_GPG_KEY", "E5616555DD4EDAAE")


def gpg_sign_file(file_path: Path, key_id: str = GPG_KEY_ID) -> bool:
    """Create a detached ASCII-armored GPG signature for a file."""
    sig_path = file_path.with_suffix(file_path.suffix + ".asc")
    # Remove old sig to avoid gpg prompt
    if sig_path.exists():
        sig_path.unlink()
    result = subprocess.run(
        ["gpg", "--batch", "--yes", "--detach-sign", "--armor",
         "--default-key", key_id, "--output", str(sig_path), str(file_path)],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def gpg_export_pubkey(key_id: str, output_path: Path) -> bool:
    """Export the public key so verifiers can import it."""
    result = subprocess.run(
        ["gpg", "--batch", "--armor", "--export", key_id],
        capture_output=True,
    )
    if result.returncode == 0 and result.stdout:
        output_path.write_bytes(result.stdout)
        return True
    return False


def export_to_png(svg_path: Path, png_path: Path) -> bool:
    """Convert SVG to PNG using inkscape or rsvg-convert."""
    if shutil.which("inkscape"):
        result = subprocess.run(
            ["inkscape", "-w", "2200", "-h", "1560", str(svg_path), "-o", str(png_path)],
            capture_output=True,
        )
        return result.returncode == 0
    elif shutil.which("rsvg-convert"):
        result = subprocess.run(
            ["rsvg-convert", "-w", "2200", str(svg_path), "-o", str(png_path)],
            capture_output=True,
        )
        return result.returncode == 0
    else:
        print(f"{AMBER}[!] No SVG converter found. Install inkscape or librsvg.{RESET}")
        return False


def export_to_pdf(svg_path: Path, pdf_path: Path) -> bool:
    """Convert SVG to PDF using inkscape."""
    if shutil.which("inkscape"):
        result = subprocess.run(
            ["inkscape", str(svg_path), "--export-type=pdf", f"--export-filename={pdf_path}"],
            capture_output=True,
        )
        return result.returncode == 0
    else:
        print(f"{AMBER}[!] PDF export requires inkscape.{RESET}")
        return False


# ==============================================================================
# Scoreboard Helpers
# ==============================================================================

def build_scoreboard_map(client: CTFdClient) -> dict:
    """Build a map of account_id -> rank from the scoreboard."""
    scoreboard = client.get_scoreboard()
    rank_map = {}
    for idx, entry in enumerate(scoreboard, start=1):
        account_id = entry.get("account_id") or entry.get("id")
        rank_map[account_id] = idx
    return rank_map


def get_user_data(client: CTFdClient, user: dict, rank_map: dict) -> dict:
    """Extract certificate-relevant data for a user."""
    user_id = user["id"]
    name = user.get("name", f"User #{user_id}")
    score = user.get("score", 0)
    rank = rank_map.get(user_id, 0)
    solves = client.get_user_solves(user_id)
    solved = len(solves)
    return {
        "id": user_id,
        "name": name,
        "score": score,
        "rank": rank,
        "solved": solved,
    }


def get_team_data(client: CTFdClient, team: dict, rank_map: dict) -> dict:
    """Extract certificate-relevant data for a team."""
    team_id = team["id"]
    name = team.get("name", f"Team #{team_id}")
    score = team.get("score", 0)
    rank = rank_map.get(team_id, 0)
    solves = client.get_team_solves(team_id)
    solved = len(solves)
    return {
        "id": team_id,
        "name": name,
        "score": score,
        "rank": rank,
        "solved": solved,
    }


# ==============================================================================
# Display
# ==============================================================================

def print_banner():
    print()
    print(f"  {BLUE}╔══════════════════════════════════════════╗{RESET}")
    print(f"  {BLUE}║{RESET}  {CYAN}WazuhBOTS Certificate Generator{RESET}         {BLUE}║{RESET}")
    print(f"  {BLUE}╚══════════════════════════════════════════╝{RESET}")
    print()


def print_user_table(participants: list):
    """Print a formatted table of participants."""
    print(f"  {'ID':>4}  {'Name':<30}  {'Score':>8}  {'Rank':>6}  {'Solved':>7}  {'Level'}")
    print(f"  {'─'*4}  {'─'*30}  {'─'*8}  {'─'*6}  {'─'*7}  {'─'*25}")
    for p in participants:
        level = get_achievement_level(p["score"])
        # Color based on level
        if "Fenrir" in level:
            c = RED
        elif "Alpha" in level:
            c = AMBER
        elif "Hunter" in level:
            c = BLUE
        elif "Pup" in level:
            c = GREEN
        else:
            c = DIM
        print(f"  {p['id']:>4}  {p['name']:<30}  {p['score']:>8,}  {p['rank']:>6}  {p['solved']:>7}  {c}{level}{RESET}")
    print()


# ==============================================================================
# Main
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate WazuhBOTS certificates from CTFd data",
    )
    parser.add_argument("--ctfd-url", default=DEFAULT_CTFD_URL,
                        help=f"CTFd base URL (default: {DEFAULT_CTFD_URL})")
    parser.add_argument("--token", default=DEFAULT_ACCESS_TOKEN,
                        help="CTFd API access token")
    parser.add_argument("--user", type=int, metavar="ID",
                        help="Generate certificate for a single user ID")
    parser.add_argument("--user-name", metavar="NAME",
                        help="Generate certificate for a user by name")
    parser.add_argument("--team", type=int, metavar="ID",
                        help="Generate certificate for a single team ID")
    parser.add_argument("--top", type=int, metavar="N",
                        help="Generate certificates for top N participants")
    parser.add_argument("--min-score", type=int, default=0,
                        help="Minimum score to generate certificate (default: 0)")
    parser.add_argument("--export", choices=["png", "pdf", "both"], default=None,
                        help="Export format in addition to SVG")
    parser.add_argument("--date", default=None,
                        help="Override certificate date (e.g., 'March 7, 2026')")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR,
                        help=f"Output directory (default: {OUTPUT_DIR})")
    parser.add_argument("--list", action="store_true",
                        help="List all participants without generating certificates")
    parser.add_argument("--teams", action="store_true",
                        help="Use team mode instead of individual users")
    parser.add_argument("--secret", default=SIGNING_SECRET,
                        help="HMAC secret for signing cert IDs (or set WBOTS_CERT_SECRET)")
    parser.add_argument("--gpg-sign", action="store_true",
                        help="Sign each certificate with GPG (detached .asc signature)")
    parser.add_argument("--gpg-key", default=GPG_KEY_ID,
                        help=f"GPG key ID to sign with (default: {GPG_KEY_ID})")

    args = parser.parse_args()

    print_banner()

    # -- Token validation --
    token = args.token
    if not token:
        token = input(f"  {AMBER}CTFd API Token:{RESET} ").strip()
    if not token:
        print(f"  {RED}[!] No API token provided. Set CTFD_ACCESS_TOKEN or use --token.{RESET}")
        sys.exit(1)

    # -- Connect --
    client = CTFdClient(args.ctfd_url, token)
    print(f"  {DIM}Connecting to {args.ctfd_url}...{RESET}", end=" ", flush=True)

    if not client.health_check():
        print(f"{RED}FAILED{RESET}")
        print(f"  {RED}[!] Cannot reach CTFd at {args.ctfd_url}{RESET}")
        sys.exit(1)
    print(f"{GREEN}OK{RESET}")

    # -- Build scoreboard --
    print(f"  {DIM}Fetching scoreboard...{RESET}", end=" ", flush=True)
    rank_map = build_scoreboard_map(client)
    print(f"{GREEN}{len(rank_map)} entries{RESET}")

    # -- Collect participants --
    participants = []

    if args.teams:
        # Team mode
        if args.team:
            team = client.get_team(args.team)
            if not team:
                print(f"  {RED}[!] Team ID {args.team} not found.{RESET}")
                sys.exit(1)
            participants = [get_team_data(client, team, rank_map)]
        else:
            print(f"  {DIM}Fetching teams...{RESET}", end=" ", flush=True)
            teams = client.get_teams()
            print(f"{GREEN}{len(teams)} teams{RESET}")
            for t in teams:
                participants.append(get_team_data(client, t, rank_map))
    else:
        # User mode
        if args.user:
            user = client.get_user(args.user)
            if not user:
                print(f"  {RED}[!] User ID {args.user} not found.{RESET}")
                sys.exit(1)
            participants = [get_user_data(client, user, rank_map)]
        elif args.user_name:
            print(f"  {DIM}Searching for '{args.user_name}'...{RESET}", end=" ", flush=True)
            users = client.get_users()
            matches = [u for u in users if args.user_name.lower() in u.get("name", "").lower()]
            if not matches:
                print(f"{RED}NOT FOUND{RESET}")
                sys.exit(1)
            print(f"{GREEN}{len(matches)} match(es){RESET}")
            for u in matches:
                participants.append(get_user_data(client, u, rank_map))
        else:
            print(f"  {DIM}Fetching users...{RESET}", end=" ", flush=True)
            users = client.get_users()
            # Filter out admins and hidden users
            users = [u for u in users if not u.get("hidden", False) and not u.get("banned", False)]
            print(f"{GREEN}{len(users)} users{RESET}")
            for u in users:
                participants.append(get_user_data(client, u, rank_map))

    # -- Apply filters --
    if args.min_score > 0:
        participants = [p for p in participants if p["score"] >= args.min_score]

    # Sort by rank (or score descending)
    participants.sort(key=lambda p: (p["rank"] if p["rank"] > 0 else 9999, -p["score"]))

    if args.top:
        participants = participants[:args.top]

    if not participants:
        print(f"\n  {AMBER}[!] No participants found matching criteria.{RESET}")
        sys.exit(0)

    # -- List mode --
    print(f"\n  {CYAN}Participants ({len(participants)}):{RESET}\n")
    print_user_table(participants)

    if args.list:
        sys.exit(0)

    # -- Signing info --
    secret = args.secret
    if secret:
        print(f"  {GREEN}✓{RESET} HMAC signing enabled")
    else:
        print(f"  {DIM}ℹ{RESET} No HMAC secret (cert IDs use plain SHA-256)")

    if args.gpg_sign:
        # Verify GPG key is available
        gpg_check = subprocess.run(
            ["gpg", "--batch", "--list-secret-keys", args.gpg_key],
            capture_output=True, text=True,
        )
        if gpg_check.returncode != 0:
            print(f"  {RED}[!] GPG key {args.gpg_key} not found{RESET}")
            sys.exit(1)
        print(f"  {GREEN}✓{RESET} GPG signing enabled  {DIM}[key: {args.gpg_key}]{RESET}")

    # -- Generate certificates --
    args.output_dir.mkdir(parents=True, exist_ok=True)
    registry = load_registry()

    # Store GPG info in registry metadata
    if args.gpg_sign:
        registry["gpg_key_id"] = args.gpg_key
        registry["gpg_fingerprint"] = "8862AB060D18A07560CFD5E5E5616555DD4EDAAE"

    print(f"\n  {CYAN}Generating certificates...{RESET}\n")

    generated = 0
    gpg_signed = 0
    for p in participants:
        # Sanitize filename
        safe_name = "".join(c if c.isalnum() or c in " _-" else "_" for c in p["name"]).strip()
        safe_name = safe_name.replace(" ", "_")

        svg_content, cert_record = render_certificate(
            name=p["name"],
            score=p["score"],
            rank=p["rank"],
            solved=p["solved"],
            date=args.date,
            secret=secret,
        )

        # Write SVG
        svg_path = args.output_dir / f"cert_{safe_name}.svg"
        svg_path.write_text(svg_content, encoding="utf-8")

        # GPG sign
        if args.gpg_sign:
            if gpg_sign_file(svg_path, args.gpg_key):
                cert_record["gpg_signed"] = True
                cert_record["gpg_key_id"] = args.gpg_key
                gpg_signed += 1
            else:
                cert_record["gpg_signed"] = False
                print(f"  {AMBER}⚠ GPG sign failed for {p['name']}{RESET}")

        # Save to registry
        registry["certificates"][cert_record["cert_id"]] = cert_record

        level = get_achievement_level(p["score"])
        status_parts = [f"{svg_path.name}"]

        # Optional exports + GPG sign each exported file
        if args.export in ("png", "both"):
            png_path = args.output_dir / f"cert_{safe_name}.png"
            if export_to_png(svg_path, png_path):
                status_parts.append(".png")
                if args.gpg_sign and gpg_sign_file(png_path, args.gpg_key):
                    gpg_signed += 1

        if args.export in ("pdf", "both"):
            pdf_path = args.output_dir / f"cert_{safe_name}.pdf"
            if export_to_pdf(svg_path, pdf_path):
                status_parts.append(".pdf")
                if args.gpg_sign and gpg_sign_file(pdf_path, args.gpg_key):
                    gpg_signed += 1

        if args.gpg_sign and cert_record.get("gpg_signed"):
            status_parts.append(".asc")

        files_str = " + ".join(status_parts)
        print(f"  {GREEN}✓{RESET} {p['name']:<30} {DIM}→{RESET} {files_str}  {DIM}[{cert_record['cert_id']}]{RESET}")

        generated += 1

    # -- Save & sign registry --
    save_registry(registry)

    if args.gpg_sign:
        gpg_sign_file(REGISTRY_PATH, args.gpg_key)
        # Export public key for verifiers
        pubkey_path = args.output_dir / "wazuhbots-signing-key.asc"
        if gpg_export_pubkey(args.gpg_key, pubkey_path):
            print(f"\n  {GREEN}✓{RESET} Public key exported → {pubkey_path.name}")

    # -- Summary --
    print()
    print(f"  {GREEN}{'═' * 50}{RESET}")
    print(f"  {GREEN}✓ {generated} certificate(s) generated{RESET}")
    if args.gpg_sign:
        print(f"  {GREEN}✓ {gpg_signed} GPG signature(s) created (.asc){RESET}")
    print(f"  {DIM}Registry: {REGISTRY_PATH} ({len(registry['certificates'])} total){RESET}")
    print(f"  {DIM}Output:   {args.output_dir}/{RESET}")
    print()


if __name__ == "__main__":
    main()
