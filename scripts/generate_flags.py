#!/usr/bin/env python3
"""
WazuhBOTS -- Generate Flags & Load Challenges into CTFd

Reads challenge definitions from ctfd/challenges/*.json, optionally
regenerates flag values, and pushes everything to the CTFd REST API.

Usage:
    python3 scripts/generate_flags.py                 # Create challenges in CTFd
    python3 scripts/generate_flags.py --dry-run       # Preview without writing
    python3 scripts/generate_flags.py --regenerate    # Regenerate random flags
    python3 scripts/generate_flags.py --ctfd-url URL  # Override CTFd URL
    python3 scripts/generate_flags.py --token TOKEN   # Provide API token directly

Environment variables:
    CTFD_URL            Base URL for CTFd (default: http://localhost:8000)
    CTFD_ACCESS_TOKEN   API access token (admin)
    CTFD_SECRET_KEY     Fallback secret key

Author: MrHacker (Kevin Munoz) -- Wazuh Technology Ambassador
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Optional

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
CHALLENGES_DIR = PROJECT_ROOT / "ctfd" / "challenges"

# Load .env before reading env vars
from dotenv import load_dotenv  # noqa: E402 — local module, not python-dotenv
load_dotenv()

DEFAULT_CTFD_URL = os.getenv("CTFD_URL", "http://localhost:8000")
DEFAULT_ACCESS_TOKEN = os.getenv("CTFD_ACCESS_TOKEN", "")


# ==============================================================================
# CTFd API Client
# ==============================================================================

class CTFdClient:
    """Minimal CTFd REST API client for challenge management."""

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
        })

    def _api(self, method: str, endpoint: str, **kwargs) -> dict:
        url = f"{self.base_url}/api/v1{endpoint}"
        resp = self.session.request(method, url, **kwargs)
        if resp.status_code == 403:
            print(f"[!] 403 Forbidden on {method} {endpoint}. Check your API token.")
            sys.exit(1)
        resp.raise_for_status()
        return resp.json()

    def get_challenges(self) -> list:
        """Retrieve all existing challenges."""
        data = self._api("GET", "/challenges")
        return data.get("data", [])

    def create_challenge(self, payload: dict) -> dict:
        """Create a new challenge. Returns the created challenge data."""
        data = self._api("POST", "/challenges", json=payload)
        return data.get("data", {})

    def delete_challenge(self, challenge_id: int) -> None:
        """Delete a challenge by ID."""
        self._api("DELETE", f"/challenges/{challenge_id}")

    def create_flag(self, challenge_id: int, flag_content: str, flag_type: str = "static") -> dict:
        """Add a flag to a challenge."""
        payload = {
            "challenge_id": challenge_id,
            "content": flag_content,
            "type": flag_type,
            "data": "",
        }
        data = self._api("POST", "/flags", json=payload)
        return data.get("data", {})

    def create_hint(self, challenge_id: int, content: str, cost: int = 0) -> dict:
        """Add a hint to a challenge."""
        payload = {
            "challenge_id": challenge_id,
            "content": content,
            "cost": cost,
            "type": "standard",
        }
        data = self._api("POST", "/hints", json=payload)
        return data.get("data", {})

    def create_tag(self, challenge_id: int, value: str) -> dict:
        """Add a tag to a challenge."""
        payload = {
            "challenge_id": challenge_id,
            "value": value,
        }
        data = self._api("POST", "/tags", json=payload)
        return data.get("data", {})

    def health_check(self) -> bool:
        """Verify CTFd is reachable and API token is valid."""
        try:
            resp = self.session.get(
                f"{self.base_url}/api/v1/challenges",
                timeout=10,
            )
            return resp.status_code in (200, 403)
        except requests.ConnectionError:
            return False


# ==============================================================================
# Challenge loading
# ==============================================================================

def load_challenge_files() -> list[dict]:
    """Load all challenge JSON files from ctfd/challenges/ directory."""
    if not CHALLENGES_DIR.exists():
        print(f"[!] Challenges directory not found: {CHALLENGES_DIR}")
        return []

    all_challenges = []
    json_files = sorted(CHALLENGES_DIR.glob("*.json"))

    if not json_files:
        print(f"[!] No challenge JSON files found in {CHALLENGES_DIR}")
        return []

    for filepath in json_files:
        print(f"  [*] Loading {filepath.name}")
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"  [!] Error reading {filepath.name}: {exc}")
            continue

        # Support both {"challenges": [...]} and bare [...]
        if isinstance(data, dict) and "challenges" in data:
            challenges = data["challenges"]
        elif isinstance(data, list):
            challenges = data
        else:
            print(f"  [!] Unexpected format in {filepath.name}, skipping.")
            continue

        for ch in challenges:
            ch["_source_file"] = filepath.name

        all_challenges.extend(challenges)

    return all_challenges


def regenerate_flag(original_flag: str) -> str:
    """Generate a new random flag value (bare hex string, no wrapper)."""
    return secrets.token_hex(12)


# ==============================================================================
# Dry run display
# ==============================================================================

def dry_run_display(challenges: list[dict], regenerate: bool) -> None:
    """Print a preview of what would be created in CTFd."""
    print("\n" + "=" * 70)
    print("  DRY RUN — No changes will be made to CTFd")
    print("=" * 70)

    categories: dict[str, list] = {}
    for ch in challenges:
        cat = ch.get("category", "Uncategorized")
        categories.setdefault(cat, []).append(ch)

    total_points = 0
    for cat_name, cat_challenges in categories.items():
        print(f"\n  Category: {cat_name}")
        print(f"  {'─' * 60}")
        for ch in cat_challenges:
            name = ch.get("name", "Unnamed")
            value = ch.get("value", 0)
            total_points += value
            flags = ch.get("flags", [])
            hints = ch.get("hints", [])
            tags = ch.get("tags", [])

            if regenerate and flags:
                display_flags = [regenerate_flag(f) for f in flags]
            else:
                display_flags = flags

            print(f"    Challenge: {name}")
            print(f"      Points:  {value}")
            print(f"      Flags:   {display_flags}")
            print(f"      Hints:   {len(hints)}")
            print(f"      Tags:    {tags}")
            print()

    print(f"  {'=' * 60}")
    print(f"  Total: {len(challenges)} challenges, {total_points} points across {len(categories)} categories")
    print(f"  {'=' * 60}\n")


# ==============================================================================
# Push challenges to CTFd
# ==============================================================================

def push_challenges(
    client: CTFdClient,
    challenges: list[dict],
    regenerate: bool,
) -> tuple[int, int]:
    """
    Create challenges in CTFd via the API.
    Returns (success_count, error_count).
    """
    success = 0
    errors = 0

    for ch in challenges:
        name = ch.get("name", "Unnamed")
        try:
            # Build challenge payload
            payload = {
                "name": name,
                "category": ch.get("category", "Uncategorized"),
                "description": ch.get("description", ""),
                "value": ch.get("value", 100),
                "type": ch.get("type", "standard"),
                "state": ch.get("state", "visible"),
                "max_attempts": ch.get("max_attempts", 0),
            }

            # Create the challenge
            created = client.create_challenge(payload)
            challenge_id = created.get("id")

            if not challenge_id:
                print(f"  [!] Failed to create challenge: {name}")
                errors += 1
                continue

            # Add flags
            flags = ch.get("flags", [])
            for flag_entry in flags:
                # Support both dict format {"content": "...", "type": "..."} and plain strings
                if isinstance(flag_entry, dict):
                    flag_content = flag_entry.get("content", "")
                    flag_type = flag_entry.get("type", "static")
                else:
                    flag_content = str(flag_entry)
                    flag_type = "static"
                if regenerate:
                    flag_content = regenerate_flag(flag_content)
                client.create_flag(challenge_id, flag_content, flag_type)

            # Add hints
            hints = ch.get("hints", [])
            for hint in hints:
                if isinstance(hint, dict):
                    client.create_hint(
                        challenge_id,
                        hint.get("content", ""),
                        hint.get("cost", 0),
                    )
                elif isinstance(hint, str):
                    client.create_hint(challenge_id, hint, 0)

            # Add tags
            tags = ch.get("tags", [])
            for tag in tags:
                client.create_tag(challenge_id, tag)

            print(f"  [+] Created: {name} ({ch.get('value', 0)} pts, {len(flags)} flag(s), {len(hints)} hint(s))")
            success += 1

        except requests.HTTPError as exc:
            print(f"  [!] HTTP error creating '{name}': {exc}")
            errors += 1
        except Exception as exc:
            print(f"  [!] Unexpected error creating '{name}': {exc}")
            errors += 1

    return success, errors


# ==============================================================================
# Interactive token setup
# ==============================================================================

def get_api_token(args: argparse.Namespace) -> str:
    """Resolve the CTFd API token from args, env, or interactive prompt."""
    # 1. CLI argument
    if args.token:
        return args.token

    # 2. Environment variable
    if DEFAULT_ACCESS_TOKEN:
        return DEFAULT_ACCESS_TOKEN

    # 3. Interactive prompt
    print("\n[*] CTFd API access token is required.")
    print("    To create one: CTFd Admin Panel > Settings > Access Tokens > Generate")
    print("    Or set the CTFD_ACCESS_TOKEN environment variable.\n")
    token = input("  Enter CTFd access token: ").strip()
    if not token:
        print("[!] No token provided. Exiting.")
        sys.exit(1)
    return token


# ==============================================================================
# Main
# ==============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="WazuhBOTS -- Generate flags and load challenges into CTFd",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview challenges without pushing to CTFd",
    )
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Regenerate flag values with random hex strings",
    )
    parser.add_argument(
        "--ctfd-url",
        type=str,
        default=DEFAULT_CTFD_URL,
        help=f"CTFd base URL (default: {DEFAULT_CTFD_URL})",
    )
    parser.add_argument(
        "--token",
        type=str,
        default="",
        help="CTFd API access token",
    )
    parser.add_argument(
        "--clear-existing",
        action="store_true",
        help="Delete all existing challenges before importing",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  WazuhBOTS -- CTFd Challenge Generator")
    print("=" * 60)

    # Load challenge definitions from JSON files
    challenges = load_challenge_files()
    if not challenges:
        print("\n[!] No challenges to process. Exiting.")
        sys.exit(1)

    print(f"\n[*] Loaded {len(challenges)} challenges from {CHALLENGES_DIR}")

    # Dry run mode -- just display and exit
    if args.dry_run:
        dry_run_display(challenges, args.regenerate)
        return

    # Resolve API token
    token = get_api_token(args)

    # Initialize CTFd client
    client = CTFdClient(args.ctfd_url, token)

    # Verify connectivity
    print(f"\n[*] Connecting to CTFd at {args.ctfd_url}...")
    if not client.health_check():
        print(f"[!] Cannot reach CTFd at {args.ctfd_url}")
        print("    Make sure CTFd is running and the URL is correct.")
        print("    Also ensure you have completed the CTFd initial setup wizard.")
        sys.exit(1)
    print("[+] CTFd is reachable")

    # Optionally clear existing challenges
    if args.clear_existing:
        print("\n[*] Removing existing challenges...")
        existing = client.get_challenges()
        for ch in existing:
            client.delete_challenge(ch["id"])
        print(f"[+] Removed {len(existing)} existing challenges")

    # Push challenges
    print(f"\n[*] Creating {len(challenges)} challenges in CTFd...")
    success, errors = push_challenges(client, challenges, args.regenerate)

    # Summary
    print(f"\n{'=' * 60}")
    print(f"  Results: {success} created, {errors} errors")
    if args.regenerate:
        print("  Flags were regenerated with new random values.")
        print("  IMPORTANT: The new flags are only stored in CTFd.")
    print(f"{'=' * 60}\n")

    if errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
