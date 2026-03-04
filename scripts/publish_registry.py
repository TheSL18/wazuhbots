#!/usr/bin/env python3
"""
WazuhBOTS -- Publish Certificate Registry to Web

Copies registry.json to docs/ so the verification web page can load it.
Re-derives HMAC for each certificate server-side so the web can show results
without exposing the secret.
Optionally embeds the registry directly into verify.html for offline use.

Usage:
    python3 scripts/publish_registry.py              # Copy to docs/
    python3 scripts/publish_registry.py --embed       # Embed into verify.html

Author: MrHacker (Kevin Munoz) -- Wazuh Technology Ambassador
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
REGISTRY_SRC = PROJECT_ROOT / "branding" / "certificates" / "registry.json"
DOCS_DIR = PROJECT_ROOT / "docs"
VERIFY_HTML = DOCS_DIR / "verify.html"

# Load .env
from dotenv import load_dotenv  # noqa: E402
load_dotenv()

SIGNING_SECRET = os.getenv("WBOTS_CERT_SECRET", "")

BLUE = "\033[38;2;59;130;246m"
GREEN = "\033[38;2;34;197;94m"
AMBER = "\033[38;2;245;158;11m"
DIM = "\033[38;2;148;163;184m"
RED = "\033[38;2;239;68;68m"
RESET = "\033[0m"


def recompute_cert_id(name, score, rank, solved, secret):
    """Re-derive a cert ID from participant data + secret."""
    payload = f"WazuhBOTS-v1|{name}|{score}|{rank}|{solved}"
    if secret:
        sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()[:12]
    else:
        sig = hashlib.sha256(payload.encode()).hexdigest()[:12]
    return f"WBOTS-{sig.upper()}"


def verify_registry_hmac(registry, secret):
    """Re-derive HMAC for each cert and add hmac_verified field."""
    verified = 0
    failed = 0
    for cert_id, record in registry.get("certificates", {}).items():
        if not secret:
            record["hmac_verified"] = None
            continue
        expected = recompute_cert_id(
            record["name"], record["score"], record["rank"], record["solved"], secret
        )
        ok = hmac.compare_digest(expected, cert_id)
        record["hmac_verified"] = ok
        if ok:
            verified += 1
        else:
            failed += 1
    return verified, failed


def main():
    parser = argparse.ArgumentParser(description="Publish certificate registry to web")
    parser.add_argument("--embed", action="store_true",
                        help="Embed registry data directly into verify.html")
    args = parser.parse_args()

    if not REGISTRY_SRC.exists():
        print(f"{RED}[!] Registry not found: {REGISTRY_SRC}{RESET}")
        print(f"{DIM}    Generate certificates first.{RESET}")
        sys.exit(1)

    registry = json.loads(REGISTRY_SRC.read_text(encoding="utf-8"))
    n = len(registry.get("certificates", {}))

    print(f"\n  {BLUE}WazuhBOTS Registry Publisher{RESET}")
    print(f"  {DIM}Registry: {n} certificate(s){RESET}\n")

    # HMAC verification at publish time
    if SIGNING_SECRET:
        verified, failed = verify_registry_hmac(registry, SIGNING_SECRET)
        print(f"  {GREEN}✓{RESET} HMAC verified: {verified} valid", end="")
        if failed:
            print(f", {RED}{failed} FAILED{RESET}")
        else:
            print()
    else:
        verify_registry_hmac(registry, "")
        print(f"  {AMBER}⚠{RESET} No WBOTS_CERT_SECRET — HMAC verification skipped")

    # Copy to docs/
    dest = DOCS_DIR / "registry.json"
    dest.write_text(
        json.dumps(registry, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"  {GREEN}✓{RESET} Published → {dest}")

    if args.embed:
        if not VERIFY_HTML.exists():
            print(f"  {RED}[!] verify.html not found{RESET}")
            sys.exit(1)

        html = VERIFY_HTML.read_text(encoding="utf-8")

        # Remove any previously embedded registry
        html = re.sub(
            r'// __EMBEDDED_REGISTRY_START__.*?// __EMBEDDED_REGISTRY_END__\n?',
            '',
            html,
            flags=re.DOTALL,
        )

        # Embed registry right after "let REGISTRY = null;"
        registry_json = json.dumps(registry, ensure_ascii=False)
        embed_block = (
            f"// __EMBEDDED_REGISTRY_START__\n"
            f"REGISTRY = {registry_json};\n"
            f"// __EMBEDDED_REGISTRY_END__\n"
        )
        html = html.replace(
            'let REGISTRY = null;',
            f'let REGISTRY = null;\n{embed_block}',
        )

        VERIFY_HTML.write_text(html, encoding="utf-8")
        print(f"  {GREEN}✓{RESET} Embedded {n} certs into verify.html")

    print(f"\n  {GREEN}Done.{RESET} Open docs/verify.html in a browser to test.\n")


if __name__ == "__main__":
    main()
