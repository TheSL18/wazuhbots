#!/usr/bin/env python3
"""
WazuhBOTS -- Ingest Pre-generated Datasets into Wazuh Indexer (OpenSearch)

Reads JSON dataset files from the datasets/ directory and bulk-indexes them
into OpenSearch via the REST API. Supports per-scenario or full ingestion
with progress tracking.

Usage:
    python3 scripts/ingest_datasets.py --all
    python3 scripts/ingest_datasets.py --scenario scenario1_dark_harvest
    python3 scripts/ingest_datasets.py --scenario scenario3_ghost_shell --bulk-size 1000
    python3 scripts/ingest_datasets.py --all --dry-run
    python3 scripts/ingest_datasets.py --list

Environment variables:
    INDEXER_URL         OpenSearch URL (default: https://localhost:9200)
    INDEXER_USERNAME    Username (default: admin)
    INDEXER_PASSWORD    Password (default: admin)

Author: MrHacker (Kevin Munoz) -- Wazuh Technology Ambassador
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Generator

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] The 'requests' library is required. Install it with: pip3 install requests")
    sys.exit(1)


# ==============================================================================
# Configuration
# ==============================================================================

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DATASETS_DIR = PROJECT_ROOT / "datasets"

INDEXER_URL = os.getenv("INDEXER_URL", "https://localhost:9200")
INDEXER_USER = os.getenv("INDEXER_USERNAME", "admin")
INDEXER_PASS = os.getenv("INDEXER_PASSWORD", "admin")

DEFAULT_BULK_SIZE = 500   # Documents per bulk API request
REQUEST_TIMEOUT = 60      # Seconds


# ==============================================================================
# Progress bar
# ==============================================================================

def progress_bar(current: int, total: int, width: int = 40, prefix: str = "") -> None:
    """Render an inline progress bar to stdout."""
    if total == 0:
        return
    fraction = current / total
    filled = int(width * fraction)
    bar = "#" * filled + "-" * (width - filled)
    percent = fraction * 100
    sys.stdout.write(f"\r  {prefix}[{bar}] {percent:5.1f}% ({current}/{total})")
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ==============================================================================
# OpenSearch / Wazuh Indexer API helpers
# ==============================================================================

def indexer_request(method: str, path: str, **kwargs) -> requests.Response:
    """Make an authenticated request to the Wazuh Indexer."""
    url = f"{INDEXER_URL}{path}"
    kwargs.setdefault("auth", (INDEXER_USER, INDEXER_PASS))
    kwargs.setdefault("verify", False)
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    return requests.request(method, url, **kwargs)


def check_connection() -> bool:
    """Verify we can reach the Wazuh Indexer."""
    try:
        resp = indexer_request("GET", "/")
        if resp.status_code == 200:
            info = resp.json()
            version = info.get("version", {}).get("number", "unknown")
            cluster = info.get("cluster_name", "unknown")
            print(f"  [+] Connected to Wazuh Indexer (version {version}, cluster: {cluster})")
            return True
        else:
            print(f"  [!] Unexpected response: HTTP {resp.status_code}")
            return False
    except requests.ConnectionError:
        print(f"  [!] Cannot connect to {INDEXER_URL}")
        return False


def create_index(index_name: str) -> bool:
    """
    Create an index if it doesn't exist. Settings and mappings come from
    the index template (wazuh or wazuhbots), so we only send a minimal body.
    Returns True if the index is ready (created or already exists).
    """
    resp = indexer_request("PUT", f"/{index_name}", json={})
    if resp.status_code == 200:
        return True
    elif resp.status_code == 400:
        # Index already exists
        error_type = resp.json().get("error", {}).get("type", "")
        if "resource_already_exists" in error_type:
            return True
        print(f"  [!] Error creating index {index_name}: {resp.text}")
        return False
    else:
        print(f"  [!] Error creating index {index_name}: HTTP {resp.status_code}")
        return False


def delete_index(index_name: str) -> bool:
    """Delete an index if it exists."""
    resp = indexer_request("DELETE", f"/{index_name}")
    return resp.status_code in (200, 404)


def bulk_ingest(index_name: str, documents: list[dict]) -> tuple[int, int]:
    """
    Bulk-index a batch of documents. Returns (success_count, error_count).
    """
    if not documents:
        return 0, 0

    lines = []
    for doc in documents:
        action = json.dumps({"index": {"_index": index_name}})
        lines.append(action)
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"

    resp = indexer_request(
        "POST",
        "/_bulk",
        data=body,
        headers={"Content-Type": "application/x-ndjson"},
    )

    if resp.status_code != 200:
        return 0, len(documents)

    result = resp.json()
    items = result.get("items", [])
    error_count = sum(1 for item in items if item.get("index", {}).get("error"))
    success_count = len(items) - error_count

    return success_count, error_count


# ==============================================================================
# Dataset loading
# ==============================================================================

def load_json_documents(filepath: Path) -> list[dict]:
    """
    Load documents from a JSON file. Supports:
      - JSON array of objects: [{"field": "value"}, ...]
      - Newline-delimited JSON (NDJSON): one object per line
      - Single JSON object (wrapped into a list)
    """
    content = filepath.read_text(encoding="utf-8").strip()
    if not content:
        return []

    # Try standard JSON first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    # Try NDJSON (one JSON object per line)
    documents = []
    for line_num, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
            if isinstance(doc, dict):
                documents.append(doc)
        except json.JSONDecodeError as exc:
            print(f"  [!] Parse error in {filepath.name} line {line_num}: {exc}")

    return documents


def discover_scenarios() -> list[Path]:
    """Find all scenario directories under datasets/."""
    if not DATASETS_DIR.exists():
        return []
    return sorted(
        d for d in DATASETS_DIR.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    )


def discover_dataset_files(scenario_dir: Path) -> list[Path]:
    """Find all JSON data files in a scenario directory (excluding metadata)."""
    return sorted(
        f for f in scenario_dir.glob("*.json")
        if f.name != "metadata.json" and f.stat().st_size > 0
    )


# ==============================================================================
# Ingestion logic
# ==============================================================================

def ensure_timestamp(doc: dict) -> dict:
    """Ensure document has both timestamp and @timestamp fields."""
    if "@timestamp" not in doc and "timestamp" in doc:
        doc["@timestamp"] = doc["timestamp"]
    return doc


def index_name_from_doc(doc: dict) -> str:
    """Derive wazuh-alerts-4.x-YYYY.MM.DD index name from document timestamp."""
    ts = doc.get("timestamp", "")
    # Extract date part from ISO-8601 timestamp
    date_part = ts[:10] if len(ts) >= 10 else "2026.03.01"
    # Convert 2026-03-01 to 2026.03.01
    date_dot = date_part.replace("-", ".")
    return f"wazuh-alerts-4.x-{date_dot}"


def check_wazuh_template() -> bool:
    """Check if the wazuh index template exists; install a BOTS-compatible one if not."""
    resp = indexer_request("GET", "/_index_template/wazuh")
    if resp.status_code == 200:
        print("  [+] Wazuh index template found")
        return True
    # Also check legacy templates
    resp2 = indexer_request("GET", "/_template/wazuh")
    if resp2.status_code == 200:
        print("  [+] Wazuh legacy index template found")
        return True
    print("  [!] No Wazuh index template found -- installing WazuhBOTS template...")
    return install_bots_template()


def install_bots_template() -> bool:
    """Install an index template with keyword mappings for all BOTS alert fields."""
    template = {
        "index_patterns": ["wazuh-alerts-4.x-*"],
        "priority": 1,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "index.refresh_interval": "5s",
            },
            "mappings": {
                "dynamic": "true",
                "dynamic_templates": [
                    {
                        "strings_as_keyword": {
                            "match_mapping_type": "string",
                            "mapping": {
                                "type": "keyword",
                                "ignore_above": 2048,
                                "fields": {
                                    "text": {"type": "text"}
                                },
                            },
                        }
                    }
                ],
                "properties": {
                    "timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
                    "@timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
                    "agent": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "name": {"type": "keyword"},
                            "ip": {"type": "keyword"},
                        }
                    },
                    "manager": {
                        "properties": {
                            "name": {"type": "keyword"},
                        }
                    },
                    "rule": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "description": {"type": "keyword", "ignore_above": 2048, "fields": {"text": {"type": "text"}}},
                            "level": {"type": "integer"},
                            "groups": {"type": "keyword"},
                            "mitre": {
                                "properties": {
                                    "id": {"type": "keyword"},
                                    "tactic": {"type": "keyword"},
                                    "technique": {"type": "keyword"},
                                }
                            },
                        }
                    },
                    "decoder": {
                        "properties": {
                            "name": {"type": "keyword"},
                        }
                    },
                    "location": {"type": "keyword"},
                    "full_log": {"type": "keyword", "ignore_above": 4096, "fields": {"text": {"type": "text"}}},
                    "data": {
                        "properties": {
                            "srcip": {"type": "keyword"},
                            "dstip": {"type": "keyword"},
                            "srcport": {"type": "keyword"},
                            "dstport": {"type": "keyword"},
                            "srcuser": {"type": "keyword"},
                            "dstuser": {"type": "keyword"},
                            "command": {"type": "keyword", "ignore_above": 2048, "fields": {"text": {"type": "text"}}},
                            "url": {"type": "keyword", "ignore_above": 2048},
                            "protocol": {"type": "keyword"},
                            "program_name": {"type": "keyword"},
                            "user_agent": {"type": "keyword", "ignore_above": 1024},
                            "http_method": {"type": "keyword"},
                            "http_status_code": {"type": "keyword"},
                            "response_size": {"type": "keyword"},
                            "bytes_sent": {"type": "keyword"},
                            "query_name": {"type": "keyword", "ignore_above": 2048},
                            "query_type": {"type": "keyword"},
                            "base_domain": {"type": "keyword"},
                            "chunk_name": {"type": "keyword"},
                            "chunk_index": {"type": "keyword"},
                            "cumulative_bytes": {"type": "keyword"},
                            "pip": {
                                "properties": {
                                    "package_name": {"type": "keyword"},
                                    "package_version": {"type": "keyword"},
                                    "package_hash": {"type": "keyword"},
                                }
                            },
                            "dns": {
                                "properties": {
                                    "query_count": {"type": "keyword"},
                                    "subdomain_length": {"type": "keyword"},
                                }
                            },
                            "logrotate": {
                                "properties": {
                                    "original_rotate": {"type": "keyword"},
                                    "original_maxage": {"type": "keyword"},
                                    "new_rotate": {"type": "keyword"},
                                    "new_maxage": {"type": "keyword"},
                                    "config_path": {"type": "keyword"},
                                }
                            },
                            "systemd": {
                                "properties": {
                                    "unit_file_path": {"type": "keyword"},
                                }
                            },
                            "audit": {
                                "properties": {
                                    "exe": {"type": "keyword"},
                                    "key": {"type": "keyword"},
                                    "syscall": {"type": "keyword"},
                                    "ppid_exe": {"type": "keyword"},
                                }
                            },
                            "geoip": {
                                "properties": {
                                    "country_name": {"type": "keyword"},
                                    "city_name": {"type": "keyword"},
                                }
                            },
                            "win": {
                                "properties": {
                                    "system": {
                                        "properties": {
                                            "eventID": {"type": "keyword"},
                                            "channel": {"type": "keyword"},
                                        }
                                    },
                                    "eventdata": {
                                        "properties": {
                                            "image": {"type": "keyword", "ignore_above": 2048},
                                            "commandLine": {"type": "keyword", "ignore_above": 4096, "fields": {"text": {"type": "text"}}},
                                            "parentCommandLine": {"type": "keyword", "ignore_above": 4096, "fields": {"text": {"type": "text"}}},
                                            "targetUserName": {"type": "keyword"},
                                            "targetDomainName": {"type": "keyword"},
                                            "subjectUserName": {"type": "keyword"},
                                            "workstationName": {"type": "keyword"},
                                            "ipAddress": {"type": "keyword"},
                                            "ipPort": {"type": "keyword"},
                                            "logonType": {"type": "keyword"},
                                            "logonProcessName": {"type": "keyword"},
                                            "authenticationPackageName": {"type": "keyword"},
                                            "serviceName": {"type": "keyword"},
                                            "serviceFileName": {"type": "keyword", "ignore_above": 2048},
                                            "serviceType": {"type": "keyword"},
                                            "serviceStartType": {"type": "keyword"},
                                            "taskName": {"type": "keyword"},
                                            "hashes": {"type": "keyword", "ignore_above": 2048},
                                            "sourceIp": {"type": "keyword"},
                                            "destinationIp": {"type": "keyword"},
                                            "destinationPort": {"type": "keyword"},
                                            "grantedAccess": {"type": "keyword"},
                                            "targetFilename": {"type": "keyword", "ignore_above": 2048},
                                            "ticketEncryptionType": {"type": "keyword"},
                                        }
                                    },
                                }
                            },
                        }
                    },
                    "syscheck": {
                        "properties": {
                            "path": {"type": "keyword", "ignore_above": 2048},
                            "event": {"type": "keyword"},
                            "md5_after": {"type": "keyword"},
                            "sha256_after": {"type": "keyword"},
                            "uid_after": {"type": "keyword"},
                            "gid_after": {"type": "keyword"},
                            "uname_after": {"type": "keyword"},
                            "size_after": {"type": "keyword"},
                            "changed_attributes": {"type": "keyword"},
                            "diff": {"type": "keyword", "ignore_above": 4096, "fields": {"text": {"type": "text"}}},
                        }
                    },
                },
            },
        },
    }

    resp = indexer_request("PUT", "/_index_template/wazuhbots", json=template)
    if resp.status_code == 200:
        print("  [+] WazuhBOTS index template installed successfully")
        return True
    print(f"  [!] Failed to install template: HTTP {resp.status_code}")
    print(f"      {resp.text[:500]}")
    return False


def ingest_file(
    filepath: Path,
    bulk_size: int,
    dry_run: bool = False,
) -> tuple[int, int]:
    """
    Ingest a single JSON file into OpenSearch using wazuh-alerts-4.x-YYYY.MM.DD index.
    Returns (total_success, total_errors).
    """
    documents = load_json_documents(filepath)
    if not documents:
        print(f"  [*] {filepath.name}: empty or unreadable, skipping")
        return 0, 0

    # Ensure @timestamp exists and group by target index
    index_groups: dict[str, list[dict]] = {}
    for doc in documents:
        ensure_timestamp(doc)
        idx = index_name_from_doc(doc)
        index_groups.setdefault(idx, []).append(doc)

    if dry_run:
        for idx, docs in sorted(index_groups.items()):
            print(f"  [*] {filepath.name}: {len(docs)} documents -> {idx} (dry-run)")
        total = sum(len(d) for d in index_groups.values())
        return total, 0

    total_success = 0
    total_errors = 0
    total_docs = len(documents)

    # Create indices and ingest by date-based index
    for idx, docs in sorted(index_groups.items()):
        if not create_index(idx):
            total_errors += len(docs)
            continue

        for i in range(0, len(docs), bulk_size):
            batch = docs[i : i + bulk_size]
            s, e = bulk_ingest(idx, batch)
            total_success += s
            total_errors += e

        progress_bar(
            total_success + total_errors,
            total_docs,
            prefix=f"{filepath.name}: ",
        )

    return total_success, total_errors


def reindex_delete_all(scenario_dirs: list[Path]) -> None:
    """Pre-scan ALL scenario dirs, collect every target index, delete once."""
    print(f"\n{'=' * 60}")
    print(f"  Reindex: scanning {len(scenario_dirs)} directories for target indices...")
    print(f"{'=' * 60}")
    target_indices: set[str] = set()
    for scenario_dir in scenario_dirs:
        for filepath in discover_dataset_files(scenario_dir):
            docs = load_json_documents(filepath)
            target_indices.update(index_name_from_doc(d) for d in docs if d)
    if target_indices:
        for idx in sorted(target_indices):
            print(f"  [*] Deleting index {idx}...")
            delete_index(idx)
        print(f"  [+] Deleted {len(target_indices)} indices\n")
    else:
        print("  [*] No target indices found\n")


def ingest_scenario(
    scenario_dir: Path,
    bulk_size: int,
    dry_run: bool = False,
) -> tuple[int, int]:
    """
    Ingest all dataset files from one scenario directory.
    Returns (total_success, total_errors).
    """
    scenario_name = scenario_dir.name
    print(f"\n{'=' * 60}")
    print(f"  Scenario: {scenario_name}")
    print(f"{'=' * 60}")

    files = discover_dataset_files(scenario_dir)
    if not files:
        print("  [*] No dataset files found in this scenario.")
        return 0, 0

    # Load and display metadata if available
    metadata_file = scenario_dir / "metadata.json"
    if metadata_file.exists():
        try:
            meta = json.loads(metadata_file.read_text(encoding="utf-8"))
            if "description" in meta:
                print(f"  Description: {meta['description']}")
            if "date_range" in meta:
                print(f"  Date range:  {meta['date_range']}")
        except (json.JSONDecodeError, OSError):
            pass

    print(f"  Files: {len(files)}")
    print()

    total_success = 0
    total_errors = 0

    for filepath in files:
        s, e = ingest_file(filepath, bulk_size, dry_run)
        total_success += s
        total_errors += e

    return total_success, total_errors


# ==============================================================================
# List mode
# ==============================================================================

def list_scenarios() -> None:
    """Display available scenarios and their dataset files."""
    scenarios = discover_scenarios()
    if not scenarios:
        print(f"  No scenario directories found in {DATASETS_DIR}")
        return

    print(f"\n  Available scenarios in {DATASETS_DIR}:\n")
    for sd in scenarios:
        files = discover_dataset_files(sd)
        total_size = sum(f.stat().st_size for f in files)
        size_mb = total_size / (1024 * 1024)
        print(f"    {sd.name}/")
        if files:
            for f in files:
                fsize = f.stat().st_size / (1024 * 1024)
                print(f"      - {f.name} ({fsize:.1f} MB)")
            print(f"      Total: {len(files)} files, {size_mb:.1f} MB")
        else:
            print("      (no dataset files)")
        print()


# ==============================================================================
# Main
# ==============================================================================

def main() -> None:
    global INDEXER_URL
    parser = argparse.ArgumentParser(
        description="WazuhBOTS -- Dataset Ingestion Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --all                              Ingest all scenarios
  %(prog)s --scenario scenario1_dark_harvest  Ingest one scenario
  %(prog)s --all --dry-run                    Preview without ingesting
  %(prog)s --list                             List available datasets
  %(prog)s --all --reindex                    Delete and re-create indices
        """,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--all", action="store_true", help="Ingest all scenarios")
    group.add_argument("--scenario", type=str, help="Specific scenario directory name")
    group.add_argument("--list", action="store_true", help="List available scenarios")

    parser.add_argument(
        "--bulk-size",
        type=int,
        default=DEFAULT_BULK_SIZE,
        help=f"Documents per bulk request (default: {DEFAULT_BULK_SIZE})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be ingested without making changes",
    )
    parser.add_argument(
        "--reindex",
        action="store_true",
        help="Delete existing indices before re-ingesting",
    )
    parser.add_argument(
        "--indexer-url",
        type=str,
        default=None,
        help=f"OpenSearch URL (default: {INDEXER_URL})",
    )
    args = parser.parse_args()

    # Allow CLI override of indexer URL
    if args.indexer_url:
        INDEXER_URL = args.indexer_url

    print("=" * 60)
    print("  WazuhBOTS -- Dataset Ingestion Tool")
    print("=" * 60)

    # List mode
    if args.list:
        list_scenarios()
        return

    # Require --all or --scenario
    if not args.all and not args.scenario:
        parser.print_help()
        sys.exit(1)

    # Verify indexer connectivity (skip for dry-run)
    if not args.dry_run:
        print(f"\n  [*] Connecting to Wazuh Indexer at {INDEXER_URL}...")
        if not check_connection():
            print("  [!] Cannot reach the Wazuh Indexer. Is it running?")
            print(f"      URL: {INDEXER_URL}")
            print(f"      User: {INDEXER_USER}")
            sys.exit(1)
        check_wazuh_template()
    else:
        print("\n  [*] DRY RUN mode -- no data will be written")

    # Determine which scenarios to process
    if args.all:
        scenario_dirs = discover_scenarios()
        if not scenario_dirs:
            print(f"\n  [!] No scenario directories found in {DATASETS_DIR}")
            sys.exit(1)
    else:
        target = DATASETS_DIR / args.scenario
        if not target.is_dir():
            print(f"\n  [!] Scenario directory not found: {target}")
            print("      Available scenarios:")
            for sd in discover_scenarios():
                print(f"        - {sd.name}")
            sys.exit(1)
        scenario_dirs = [target]

    # Run ingestion
    start_time = time.time()
    grand_success = 0
    grand_errors = 0

    # With --reindex: delete ALL target indices ONCE before ingesting anything
    if args.reindex and not args.dry_run:
        reindex_delete_all(scenario_dirs)

    for scenario_dir in scenario_dirs:
        s, e = ingest_scenario(scenario_dir, args.bulk_size, args.dry_run)
        grand_success += s
        grand_errors += e

    elapsed = time.time() - start_time

    # Final summary
    print(f"\n{'=' * 60}")
    print(f"  Ingestion complete")
    print(f"    Scenarios processed: {len(scenario_dirs)}")
    print(f"    Documents indexed:   {grand_success}")
    if grand_errors > 0:
        print(f"    Errors:              {grand_errors}")
    print(f"    Elapsed time:        {elapsed:.1f}s")
    if args.dry_run:
        print(f"    Mode:                DRY RUN (no changes made)")
    print(f"{'=' * 60}\n")

    if grand_errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
