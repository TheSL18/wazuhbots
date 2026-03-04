"""
Minimal .env loader — no external dependencies.

Usage:
    from dotenv import load_dotenv
    load_dotenv()  # loads PROJECT_ROOT/.env into os.environ
"""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_dotenv(env_path: Path | None = None) -> int:
    """Load variables from a .env file into os.environ.

    Only sets variables that are NOT already in the environment,
    so real env vars and CLI args always take priority.

    Returns the number of variables loaded.
    """
    if env_path is None:
        env_path = PROJECT_ROOT / ".env"

    if not env_path.exists():
        return 0

    loaded = 0
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        # Skip comments and blank lines
        if not line or line.startswith("#"):
            continue
        # Must have KEY=VALUE
        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip()

        # Strip surrounding quotes from value
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]

        # Don't override existing env vars
        if key not in os.environ:
            os.environ[key] = value
            loaded += 1

    return loaded
