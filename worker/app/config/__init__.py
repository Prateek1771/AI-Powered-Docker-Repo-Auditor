import os
from pathlib import Path

# ponytail: 4-line .env loader beats adding python-dotenv, and living in
# app/config/__init__ means every entrypoint gets it via the import chain.
# Swap for pydantic-settings if config outgrows a handful of keys.
_ENV_FILE = Path(__file__).parents[2] / ".env"
if _ENV_FILE.exists():
    for line in _ENV_FILE.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))
