import os
from pathlib import Path

# ponytail: 4-line .env loader beats adding python-dotenv, and living in
# app/config/__init__ means every entrypoint gets it via the import chain.
# Swap for pydantic-settings if config outgrows a handful of keys.
#
# parents[3], not parents[2]. This file is worker/app/config/__init__.py, so
# parents[2] is `worker/` - and the .env this project actually uses is at the
# repo root, beside docker-compose.yml and example.env. The loader pointed one
# directory too shallow and had therefore never loaded anything. Nothing caught
# it because both real callers get their environment elsewhere: containers from
# compose, and a laptop from whatever is exported in the shell. A local
# `python -m app.cli` outside compose got no key at all.
_ENV_FILE = Path(__file__).parents[3] / ".env"
if _ENV_FILE.exists():
    for line in _ENV_FILE.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))
