#!/usr/bin/env python3
"""The sole Python boundary for reading Guardian configuration as data."""

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
CONFIG_FILE = PROJECT_ROOT / "config" / "guardian.conf"
_SETTING = re.compile(r'^\s*([A-Z_][A-Z0-9_]*)\s*=\s*"?([^"#]*)"?')


def read_config():
    """Read key/value settings without ever sourcing or executing the file."""
    try:
        lines = CONFIG_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    settings = {}
    for line in lines:
        if line.lstrip().startswith("#"):
            continue
        match = _SETTING.match(line)
        if match:
            settings[match.group(1)] = match.group(2).strip()
    return settings


def _expand(value):
    """Expand only the two documented path variables."""
    return (value.replace("${GUARDIAN_ROOT}", str(PROJECT_ROOT))
                 .replace("${HOME}", str(Path.home())))


def config_path(key, default):
    return Path(_expand(read_config().get(key, default)))


def config_words(key):
    return read_config().get(key, "").split()


def workspace_dir():
    return config_path("WORKSPACE_DIR", str(PROJECT_ROOT / "workspace"))
