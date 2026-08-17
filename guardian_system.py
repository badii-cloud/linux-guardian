#!/usr/bin/env python3
"""Safe, fixed gateway from web code to the Bash monitoring modules."""

import json
import subprocess

from guardian_config import PROJECT_ROOT

LINUX_DIR = PROJECT_ROOT / "linux"
SCRIPT_TIMEOUT_SECONDS = 60
ALLOWED_MODULES = {
    "system": "system.sh", "network": "network.sh", "process": "process.sh",
    "services": "services.sh", "diagnosis": "diagnosis.sh",
}


def error(message):
    return {"status": "error", "message": message}


def run_script(filename, arguments=None):
    """Execute a repository-owned script using argv, never a shell string."""
    try:
        completed = subprocess.run(
            [str(LINUX_DIR / filename), *(arguments or [])], capture_output=True,
            text=True, timeout=SCRIPT_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired:
        return error(f"{filename} took longer than {SCRIPT_TIMEOUT_SECONDS}s and was stopped")
    except OSError as exc:
        return error(f"could not run {filename}: {exc}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        lines = (completed.stderr or completed.stdout or "").strip().splitlines()
        return error(f"{filename} did not return valid JSON: {lines[0] if lines else 'no output at all'}")


def module_data(name):
    """Run an allow-listed monitoring module."""
    return run_script(ALLOWED_MODULES[name])
