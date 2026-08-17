#!/usr/bin/env python3
"""Read-only readiness checks for a safe Linux Guardian demonstration."""

import os

import guardian_actions as actions
import guardian_incidents as incidents
import guardian_store as store
from guardian_config import CONFIG_FILE, config_words, read_config, workspace_dir


def _check(name, ok, detail, warning=False):
    return {"name": name, "result": "PASS" if ok else ("WARNING" if warning else "FAIL"),
            "detail": detail}


def report():
    """Return explainable checks; this function never starts or changes anything."""
    checks = []
    config = read_config()
    required = ("MONITORED_SERVICES", "HEALABLE_SERVICES", "HISTORY_DB", "WORKSPACE_DIR")
    missing = [key for key in required if not config.get(key)]
    checks.append(_check("Policy configuration", not missing,
                         "guardian.conf is readable" if not missing else
                         "missing: " + ", ".join(missing)))

    action_problems = actions.check_registry()
    checks.append(_check("Action safety registry", not action_problems,
                         f"{len(actions.ACTIONS)} approved actions" if not action_problems else
                         action_problems[0]))

    incident_problems = incidents.check_registry()
    checks.append(_check("Incident definitions", not incident_problems,
                         f"{len(incidents.TYPES)} known incident types" if not incident_problems else
                         incident_problems[0]))

    workspace = workspace_dir()
    usable_workspace = workspace.is_dir() and os.access(workspace, os.R_OK | os.W_OK | os.X_OK)
    checks.append(_check("Safe workspace", usable_workspace,
                         str(workspace) if usable_workspace else
                         f"not usable: {workspace}"))

    monitored = config_words("MONITORED_SERVICES")
    healable = config_words("HEALABLE_SERVICES")
    outside = sorted(set(healable) - set(monitored))
    checks.append(_check("Healing policy", not outside,
                         ("Guardian may only propose: " + ", ".join(healable or ["nothing"]))
                         if not outside else "healable service is not monitored: " + ", ".join(outside)))

    try:
        connection = store.connect()
        version = store.schema_version(connection)
        connection.close()
        checks.append(_check("History database", True, f"ready (schema version {version})"))
    except store.StoreError as error:
        checks.append(_check("History database", False, str(error), warning=True))

    passed = sum(check["result"] == "PASS" for check in checks)
    return {"status": "ok", "checks": checks, "passed": passed, "total": len(checks),
            "config_file": str(CONFIG_FILE)}
