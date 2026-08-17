# Linux Guardian architecture

```
Browser → app.py (HTTP and templates) → guardian_*.py (domain logic)
                                      → guardian_system.py (fixed Bash gateway)
                                      → linux/*.sh (machine operations)

guardian_config.py → config/guardian.conf
guardian_store.py  → data/guardian.db
```

`app.py` is the composition root: it owns routes, HTTP responses and templates.
It does not parse configuration or build subprocess commands. The fixed module
allow-list lives in `guardian_system.py`, so a URL can never choose a script.

`guardian_config.py` is the only Python parser for `guardian.conf`; it treats
the Bash-compatible configuration as data and never executes it. The domain
modules remain Flask-free and are tested from the terminal.
