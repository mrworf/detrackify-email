#!/usr/bin/env python3
"""WSGI entry point for Detrackify Guard Server."""

import os
import sys
from detrackify_guard import GuardServer
from guard.config import GuardConfig

def _load_config_from_env_or_file() -> GuardConfig:
    """Load configuration from CONFIG_FILE (or /app/config.yml) if present, else from env."""
    config_path = os.getenv('CONFIG_FILE') or '/app/config.yml'
    try:
        if os.path.isfile(config_path):
            cfg = GuardConfig.from_yaml(config_path)
        else:
            cfg = GuardConfig.from_env()
        cfg.validate()
        return cfg
    except Exception:
        # Re-raise to surface errors during app creation
        raise


def create_app():
    """Create and configure the Flask application."""
    config = _load_config_from_env_or_file()
    server = GuardServer(config)
    return server.app

# Create the application instance
# Only create at import if either a config file exists or GUARD_SALT is set
_default_config_path = os.getenv('CONFIG_FILE') or '/app/config.yml'
if os.getenv('GUARD_SALT') or os.path.isfile(_default_config_path):
    app = create_app()
else:
    app = None

if __name__ == '__main__':
    # For development/testing, run directly
    app.run(host='0.0.0.0', port=9090, debug=True) 