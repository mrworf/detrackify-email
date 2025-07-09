#!/usr/bin/env python3
"""WSGI entry point for Detrackify Guard Server."""

import os
import sys
from detrackify_guard import GuardServer
from guard.config import GuardConfig

def create_app():
    """Create and configure the Flask application."""
    # Get configuration from environment variables
    config = GuardConfig.from_env()
    config.validate()
    
    # Create the guard server
    server = GuardServer(config)
    
    return server.app

# Create the application instance
# Only create if GUARD_SALT is set to avoid validation errors during import
if os.getenv('GUARD_SALT'):
    app = create_app()
else:
    # Create a placeholder app that will be replaced when create_app() is called
    app = None

if __name__ == '__main__':
    # For development/testing, run directly
    app.run(host='0.0.0.0', port=9090, debug=True) 