#!/bin/bash
set -e

# Production startup script for Detrackify Guard Server
# This script starts the server with Gunicorn for production use

echo "Starting Detrackify Guard Server in production mode..."

# Check if GUARD_SALT is set
if [ -z "$GUARD_SALT" ]; then
    echo "Error: GUARD_SALT environment variable is required"
    echo "Please set it before running this script:"
    echo "export GUARD_SALT='your-secure-salt-here'"
    exit 1
fi

# Set default Gunicorn configuration if not provided
export GUNICORN_BIND=${GUNICORN_BIND:-"0.0.0.0:9090"}
export GUNICORN_WORKERS=${GUNICORN_WORKERS:-4}
export GUNICORN_WORKER_CLASS=${GUNICORN_WORKER_CLASS:-"sync"}
export GUNICORN_TIMEOUT=${GUNICORN_TIMEOUT:-30}
export GUNICORN_LOG_LEVEL=${GUNICORN_LOG_LEVEL:-"info"}

echo "Configuration:"
echo "  Bind: $GUNICORN_BIND"
echo "  Workers: $GUNICORN_WORKERS"
echo "  Worker Class: $GUNICORN_WORKER_CLASS"
echo "  Timeout: $GUNICORN_TIMEOUT"
echo "  Log Level: $GUNICORN_LOG_LEVEL"

# Start Gunicorn
exec gunicorn --config gunicorn.conf.py wsgi:app 