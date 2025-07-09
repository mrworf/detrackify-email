#!/usr/bin/env python3
"""Gunicorn configuration for Detrackify Guard Server."""

import os
import multiprocessing

# Server socket
bind = os.getenv('GUNICORN_BIND', '0.0.0.0:9090')
backlog = int(os.getenv('GUNICORN_BACKLOG', 2048))

# Worker processes
workers = int(os.getenv('GUNICORN_WORKERS', multiprocessing.cpu_count() * 2 + 1))
worker_class = os.getenv('GUNICORN_WORKER_CLASS', 'sync')
worker_connections = int(os.getenv('GUNICORN_WORKER_CONNECTIONS', 1000))
max_requests = int(os.getenv('GUNICORN_MAX_REQUESTS', 1000))
max_requests_jitter = int(os.getenv('GUNICORN_MAX_REQUESTS_JITTER', 100))

# Timeouts
timeout = int(os.getenv('GUNICORN_TIMEOUT', 30))
keepalive = int(os.getenv('GUNICORN_KEEPALIVE', 2))
graceful_timeout = int(os.getenv('GUNICORN_GRACEFUL_TIMEOUT', 30))

# Logging
accesslog = os.getenv('GUNICORN_ACCESS_LOG', '-')  # '-' means stdout
errorlog = os.getenv('GUNICORN_ERROR_LOG', '-')    # '-' means stderr
loglevel = os.getenv('GUNICORN_LOG_LEVEL', 'info')
access_log_format = os.getenv('GUNICORN_ACCESS_LOG_FORMAT', 
                             '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"')

# Process naming
proc_name = os.getenv('GUNICORN_PROC_NAME', 'detrackify-guard')

# Security
limit_request_line = int(os.getenv('GUNICORN_LIMIT_REQUEST_LINE', 4094))
limit_request_fields = int(os.getenv('GUNICORN_LIMIT_REQUEST_FIELDS', 100))
limit_request_field_size = int(os.getenv('GUNICORN_LIMIT_REQUEST_FIELD_SIZE', 8190))

# Preload application for better performance
preload_app = True

# Restart workers after this many requests, to help prevent memory leaks
max_requests = int(os.getenv('GUNICORN_MAX_REQUESTS', 1000))
max_requests_jitter = int(os.getenv('GUNICORN_MAX_REQUESTS_JITTER', 100))

# Worker timeout
timeout = int(os.getenv('GUNICORN_TIMEOUT', 30))

# Enable auto-restart on code changes (development only)
reload = os.getenv('GUNICORN_RELOAD', 'false').lower() == 'true'

# SSL (if needed)
keyfile = os.getenv('GUNICORN_KEYFILE')
certfile = os.getenv('GUNICORN_CERTFILE')

# User/Group (if running as non-root)
user = os.getenv('GUNICORN_USER')
group = os.getenv('GUNICORN_GROUP')

# Temporary directory
tmp_upload_dir = os.getenv('GUNICORN_TMP_UPLOAD_DIR', None) 