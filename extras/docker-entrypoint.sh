#!/bin/bash
set -e

# Check if we should use Gunicorn (default: true for production)
USE_GUNICORN=${USE_GUNICORN:-true}

# Determine configuration source: single well-known path inside container
CONFIG_PATH="/app/config.yml"
if [ ! -f "$CONFIG_PATH" ]; then
    CONFIG_PATH=""
fi

# If no config file is available, require GUARD_SALT
if [ -z "$CONFIG_PATH" ] && [ -z "$GUARD_SALT" ]; then
    echo "Error: No configuration file found and GUARD_SALT not provided"
    echo "Mount a unified YAML to /app/config.yml (or set CONFIG_FILE), or set GUARD_SALT."
    exit 1
fi

# Set default bind address for Docker
if [ -z "$GUNICORN_BIND" ] && [ "$USE_GUNICORN" = "true" ]; then
    export GUNICORN_BIND="0.0.0.0:9090"
fi

# Set default listen IP for direct Flask execution
if [ -z "$LISTEN_IP" ] && [ "$USE_GUNICORN" = "false" ]; then
    export LISTEN_IP="0.0.0.0"
fi

# Set default listen port for direct Flask execution
if [ -z "$LISTEN_PORT" ] && [ "$USE_GUNICORN" = "false" ]; then
    export LISTEN_PORT="9090"
fi

# Validate RESOLVE parameter if provided
if [ -n "$RESOLVE" ]; then
    if [ "$RESOLVE" != "head" ] && [ "$RESOLVE" != "get" ]; then
        echo "Error: RESOLVE must be 'head' or 'get', got: $RESOLVE"
        exit 1
    fi
fi

# Execute with Gunicorn (production)
if [ "$USE_GUNICORN" = "true" ]; then
    echo "Starting Detrackify Guard Server with Gunicorn..."
    exec gunicorn --config gunicorn.conf.py wsgi:app
else
    # Execute with direct Flask (development)
    echo "Starting Detrackify Guard Server with Flask (development mode)..."
    
    # Build command line arguments for direct execution
    ARGS=("--listen-ip" "$LISTEN_IP" "--listen-port" "$LISTEN_PORT")
    if [ -n "$CONFIG_PATH" ]; then
        ARGS+=("--config" "$CONFIG_PATH")
    else
        ARGS+=("--salt" "$GUARD_SALT")
    fi
    
    # Optional parameters
    if [ -n "$TEMPLATE_DIR" ]; then
        ARGS+=("--template-dir" "$TEMPLATE_DIR")
    fi
    
    if [ -n "$RESOURCES_DIR" ]; then
        ARGS+=("--resources-dir" "$RESOURCES_DIR")
    fi
    
    if [ -n "$TIMEOUT" ]; then
        ARGS+=("--timeout" "$TIMEOUT")
    fi
    
    if [ "$PRIVACY" = "true" ] || [ "$PRIVACY" = "1" ]; then
        ARGS+=("--privacy")
    fi
    
    if [ -n "$RESOLVE" ]; then
        ARGS+=("--resolve" "$RESOLVE")
    fi
    
    if [ -n "$RESOLVE_CACHE_FILE" ]; then
        ARGS+=("--resolve-cache-file" "$RESOLVE_CACHE_FILE")
    fi
    
    if [ -n "$RESOLVE_CACHE_DAYS" ]; then
        ARGS+=("--resolve-cache-days" "$RESOLVE_CACHE_DAYS")
    fi
    
    if [ -n "$RESOLVE_CACHE_MAX" ]; then
        ARGS+=("--resolve-cache-max" "$RESOLVE_CACHE_MAX")
    fi
    
    if [ -n "$USER_AGENT" ]; then
        ARGS+=("--user-agent" "$USER_AGENT")
    fi
    
    # Handle multiple strip-param-prefix values
    if [ -n "$STRIP_PARAM_PREFIX" ]; then
        # Split by comma or space
        IFS=', ' read -ra PREFIXES <<< "$STRIP_PARAM_PREFIX"
        for prefix in "${PREFIXES[@]}"; do
            if [ -n "$prefix" ]; then
                ARGS+=("--strip-param-prefix" "$prefix")
            fi
        done
    fi
    
    # Handle multiple strip-param-prefix values as separate env vars
    # STRIP_PARAM_PREFIX_1, STRIP_PARAM_PREFIX_2, etc.
    for i in {1..10}; do
        env_var="STRIP_PARAM_PREFIX_$i"
        if [ -n "${!env_var}" ]; then
            ARGS+=("--strip-param-prefix" "${!env_var}")
        fi
    done
    
    exec python detrackify_guard.py "${ARGS[@]}"
fi 