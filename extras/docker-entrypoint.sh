#!/bin/bash
set -e

# For Docker, use 0.0.0.0 so other containers (e.g., nginx) can connect
ARGS=("--listen-ip" "0.0.0.0" "--listen-port" "9090")

# Required parameter
if [ -n "$GUARD_SALT" ]; then
    ARGS+=("--guardsalt" "$GUARD_SALT")
else
    echo "Error: GUARD_SALT environment variable is required"
    exit 1
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
    if [ "$RESOLVE" = "head" ] || [ "$RESOLVE" = "get" ]; then
        ARGS+=("--resolve" "$RESOLVE")
    else
        echo "Error: RESOLVE must be 'head' or 'get', got: $RESOLVE"
        exit 1
    fi
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

# Execute the command
exec python detrackify_guard.py "${ARGS[@]}" 