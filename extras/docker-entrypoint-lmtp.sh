#!/bin/bash
set -e

# Determine configuration source
CONFIG_PATH="/app/config.yml"
if [ ! -f "$CONFIG_PATH" ]; then
    CONFIG_PATH=""
fi

# Default listen address for Docker (bind all interfaces)
LMTP_LISTEN="${LMTP_LISTEN:-0.0.0.0:10024}"

# Downstream is required
if [ -z "$CONFIG_PATH" ] && [ -z "$LMTP_DOWNSTREAM" ]; then
    echo "Error: No configuration file found and LMTP_DOWNSTREAM not provided"
    echo "Mount a YAML config to /app/config.yml, or set LMTP_DOWNSTREAM."
    exit 1
fi

ARGS=("--listen" "$LMTP_LISTEN")

if [ -n "$CONFIG_PATH" ]; then
    ARGS+=("--config" "$CONFIG_PATH")
fi

if [ -n "$LMTP_DOWNSTREAM" ]; then
    ARGS+=("--downstream" "$LMTP_DOWNSTREAM")
fi

if [ -n "$GUARD_SERVER" ]; then
    ARGS+=("--guardserver" "$GUARD_SERVER")
fi

if [ -n "$GUARD_SALT" ]; then
    ARGS+=("--guardsalt" "$GUARD_SALT")
fi

if [ -n "$GUARD_LINK" ]; then
    ARGS+=("--guardlink" "$GUARD_LINK")
fi

if [ "$GUARD_CAPTURE_TO" = "true" ] || [ "$GUARD_CAPTURE_TO" = "1" ]; then
    ARGS+=("--guardcaptureto")
fi

if [ "$GUARD_PHISHY" = "true" ] || [ "$GUARD_PHISHY" = "1" ]; then
    ARGS+=("--guardphishy")
fi

if [ -n "$GUARD_WHITELIST_FILE" ]; then
    ARGS+=("--guard-whitelist-file" "$GUARD_WHITELIST_FILE")
fi

if [ -n "$DOMAIN_ALIASES_FILE" ]; then
    ARGS+=("--domain-aliases-file" "$DOMAIN_ALIASES_FILE")
fi

if [ -n "$BLACKLIST_FILE" ]; then
    ARGS+=("--blacklist-file" "$BLACKLIST_FILE")
fi

if [ -n "$WHITELIST_FILE" ]; then
    ARGS+=("--whitelist-file" "$WHITELIST_FILE")
fi

if [ -n "$CACHE_FILE" ]; then
    ARGS+=("--cache-file" "$CACHE_FILE")
fi

# Handle multiple strip-param-prefix values (comma-separated)
if [ -n "$STRIP_PARAM_PREFIX" ]; then
    IFS=', ' read -ra PREFIXES <<< "$STRIP_PARAM_PREFIX"
    for prefix in "${PREFIXES[@]}"; do
        if [ -n "$prefix" ]; then
            ARGS+=("--strip-param-prefix" "$prefix")
        fi
    done
fi

if [ -n "$LOGFILE" ]; then
    ARGS+=("--logfile" "$LOGFILE")
fi

if [ "$VERBOSE" = "true" ] || [ "$VERBOSE" = "1" ]; then
    ARGS+=("--verbose")
fi

if [ "$DEBUG" = "true" ] || [ "$DEBUG" = "1" ]; then
    ARGS+=("--debug")
fi

echo "Starting Detrackify LMTP proxy (listen: $LMTP_LISTEN)..."
exec python detrackify_lmtp.py "${ARGS[@]}"
