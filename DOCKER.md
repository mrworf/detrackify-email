# Docker Deployment Guide

This guide explains how to deploy and run the Detrackify Guard Server using Docker. The guard server provides link protection and warning pages for suspicious links in emails.

## Quick Start

### Using Docker Compose (Recommended)

The easiest way to get started is using the provided `docker-compose.yml`:

```bash
# Start the guard server
docker-compose up -d

# Check if it's running
docker-compose ps

# View logs
docker-compose logs -f detrackify-guard
```

### Using Docker directly

```bash
# Pull the official image
docker pull ghcr.io/mrworf/detrackify-guard:latest

# Run with unified configuration file mounted (preferred). Entry point auto-detects /app/config.yml
docker run -d \
  --name detrackify-guard \
  -p 9090:9090 \
  -v $(pwd)/examples/config_guard_server.yml:/app/config.yml:ro \
  ghcr.io/mrworf/detrackify-guard:latest

# Or run with basic inline configuration via env (fallback)
docker run -d \
  --name detrackify-guard \
  -p 9090:9090 \
  -e GUARD_SALT=your_secure_salt_here \
  ghcr.io/mrworf/detrackify-guard:latest
```

## Container Optimization

### Requirements Management

The Docker build automatically excludes development tools during the build process:

- Uses the standard `requirements.txt` file
- Automatically excludes `pytest` and `pylint` using pip constraints


## Container Registry

- **Registry**: `ghcr.io/mrworf/detrackify-guard`
- **Latest**: `ghcr.io/mrworf/detrackify-guard:latest`
- **Specific versions**: `ghcr.io/mrworf/detrackify-guard:v1.0.0`
- **Development**: `ghcr.io/mrworf/detrackify-guard:dev`

## Configuration

### Environment Variables

#### Required
- `GUARD_SALT`: Salt for hash validation (minimum 8 characters, keep secret) — only required if no config file is found in the container

#### Optional
- `TIMEOUT`: Seconds before continue button activates (default: 5)
- `PRIVACY`: Enable privacy mode - disable logging of visited links (true/false, default: false)
- `RESOLVE`: Link resolution mode (head/get, default: None - disabled)
- `RESOLVE_CACHE_FILE`: Path to cache file (default: /app/cache/resolve_cache.json)
- `RESOLVE_CACHE_DAYS`: Days to keep cache entries (default: 30)
- `RESOLVE_CACHE_MAX`: Maximum cache entries (default: 4096)
- `STRIP_PARAM_PREFIX`: Comma-separated list of parameter prefixes to strip (e.g., "utm_source,utm_medium,fbclid")
- `USER_AGENT`: Custom User-Agent for link resolution requests
- `TEMPLATE_DIR`: Directory containing templates (default: /app/templates)
- `RESOURCES_DIR`: Directory containing additional resources (default: /app/resources)
- `LISTEN_IP`: IP address to bind to (default: 127.0.0.1)
- `LISTEN_PORT`: Port to listen on (default: 9090)
- `FORCE_LANGUAGE`: Force specific language template (e.g., de, es, fr, zh, ar)
- `DOMAIN_ALIASES_FILE`: Path to domain aliases YAML file (default: domain_aliases.yml)
- `BLACKLIST_FILE`: Path to blacklist YAML file (default: blacklist.yml)
- `DENY_ON_WARNINGS`: Comma-separated list of warnings to deny access for (e.g., "ssl_certificate,connection_error")

#### Gunicorn Configuration (Production)
- `USE_GUNICORN`: Use Gunicorn instead of Flask development server (true/false, default: true)
- `GUNICORN_WORKERS`: Number of worker processes (default: 4)
- `GUNICORN_WORKER_CLASS`: Worker class - sync, gevent, eventlet (default: sync)
- `GUNICORN_TIMEOUT`: Worker timeout in seconds (default: 30)
- `GUNICORN_KEEPALIVE`: Keep-alive timeout (default: 2)
- `GUNICORN_MAX_REQUESTS`: Max requests per worker before restart (default: 1000)
- `GUNICORN_MAX_REQUESTS_JITTER`: Jitter for max requests (default: 100)
- `GUNICORN_GRACEFUL_TIMEOUT`: Graceful shutdown timeout (default: 30)
- `GUNICORN_LOG_LEVEL`: Log level - debug, info, warning, error (default: info)
- `GUNICORN_BIND`: Bind address and port (default: 0.0.0.0:9090)

### Example Configuration

```bash
docker run -d \
  --name detrackify-guard \
  -p 9090:9090 \
  -e GUARD_SALT=my-super-secret-salt-123 \
  -e TIMEOUT=10 \
  -e PRIVACY=true \
  -e RESOLVE=head \
  -e STRIP_PARAM_PREFIX=utm_source,utm_medium,utm_campaign,fbclid,gclid \
  -e USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  ghcr.io/mrworf/detrackify-guard:latest
```

## Docker Compose Examples

### Basic Setup

The included `docker-compose.yml` provides a complete setup:

```yaml
version: '3.8'

services:
  detrackify-guard:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: detrackify-guard
    ports:
      - "9090:9090"
    # Mount unified configuration file (preferred). Auto-detected by entry point.
    volumes:
      - ./examples/config_guard_server.yml:/app/config.yml:ro
      - ./templates:/app/templates:ro
      - ./resources:/app/resources:ro
      - ./cache:/app/cache
    environment:
      # Fallback to inline variables if you do not mount a config
      # - GUARD_SALT=changeme123  # Change this!
      # - TIMEOUT=5
      # - PRIVACY=false
      # - RESOLVE=head
      # - STRIP_PARAM_PREFIX=utm_source,utm_medium,utm_campaign
    restart: unless-stopped
```

### Production Setup with Gunicorn

For production deployments, the container uses Gunicorn by default with optimized settings:

```yaml
version: '3.8'

services:
  detrackify-guard:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: detrackify-guard
    ports:
      - "9090:9090"
    volumes:
      - ./examples/config_guard_server.yml:/app/config.yml:ro
      - ./templates:/app/templates:ro
      - ./resources:/app/resources:ro
      - ./cache:/app/cache
    environment:
      # No CONFIG_FILE required; entry point auto-detects /app/config.yml
      
      # Server mode (Gunicorn for production)
      - USE_GUNICORN=true
      
      # Gunicorn configuration
      - GUNICORN_WORKERS=8
      - GUNICORN_WORKER_CLASS=sync
      - GUNICORN_TIMEOUT=60
      - GUNICORN_MAX_REQUESTS=2000
      - GUNICORN_LOG_LEVEL=warning
      
      # Application configuration (only needed if not using CONFIG_FILE)
      # - TIMEOUT=5
      # - PRIVACY=true
      # - RESOLVE=head
      # - STRIP_PARAM_PREFIX=utm_source,utm_medium,utm_campaign,fbclid,gclid
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import requests; requests.get('http://localhost:9090/guard/health', timeout=5)"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

### With Nginx Reverse Proxy

For production deployments, use the included nginx configuration:

```bash
# Start with nginx reverse proxy
docker-compose --profile proxy up -d
```

This will:
- Start the guard server on port 9090 (internal)
- Start nginx on ports 80 and 443 (external)
- Configure SSL termination (if certificates are provided)
- Handle load balancing and security headers

### Custom Configuration

Create a custom `docker-compose.override.yml` for your specific needs:

```yaml
version: '3.8'

services:
  detrackify-guard:
    environment:
      - GUARD_SALT=${GUARD_SALT}
      - PRIVACY=true
      - TIMEOUT=10
    volumes:
      - ./custom-templates:/app/templates:ro
      - ./custom-resources:/app/resources:ro
      - ./cache:/app/cache
```

## Volumes and Data Persistence

### Templates and Resources
Mount custom templates and resources for localization and branding:

```bash
-v ./templates:/app/templates:ro
-v ./resources:/app/resources:ro
```

### Cache Persistence
Persist URL resolution cache across container restarts:

```bash
-v ./cache:/app/cache
```

### Configuration Files
Mount configuration files for advanced features:

```bash
-v ./config:/app/config:ro
```

## Security Features

### Container Security
- **Non-root user**: Container runs as `detrackify` user
- **Health checks**: Built-in health monitoring at `/guard/health`
- **Read-only mounts**: Templates and resources are mounted read-only
- **Secure defaults**: Privacy mode and timeout settings

### Network Security
- **Internal communication**: Guard server listens on 0.0.0.0 for container networking
- **Reverse proxy**: Optional nginx with SSL termination
- **Firewall ready**: Expose only necessary ports

### Production Security Checklist
- [ ] Change `GUARD_SALT` to a secure random string (32+ characters)
- [ ] Enable `PRIVACY=true` in production
- [ ] Use HTTPS with proper SSL certificates
- [ ] Configure firewall rules to restrict access
- [ ] Set up monitoring and logging
- [ ] Regular security updates and image pulls
- [ ] Use secrets management for sensitive data

## Monitoring and Health Checks

### Health Check Endpoint
The guard server provides a health check endpoint:

```bash
# Check health
curl http://localhost:9090/guard/health

# Expected response
{"status": "healthy", "timestamp": 1640995200.0}
```

### Docker Health Check
The container includes built-in health monitoring:

```bash
# Check container health
docker ps
docker inspect detrackify-guard | grep Health -A 10
```

### Logging
```bash
# View container logs
docker logs detrackify-guard

# Follow logs in real-time
docker logs -f detrackify-guard

# View logs for specific time period
docker logs --since="2024-01-01T00:00:00" detrackify-guard
```

## Advanced Configuration

### Custom Templates
Mount custom warning page templates:

```bash
# Create custom templates directory
mkdir -p custom-templates

# Copy and modify templates
cp templates/guard_warning.html custom-templates/

# Mount in container
-v ./custom-templates:/app/templates:ro
```

### Domain Aliases
Configure domain aliases for trusted domains:

```yaml
# domain_aliases.yml
aliases:
  instacart.com:
    - instacartemail.com
    - email.instacart.com
  amazon.com:
    - amazon-communications.com
```

Mount the file:
```bash
-v ./domain_aliases.yml:/app/domain_aliases.yml:ro
```

### Blocklist Configuration
Configure URL and sender blocking:

```yaml
# blacklist.yml
whitelist:
  - 'https://trusted.example.com/logo.png'
  - 'https://cdn.example.org/.*'

blacklist:
  - sender: '^spam@malicious\\.com$'
  - url: '^https://malicious\\.com/.*'
  - url: '^https://.*\\.phishing\\.net/.*'
```

Mount the file:
```bash
-v ./blacklist.yml:/app/blacklist.yml:ro
```

## Scaling and Performance

### High Traffic Deployments
For high-traffic deployments:

1. **Load Balancer**: Use nginx, haproxy, or cloud load balancer
2. **Multiple Instances**: Run multiple guard server containers
3. **External Cache**: Use Redis or database for URL resolution cache
4. **Monitoring**: Implement proper monitoring and alerting

### Example Load Balancer Setup
```yaml
version: '3.8'

services:
  detrackify-guard-1:
    image: ghcr.io/mrworf/detrackify-guard:latest
    environment:
      - GUARD_SALT=${GUARD_SALT}
    expose:
      - "9090"

  detrackify-guard-2:
    image: ghcr.io/mrworf/detrackify-guard:latest
    environment:
      - GUARD_SALT=${GUARD_SALT}
    expose:
      - "9090"

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - detrackify-guard-1
      - detrackify-guard-2
```

## Development

### Building from Source
```bash
# Build local image
docker build -t detrackify-guard:local .

# Run with volume mounts for development
docker run -d \
  --name detrackify-guard-dev \
  -p 9090:9090 \
  -v ./detrackify_guard.py:/app/detrackify_guard.py \
  -v ./guard:/app/guard \
  -e GUARD_SALT=dev_salt \
  detrackify-guard:local
```

### Testing
```bash
# Run tests in container
docker run --rm detrackify-guard:local python -m pytest

# Interactive shell for debugging
docker run -it --rm detrackify-guard:local /bin/bash
```

### Testing with detrackify_url.py
The `detrackify_url.py` tool can be used to test the guard server:

```bash
# Generate a test URL for the running guard server
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://example.com \
  --from user@example.com \
  --verbose

# Test different scenarios
# Normal link
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://trusted.example.com \
  --from admin@example.com

# Domain mismatch
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://suspicious.com \
  --from admin@example.com

# Blocked URL
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://malicious.com \
  --from spam@evil.com \
  --block blacklisted
```

Copy the generated URLs and paste them in your browser to test the guard server's warning pages and behavior.

## Integration with Email Processing

To integrate with `detrackify_email.py`, configure the guard server URL:

```yaml
# In your detrackify_email.py configuration
options:
  guard:
    server: https://guard.yourdomain.com
    salt: your_shared_salt_here
    link: mismatch
    capture_to: false
```

The guard server will handle link protection and warning pages for suspicious links detected in emails.

## LMTP Proxy Container

The LMTP proxy container runs `detrackify_lmtp.py` as a standalone LMTP service for transparent email processing between your MTA and delivery agent.

### Quick Start

```bash
# Start the LMTP proxy
docker-compose up -d detrackify-lmtp

# Or build and run directly
docker build -f Dockerfile.lmtp -t detrackify-lmtp .
docker run -d \
  --name detrackify-lmtp \
  -p 10024:10024 \
  -v $(pwd)/examples/config_lmtp.yml:/app/config.yml:ro \
  -e LMTP_DOWNSTREAM=dovecot:24 \
  detrackify-lmtp
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LMTP_LISTEN` | Listen address (`host:port` or socket path) | `0.0.0.0:10024` |
| `LMTP_DOWNSTREAM` | Downstream LMTP target (required if no config file) | None |
| `GUARD_SERVER` | Guard server URL | None |
| `GUARD_SALT` | Salt for guarded links | None |
| `GUARD_LINK` | Guard link mode: `off`, `mismatch`, `always` | `off` |
| `GUARD_CAPTURE_TO` | Capture recipient in guarded links (`true`/`false`) | `false` |
| `GUARD_PHISHY` | Enable phishing detection (`true`/`false`) | `false` |
| `GUARD_WHITELIST_FILE` | Path to guard whitelist YAML file | None |
| `DOMAIN_ALIASES_FILE` | Path to domain aliases YAML file | None |
| `BLACKLIST_FILE` | Path to blacklist YAML file | None |
| `WHITELIST_FILE` | Path to whitelist YAML file | None |
| `CACHE_FILE` | Path to cache YAML file | None |
| `STRIP_PARAM_PREFIX` | Comma-separated list of parameter prefixes to strip | None |
| `VERBOSE` | Enable verbose logging (`true`/`false`) | `false` |
| `DEBUG` | Enable debug logging (`true`/`false`) | `false` |
| `LOGFILE` | Path to log file | None |

### Docker Compose

The `docker-compose.yml` includes a `detrackify-lmtp` service:

```yaml
detrackify-lmtp:
  build:
    context: .
    dockerfile: Dockerfile.lmtp
  container_name: detrackify-lmtp
  ports:
    - "10024:10024"
  volumes:
    - ./examples/config_lmtp.yml:/app/config.yml:ro
  environment:
    - LMTP_DOWNSTREAM=dovecot:24
  restart: unless-stopped
```

### Full Stack Deployment

Run both the LMTP proxy and guard server together:

```bash
docker-compose up -d detrackify-lmtp detrackify-guard
```

Mail flow:
```
Postfix --LMTP:10024--> [detrackify-lmtp] --LMTP--> Dovecot
                              |
                              +--> [detrackify-guard :9090] (link warnings)
```

Configure the LMTP proxy to use the guard server by setting `GUARD_SERVER=http://detrackify-guard:9090` or via the config file.

### Health Check

The container includes a TCP socket health check on the LMTP port:

```bash
docker inspect detrackify-lmtp | grep Health -A 10
```

## Support

For issues and questions:
- Check the [main README](../README.md) for general information
- Review [GUARD_SERVER.md](../GUARD_SERVER.md) for detailed server configuration
- Check the [examples](../examples/) directory for configuration samples
- Open an issue on GitHub for bugs or feature requests 