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

# Run with basic configuration
docker run -d \
  --name detrackify-guard \
  -p 9090:9090 \
  -e GUARD_SALT=your_secure_salt_here \
  ghcr.io/mrworf/detrackify-guard:latest
```

## Container Registry

The official Docker image is available from GitHub Container Registry:

- **Registry**: `ghcr.io/mrworf/detrackify-guard`
- **Latest**: `ghcr.io/mrworf/detrackify-guard:latest`
- **Specific versions**: `ghcr.io/mrworf/detrackify-guard:v1.0.0`
- **Development**: `ghcr.io/mrworf/detrackify-guard:dev`

## Configuration

### Environment Variables

#### Required
- `GUARD_SALT`: Salt for hash validation (minimum 8 characters, keep secret)

#### Optional
- `TIMEOUT`: Seconds before continue button activates (default: 5)
- `PRIVACY`: Enable privacy mode - disable logging of visited links (true/false, default: false)
- `RESOLVE`: Link resolution mode (head/get, default: head)
- `RESOLVE_CACHE_FILE`: Path to cache file (default: /app/cache/resolve_cache.json)
- `RESOLVE_CACHE_DAYS`: Days to keep cache entries (default: 30)
- `RESOLVE_CACHE_MAX`: Maximum cache entries (default: 4096)
- `STRIP_PARAM_PREFIX`: Comma-separated list of parameter prefixes to strip (e.g., "utm_source,utm_medium,fbclid")
- `USER_AGENT`: Custom User-Agent for link resolution requests
- `TEMPLATE_DIR`: Directory containing templates (default: /app/templates)
- `RESOURCES_DIR`: Directory containing additional resources (default: /app/resources)

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
    environment:
      - GUARD_SALT=changeme123  # Change this!
      - TIMEOUT=5
      - PRIVACY=false
      - RESOLVE=head
      - STRIP_PARAM_PREFIX=utm_source,utm_medium,utm_campaign
    volumes:
      - ./templates:/app/templates:ro
      - ./resources:/app/resources:ro
      - ./cache:/app/cache
    restart: unless-stopped
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

## Troubleshooting

### Common Issues

#### Container Won't Start
```bash
# Check if port is already in use
netstat -tulpn | grep 9090

# Verify environment variables
docker run --rm -e GUARD_SALT=test ghcr.io/mrworf/detrackify-guard:latest
```

#### Health Check Failures
```bash
# Check container logs
docker logs detrackify-guard

# Test health endpoint directly
curl -f http://localhost:9090/guard/health
```

#### Permission Issues
```bash
# Ensure cache directory has proper permissions
mkdir -p cache
chmod 755 cache

# Check mounted volume permissions
docker exec detrackify-guard ls -la /app/cache
```

### Debug Mode
Enable debug mode for troubleshooting:

```bash
docker run -d \
  --name detrackify-guard-debug \
  -p 9090:9090 \
  -e GUARD_SALT=debug_salt \
  -e DEBUG=true \
  ghcr.io/mrworf/detrackify-guard:latest
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
# blocklist.yml
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

## Support

For issues and questions:
- Check the [main README](../README.md) for general information
- Review [GUARD_SERVER.md](../GUARD_SERVER.md) for detailed server configuration
- Check the [examples](../examples/) directory for configuration samples
- Open an issue on GitHub for bugs or feature requests 