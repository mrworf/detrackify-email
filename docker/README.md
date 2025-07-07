# Docker Deployment

This folder contains all the files needed to deploy Detrackify using Docker.

## Files

- `Dockerfile`: Multi-stage build for the guard server
- `docker-compose.yml`: Complete deployment with optional nginx reverse proxy
- `.dockerignore`: Excludes unnecessary files from the build context

## Quick Start

### Using Docker Compose (Recommended)

1. **Basic deployment:**
   ```bash
   cd docker
   docker-compose up -d
   ```

2. **With nginx reverse proxy:**
   ```bash
   cd docker
   docker-compose --profile proxy up -d
   ```

### Using Docker directly

1. **Build the image:**
   ```bash
   cd docker
   docker build -f Dockerfile -t detrackify-guard ..
   ```

2. **Run the container:**
   ```bash
   docker run -d \
     --name detrackify-guard \
     -p 9090:9090 \
     -e GUARD_SALT=your_secure_salt_here \
     detrackify-guard
   ```

## Container Registry

The official image is available from GitHub Container Registry:

```bash
# Pull the latest image
docker pull ghcr.io/mrworf/detrackify-guard:latest

# Run with the official image
docker run -d \
  --name detrackify-guard \
  -p 9090:9090 \
  -e GUARD_SALT=your_secure_salt_here \
  ghcr.io/mrworf/detrackify-guard:latest
```

## Environment Variables

### Required
- `GUARD_SALT`: Salt for hash validation (minimum 8 characters)

### Optional
- `TIMEOUT`: Seconds before continue button activates (default: 5)
- `PRIVACY`: Enable privacy mode (true/false, default: false)
- `RESOLVE`: Link resolution mode (head/get, default: head)
- `RESOLVE_CACHE_FILE`: Path to cache file (default: /app/cache/resolve_cache.json)
- `RESOLVE_CACHE_DAYS`: Days to keep cache entries (default: 30)
- `RESOLVE_CACHE_MAX`: Maximum cache entries (default: 4096)
- `STRIP_PARAM_PREFIX`: Comma-separated list of parameter prefixes to strip
- `USER_AGENT`: Custom User-Agent for link resolution

## Volumes

### Templates and Resources
Mount custom templates and resources for localization:
```bash
-v ../templates:/app/templates:ro
-v ../resources:/app/resources:ro
```

### Cache Persistence
Persist URL resolution cache across container restarts:
```bash
-v ./cache:/app/cache
```

## Security Features

- **Non-root user**: Container runs as `detrackify` user
- **Health checks**: Built-in health monitoring
- **Read-only mounts**: Templates and resources are mounted read-only
- **Secure defaults**: Privacy mode and timeout settings

## Reverse Proxy Setup

The `docker-compose.yml` includes an optional nginx reverse proxy configuration:

1. **Enable the proxy profile:**
   ```bash
   docker-compose --profile proxy up -d
   ```

2. **SSL certificates** (optional):
   ```bash
   # Create SSL directory
   mkdir ssl
   # Add your certificates to ssl/
   docker-compose --profile proxy up -d
   ```

3. **Custom nginx configuration:**
   Edit `../extras/nginx.conf` to customize the reverse proxy settings.

## Production Deployment

### Security Checklist
- [ ] Change `GUARD_SALT` to a secure random string
- [ ] Enable `PRIVACY=true` in production
- [ ] Use HTTPS with proper SSL certificates
- [ ] Configure firewall rules
- [ ] Set up monitoring and logging
- [ ] Regular security updates

### Scaling
For high-traffic deployments:
- Use a load balancer (nginx, haproxy)
- Consider multiple guard server instances
- Implement proper monitoring and alerting
- Use external cache storage (Redis, etc.)

## Troubleshooting

### Common Issues

1. **Container won't start:**
   - Check if port 9090 is already in use
   - Verify `GUARD_SALT` is set and at least 8 characters

2. **Health check failures:**
   - Check container logs: `docker logs detrackify-guard`
   - Verify the guard server is responding on port 9090

3. **Permission issues:**
   - Ensure cache directory has proper permissions
   - Check that mounted volumes are accessible

### Logs
```bash
# View container logs
docker logs detrackify-guard

# Follow logs in real-time
docker logs -f detrackify-guard

# View logs for specific time period
docker logs --since="2024-01-01T00:00:00" detrackify-guard
```

## Development

### Building for Development
```bash
# Build with development dependencies
docker build -f Dockerfile --target development -t detrackify-guard:dev ..

# Run with volume mounts for live code changes
docker run -d \
  --name detrackify-guard-dev \
  -p 9090:9090 \
  -v ../detrackify_guard.py:/app/detrackify_guard.py \
  -e GUARD_SALT=dev_salt \
  detrackify-guard:dev
```

### Testing
```bash
# Run tests in container
docker run --rm detrackify-guard python -m pytest

# Interactive shell for debugging
docker run -it --rm detrackify-guard /bin/bash
``` 