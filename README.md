# Detrackify

[![Build Status](https://github.com/mrworf/detrackify-email/workflows/Build%20and%20Publish%20Docker%20Image/badge.svg)](https://github.com/mrworf/detrackify-email/actions)
[![Docker Image](https://img.shields.io/docker/image-size/ghcr.io/mrworf/detrackify-guard/latest)](https://ghcr.io/mrworf/detrackify-guard)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

**Detrackify** is a comprehensive email security tool that protects users from tracking pixels and phishing attempts. It processes emails to remove tracking mechanisms while preserving email formatting, and provides link protection through an optional guard server.

## What It Does

### Email Processing (`detrackify_email.py`)
- **Tracking Pixel Removal**: Detects and replaces tracking pixels with transparent 1x1 images
- **Link Protection**: Rewrites suspicious links to route through a guard server
- **Phishing Detection**: Automatically guards links when sender display names don't match email domains
- **URL Parameter Stripping**: Removes tracking parameters from image URLs
- **Blocklist/Whitelist Support**: Fine-grained control over allowed and blocked content

### Guard Server (`detrackify_guard.py`)
- **Link Verification**: Validates rewritten links using cryptographic signatures
- **Warning Pages**: Shows user-friendly warnings before allowing access to suspicious links
- **URL Resolution**: Follows redirects to show final destinations
- **Multi-language Support**: Warning pages in 8 languages
- **Privacy Mode**: Optional logging disable for sensitive environments

## Quick Start

### Using Docker (Recommended)

```bash
# Start the guard server
docker-compose up -d

# Process an email
python detrackify_email.py \
  --input email.eml \
  --output cleaned.eml \
  --guardserver http://localhost:9090 \
  --guardsalt your_secure_salt \
  --guardlink mismatch
```

### Using Python Directly

```bash
# Install dependencies
pip install -r requirements.txt

# Start guard server
python detrackify_guard.py --salt your_secure_salt

# Process an email
python detrackify_email.py \
  --input email.eml \
  --output cleaned.eml \
  --guardserver http://localhost:9090 \
  --guardsalt your_secure_salt \
  --guardlink mismatch
```

## Key Features

### 🔒 **Security First**
- Cryptographic link verification prevents tampering
- Non-root Docker containers
- Privacy mode for sensitive environments
- Comprehensive input validation

### 🎯 **Smart Detection**
- Automatic tracking pixel identification
- Phishing detection based on sender/domain mismatch
- Domain alias support for legitimate organizations
- Configurable blocklists and whitelists

### 🌍 **Production Ready**
- Multi-language warning pages (8 languages)
- Docker and Docker Compose support
- Gunicorn production server
- Health checks and monitoring
- Reverse proxy support

## Documentation

### Core Documentation
- **[EMAIL_PROCESSING.md](EMAIL_PROCESSING.md)** - Complete guide to email processing features and configuration
- **[GUARD_SERVER.md](GUARD_SERVER.md)** - Detailed guard server setup and configuration
- **[DOCKER.md](DOCKER.md)** - Docker deployment and container management

### Configuration Examples
- **[examples/](examples/)** - Sample configuration files and usage examples
- **[examples/README.md](examples/README.md)** - Configuration format and examples guide

### Testing and Development
- **[AGENTS.md](AGENTS.md)** - Development guidelines and testing procedures

## Configuration

Detrackify uses a unified YAML configuration format that works with both tools:

```yaml
# Shared configuration
common:
  salt: "your-secret-salt-here"
  domain_aliases_file: domain_aliases.yml
  blacklist_file: blacklist.yml

# Email processor settings
email:
  guard:
    server: http://localhost:9090
    link: mismatch
    phishy: true

# Guard server settings
# Note: top-level `guard_server` config controls the standalone guard service.
# The nested `email.guard` section controls email-side link rewriting behavior.
guard_server:
  listen_ip: "127.0.0.1"
  listen_port: 9090
  timeout: 5
  privacy: false
  resolve: "head"
```

See [examples/](examples/) for complete configuration examples.

Note on blocklist/whitelist files:
- Both lists can be stored in the same YAML file. Only top-level `whitelist` and `blacklist` keys are read; other keys are ignored.
- Missing keys are treated as empty, so one file can serve both tools.

## Testing

Run the test suite to verify everything works:

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
pytest -v
```

Use `detrackify_url.py` to test guard server configurations:

```bash
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://example.com \
  --from user@example.com
```

## Integration

### Email Server Integration
Integrate with your MTA (Postfix, Exim, etc.) to process emails automatically:

```bash
# Example Postfix integration
python detrackify_email.py \
  --guardserver https://guard.yourdomain.com \
  --guardsalt your_shared_salt \
  --guardlink mismatch
```

### Reverse Proxy Setup
Use nginx or Apache as a reverse proxy for production deployments:

```bash
# Start with nginx reverse proxy
docker-compose --profile proxy up -d
```

## Security Considerations

- **Change the default salt**: Always use a secure random salt
- **Enable HTTPS**: Use SSL certificates in production
- **Enable privacy mode**: Disable link logging in sensitive environments
- **Regular updates**: Keep dependencies and container images updated
- **Monitor logs**: Set up proper logging and monitoring

## License

This project is licensed under the GNU General Public License v3.0. See the [COPYING](COPYING) file for the full license text.

## Support

- **Issues**: Report bugs and feature requests on GitHub
- **Documentation**: Check the detailed guides in the documentation files
- **Examples**: Review the [examples/](examples/) directory for configuration samples
- **Testing**: Use the test suite and `detrackify_url.py` for troubleshooting