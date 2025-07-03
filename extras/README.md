# Extras - Example Configurations

This folder contains example configurations and additional resources for deploying the detrackify guard server in various environments.

## Available Examples

### docker-entrypoint.sh
Shell script that converts environment variables to command-line arguments for the detrackify guard server. This script is used by the Docker container to handle configuration through environment variables.

#### Features
- Converts all environment variables to appropriate command-line flags
- Handles multiple values for `STRIP_PARAM_PREFIX` (comma-separated or individual variables)
- Validates required parameters (GUARD_SALT)
- Provides clear error messages for invalid configurations

#### Usage
This script is automatically used by the Docker container. It's referenced in the Dockerfile and handles all environment variable configuration.

### nginx.conf
Complete nginx configuration for reverse proxy deployment with:
- Security headers (X-Frame-Options, X-Content-Type-Options, etc.)
- Rate limiting (10 requests/second with burst allowance)
- HTTP and HTTPS support (HTTPS configuration commented out)
- Proper proxy settings for the guard server
- Health check endpoint

#### Usage
```bash
# Copy to your nginx configuration
cp extras/nginx.conf /etc/nginx/nginx.conf

# Or use with docker-compose (already configured)
docker-compose --profile proxy up -d
```

#### Customization
- Update `server_name` to match your domain
- Uncomment and configure SSL certificates for HTTPS
- Adjust rate limiting values as needed
- Modify security headers based on your requirements

## Adding Your Own Examples

Feel free to add your own configuration examples to this folder:
- Apache configurations
- Systemd service files
- Kubernetes manifests
- Monitoring configurations
- etc.

Please include a brief description in this README when adding new examples. 