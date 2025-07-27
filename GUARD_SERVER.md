# Guard server and link rewriting

Many phishing attempts disguise a malicious link behind seemingly innocent text. `detrackify_email.py` can rewrite such links so that the user is warned before the browser follows them. The guard server verifies the link using a shared secret, serves a warning page and then redirects without storing any state on the server. Logging of the clicked link can be disabled for privacy.
When guardlink runs in `mismatch` mode the domain of each link is compared with the sender's domain. Links from a different domain or subdomain are considered suspicious and replaced.

## User protection

By default, the tool does not perform any resolve on the URLs provided and will simply show the user that the domain of the email sender doesn't match the domain of the link. This is to avoid triggering any kind of tracking mechanism. However, it's the opinion of the author that the use of `--resolve` is preferable.

Here's why...

While using `--resolve` means the server will make HTTP/HTTPS requests on behalf of users, potentially triggering tracking mechanisms, this approach provides several important benefits:

1. Once resolved, no more tracking will be done since result is cached on server.
2. IP of "user" will always be the server.
3. Device fingerprinting will not match.
4. Cookies aren't available and does not persist on server, all requests are essentially "incognito".
5. No javascript or other malicious payloads are ever sent to user unless they click after being warned.

It also means better protection from phishing attempts that are hiding behind URL redirects.

### Privacy

Nothing is stored on the server. Normally each redirect is logged along with how long the user waited before continuing. When `--privacy` is enabled these informational messages are suppressed, but warnings and errors are still logged.

## Enabling guarded links

Set the following options either on the command line or in your `detrackify_email.py` configuration file:

```yaml
salt: changeme123
email:
  guard:
    server: https://guard.example.com
    link: mismatch
    capture_to: false
```

`email.guard.server` is the public URL to the guard server including the scheme. `salt` must be at least eight characters and should be kept secret. `email.guard.link` controls which links are rewritten: `mismatch` only rewrites links that do not match the sender domain, `always` rewrites all links and `off` disables the feature.

When a link is rewritten, a JSON payload containing the original URL, its display text and the sender domain is base64 encoded.  A SHA256 hash is then calculated from that encoded payload plus the configured salt and both values are appended to the guard server address.  This allows the server to verify that the payload has not been tampered with when a user clicks the link.  The processed email will also include the headers `X-Detrackify-Guarded-Links` and `X-Detrackify-Guard-Mode` when guardlink is active.
If `guard.capture_to` is enabled, the recipient address is included in the JSON so the server can log which user clicked the link&mdash;or at least which recipient the link was originally meant for (forwards and quoted mail may not reflect the actual clicker).

## Running the guard server

### Using Docker (Recommended)

For production deployments, we recommend using Docker. See [DOCKER.md](DOCKER.md) for complete Docker deployment instructions.

### Using Gunicorn (Production)

For production deployments outside of Docker, use Gunicorn for better performance and reliability:

#### Quick Start

```bash
# Set required environment variable
export GUARD_SALT="your-secure-salt-here"

# Start with default settings
./start_production.sh

# Or start manually with custom settings
export GUNICORN_WORKERS=4
export GUNICORN_TIMEOUT=30
gunicorn --config gunicorn.conf.py wsgi:app
```

#### Windows

```cmd
# Set required environment variable
set GUARD_SALT=your-secure-salt-here

# Start with default settings
start_production.bat

# Or start manually
set GUNICORN_WORKERS=4
set GUNICORN_TIMEOUT=30
gunicorn --config gunicorn.conf.py wsgi:app
```

> NOTE! Windows is untested.

#### Gunicorn Configuration

The `gunicorn.conf.py` file provides production-optimized settings. You can customize it through environment variables:

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `GUNICORN_WORKERS` | `(CPU cores × 2) + 1` | Number of worker processes |
| `GUNICORN_WORKER_CLASS` | `sync` | Worker class (sync, gevent, eventlet) |
| `GUNICORN_TIMEOUT` | `30` | Worker timeout in seconds |
| `GUNICORN_KEEPALIVE` | `2` | Keep-alive timeout |
| `GUNICORN_MAX_REQUESTS` | `1000` | Max requests per worker before restart |
| `GUNICORN_BIND` | `0.0.0.0:9090` | Bind address and port |
| `GUNICORN_LOG_LEVEL` | `info` | Log level (debug, info, warning, error) |

#### Example Production Configuration

```bash
export GUARD_SALT="your-secure-salt-here"
export GUNICORN_WORKERS=8
export GUNICORN_WORKER_CLASS="gevent"
export GUNICORN_TIMEOUT=60
export GUNICORN_MAX_REQUESTS=2000
export GUNICORN_LOG_LEVEL="warning"
export GUNICORN_BIND="0.0.0.0:9090"

gunicorn --config gunicorn.conf.py wsgi:app
```

### Using Python directly (Development)

Start the server with at least the salt option:

```bash
python3 detrackify_guard.py --salt changeme123
```

### Using YAML Configuration File

Instead of specifying all options on the command line, you can use a YAML configuration file:

```bash
python3 detrackify_guard.py --config config.yml
```

The configuration file supports all the same options as command line arguments, except for `debug` and `force_language`, which are command line only. Command line arguments will override values from the configuration file.

#### Configuration File Format

Detrackify uses a unified configuration format that can be shared between the email processor and guard server:

```yaml
# Unified Detrackify Configuration
# This file can be used by both detrackify_email.py and detrackify_guard.py

# Shared configuration (used by both email and guard)
salt: "test123456789"
domain_aliases_file: domain_aliases.yml
blacklist_file: blacklist.yml

# Email processor configuration
email:
  guard:
    server: http://localhost:9090
    link: mismatch

# Guard server configuration
guard:
  # Server settings
  listen_ip: "127.0.0.1"
  listen_port: 9090
  
  # Security and behavior settings
  timeout: 5
  privacy: false
  
  # Link resolution settings
  resolve: "head"
  resolve_cache_file: "cache/resolve_cache.json"
  resolve_cache_days: 30
  resolve_cache_max: 4096
  
  # URL parameter stripping
  strip_param_prefix:
    - "utm_"
    - "fbclid"
    - "gclid"
  
  # User agent for link resolution requests
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  
  # Warning blocking - deny access for specific warning types
  deny_on_warnings:
    - "ssl_certificate"
    - "connection_error"
```

When using a unified configuration file, the guard server will:
1. Load shared settings from the root level (including `salt`)
2. Load guard-specific settings from the `guard` section
3. Apply command line arguments with precedence over settings file

The `salt` option is shared between both applications and is used for hash validation. 

See the main README for more details on configuration format.

### Command Line Parameters

Optional parameters:

* `--config`, `-c` Path to YAML configuration file
* `--listen-ip` IP to bind to (default `127.0.0.1`)
* `--listen-port` Port to listen on (default `9090`)
* `--salt` Guard salt for hash validation (required if not in config file)
* `--template-dir` Directory containing templates (default `templates`)
* `--resources-dir` Directory containing additional resources (images only)
* `--timeout` Seconds to wait before the continue button activates (default `5`)
* `--privacy` Disable logging of visited links
* `--resolve` Resolve the final URL before showing the continue button (choices: `head`, `get`, default: `None` - disabled)
* `--resolve-cache-file` File used to store resolved URLs
* `--resolve-cache-days` Days to keep cached items (default `30`)
* `--resolve-cache-max` Maximum number of cached items (default `4096`)
* `--user-agent` User-Agent string for link resolution requests (default: Chrome browser)
* `--debug` Enable debug mode with template auto-reload
* `--force-language` Force serving a specific language template (e.g., da, de, es, fr, zh, ar)
* `--strip-param-prefix` Remove tracking parameters starting with PREFIX and everything after (may be used multiple times)
* `--deny-on-warnings` Deny access for specific warnings instead of showing warning modals (may be used multiple times)

The `--strip-param-prefix` option is useful for removing marketing parameters such as `utm_source`. The first matching parameter and all subsequent parameters are dropped from the URL before displaying it or performing the redirect.
Removing parameters may break links if any subsequent parameter is required by the destination site.

The `--deny-on-warnings` option allows you to completely block access to URLs that trigger specific warning types during resolution, instead of showing a warning modal. When a denied warning is detected, the user sees a blocked page with an explanation but no continue button. This option can be specified multiple times to deny different warning types.

#### Available Warning Types

The following warning types can be used with `--deny-on-warnings`:

- **`ssl_certificate`** - SSL certificate verification failed, expired, or unverifiable certificates
- **`connection_error`** - Connection errors including DNS failures and network connectivity issues  
- **`connection_timeout`** - Connection timeout when server takes too long to respond
- **`too_many_redirects`** - Too many redirects detected (potential redirect chains)
- **`request_error`** - Other HTTP request-related errors
- **`unexpected_error`** - Unexpected errors during URL resolution

#### Usage Examples

Command line (multiple warnings):
```bash
python3 detrackify_guard.py --salt mysalt --deny-on-warnings ssl_certificate --deny-on-warnings connection_error
```

YAML configuration:
```yaml
deny_on_warnings:
  - "ssl_certificate"
  - "connection_error" 
  - "too_many_redirects"
```

Environment variable:
```bash
export DENY_ON_WARNINGS="ssl_certificate,connection_error,too_many_redirects"
```

The server verifies the provided hash, shows a warning page and then redirects the
user without sending a referrer header. It automatically chooses a warning page
template based on the browser's `Accept-Language` header. Templates for German,
Spanish, French, Chinese and Arabic are included; if no matching template exists
the English version is used. These translations were generated automatically so
minor errors may exist.

## Warning Types and Error Handling

When URL resolution is enabled, the guard server can encounter various issues while trying to verify the final destination of links. The system provides user-friendly warnings for different types of problems:

### SSL Certificate Issues
- **Trigger**: Invalid, expired, or unverifiable SSL certificates
- **Warning**: "⚠️ Security Certificate Warning"
- **User Action**: Proceed with caution, consider contacting website owner

### Connection Problems
- **Trigger**: Network connectivity issues, DNS failures
- **Warning**: "⚠️ Connection Warning"
- **User Action**: Unable to check destination, try again later

### Timeout Issues
- **Trigger**: Server takes too long to respond
- **Warning**: "⚠️ Connection Timeout"
- **User Action**: Try again later, or proceed if trusted

### Redirect Problems
- **Trigger**: Too many redirects detected
- **Warning**: "⚠️ Redirect Warning"
- **User Action**: Proceed with extreme caution

### Request Errors
- **Trigger**: Various HTTP request failures
- **Warning**: "⚠️ Request Error"
- **User Action**: Try again, or proceed with caution

### Unexpected Errors
- **Trigger**: Unknown or unexpected errors
- **Warning**: "⚠️ Verification Error"
- **User Action**: Try again, or proceed with caution

All warnings are displayed in a modal dialog that requires user acknowledgment before continuing. The system also provides optional "Learn more" links for additional information about specific warning types.

## Localization

The guard server supports multiple languages through template-based localization. Each language has its own template file with translated content and appropriate layout adjustments.

### Supported Languages

Currently supported languages:
- **English** (`guard_warning.html`) - Default template (and fallback when language support is missing)
- **German** (`guard_warning_de.html`)
- **Spanish** (`guard_warning_es.html`)
- **French** (`guard_warning_fr.html`)
- **Chinese** (`guard_warning_zh.html`)
- **Arabic** (`guard_warning_ar.html`)
- **Swedish** (`guard_warning_sv.html`)
- **Danish** (`guard_warning_da.html`)

### Language Selection

The server automatically selects the appropriate template based on the browser's `Accept-Language` header. You can also force a specific language using the `--force-language` command line option:

```bash
python3 detrackify_guard.py --force-language de
```

### Adding a New Language

To add support for a new language:

1. **Create a new template file** in the `templates/` directory:
   ```
   templates/guard_warning_xx.html
   ```
   Where `xx` is the ISO 639-1 language code (e.g., `it` for Italian, `pt` for Portuguese).

2. **Copy the base template** and translate the content:
   ```bash
   cp templates/guard_warning.html templates/guard_warning_it.html
   ```

3. **Translate the following elements**:
   - **Main content**: Phishing explanation, link descriptions, hints
   - **Button text**: "Continue to final destination", "Yes, I understand and want to continue"
   - **Modal content**: Warning headers, explanations, action guidance
   - **Block messages**: Blocked website explanations
   - **Progress messages**: "Resolving final destination, please wait..."

4. **Update JavaScript strings** in the template:
   ```javascript
   const JS_STRINGS = {
     // Error messages
     error_resolving_link: 'Errore nella risoluzione del link',
     connection_timed_out: 'Connessione scaduta',
     // ... translate all strings
   };
   ```

5. **Update warning definitions**:
   ```javascript
   const WARNING_DEFINITIONS = {
     'ssl_certificate': {
       header: '⚠️ Avviso Certificato di Sicurezza',
       message: 'Questo sito web ha problemi con il certificato di sicurezza',
       // ... translate all warning content
     },
     // ... translate all warning types
   };
   ```

6. **Consider layout adjustments**:
   - Some languages may require different text lengths
   - Right-to-left languages (like Arabic) may need CSS adjustments
   - Font sizes or spacing might need adjustment for different character sets

### Template Structure

Each template contains:
- **HTML content**: Main warning page with translated text
- **CSS classes**: Styling (shared via `common.css`)
- **JavaScript strings**: User-facing text used by `common.js`
- **Warning definitions**: Modal content for different warning types

### Testing Localization

To test a new language template:

1. **Use the force language option**:
   ```bash
   python3 detrackify_guard.py --force-language it
   ```

2. **Test with different scenarios**:
   - Normal links (no warnings)
   - SSL certificate issues
   - Connection timeouts
   - Blocked URLs

3. **Verify all text is translated**:
   - Main page content
   - Warning modals
   - Button text
   - Error messages

### Best Practices

- **Keep translations consistent** with existing language versions
- **Test with real scenarios** to ensure warning messages make sense
- **Consider cultural differences** in how warnings are presented
- **Maintain the same functionality** across all language versions
- **Use appropriate fonts** for languages with special characters
- **Keep it simple** to not scare or baffle regular users

## Link resolution

When link resolution is enabled the server will attempt to determine the final
destination of the provided link. Use `--resolve head` for HEAD requests or `--resolve get` for GET requests which also extracts the page title.

The page will display a progress message while this happens and the
continue button activates only once the real URL is known. The
result is cached in memory and optionally persisted to a JSON file to speed up
future requests.
Using `--resolve get` downloads the full page, which may consume significantly
more data and could trigger tracking mechanisms on the remote server. 

> It's worth noting that while HEAD is less bandwidth intensive, some servers don't allow HEAD and some won't provide the redirects we need to resolve the path. And yet they may still track you. 

The resolved link replaces the progress message and is highlighted just like the
original URL. If the final destination shares the same domain as the sender then
the highlight is shown in green and the continue button will open this resolved
link.
Options for the countdown and resolution are served through `/guard/opts.js`
so `/guard/common.js` can be cached efficiently.
If the resolution fails the `/resolve` endpoint returns an error message along
with an HTTP status code. In that case the browser falls back to the original
URL once the timer expires.
The cache key is `SHA256(data + SHA256(data))` where `data` is the base64-encoded link payload.
Entries older than the configured number of days are pruned every 24 hours and
the cache never grows beyond the specified maximum size.

## Endpoints

All endpoints except `/resources/` are served below the `/guard/` prefix:

* `/guard/<sha>/<b64>` — Show the warning page and handle the POST when link resolution is disabled.
* `/guard/resolve` — POST endpoint used by JavaScript to resolve the final URL. Returns JSON `{url, hash, title}`.
* `/guard/go` — POST endpoint that performs the redirect once a URL has been resolved.
* `/guard/common.js` — Shared JavaScript for the countdown and optional resolution (cacheable).
* `/guard/opts.js` — Dynamic options consumed by `common.js` via the Referer header.
* `/guard/common.css` — Common stylesheet used by the warning pages.
* `/resources/<path>` — Optional static resources such as images.

## Testing the Guard Server

### Using detrackify_url.py

The `detrackify_url.py` tool allows you to generate test URLs for the guard server:

```bash
# Basic test URL
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://example.com \
  --from user@example.com

# Test with recipient logging
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://example.com \
  --from user@example.com \
  --to recipient@company.com

# Test blocked URLs
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://malicious.com \
  --from spam@evil.com \
  --block blacklisted

# Test warning scenarios
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://expired-ssl.com \
  --from user@example.com \
  --block warning_blocked:ssl_certificate
```

### Manual Testing

You can also test the guard server manually by:

1. **Starting the server** with your configuration
2. **Generating a test URL** using `detrackify_url.py`
3. **Opening the URL** in a browser
4. **Verifying the warning page** displays correctly
5. **Testing the continue button** functionality

### Testing Different Scenarios

- **Normal links**: Trusted domains and senders
- **Domain mismatches**: Links from different domains
- **Blocked URLs**: Blacklisted domains and senders
- **Warning types**: SSL issues, timeouts, redirects
- **Custom display**: Different link text

See the main [README.md](README.md) for complete documentation of the `detrackify_url.py` tool.

## Using a reverse proxy

The guard server can run behind a reverse proxy such as nginx or Apache. Configure the proxy to pass requests for `/guard/` and `/resource/` to the internal server.

### Example Configurations

The `extras/` folder contains example configurations for common deployment scenarios:

- `extras/nginx.conf` - Complete nginx configuration with security headers, rate limiting, and SSL support

Example nginx snippet:

```nginx
location /guard/ {
    proxy_pass http://127.0.0.1:9090/guard/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
location /resources/ {
    proxy_pass http://127.0.0.1:9090/resources/;
}
```

When using a proxy, set `guard.server` to the external URL clients will access (e.g. `https://example.com`). No code changes are required.

## Docker Deployment

The guard server can be deployed using Docker for easier deployment and management. A `Dockerfile` and `docker-compose.yml` are provided for containerized deployment.

### Using the Published Image

The official Docker image is available from GitHub Container Registry:

```bash
# Pull the latest image
docker pull ghcr.io/mrworf/detrackify-guard:latest

# Run with basic configuration
docker run -d \
  --name detrackify-guard \
  -p 9090:9090 \
  -e GUARD_SALT=your_secure_salt_here \
  ghcr.io/mrworf/detrackify-guard:latest
```

### Building the Docker Image Locally

To build the Docker image locally:

```bash
docker build -t detrackify-guard .
```

The image includes:
- Python 3.11 slim base image
- All required dependencies from `requirements.txt`
- Non-root user for security
- Health check endpoint at `/guard/health`
- Default configuration for port 9090
- Environment variable support for all configuration options

### Running with Docker

#### Basic Docker Run

```bash
docker run -d \
  --name detrackify-guard \
  -p 9090:9090 \
  -e GUARD_SALT=your_secure_salt_here \
  -e TIMEOUT=5 \
  -e RESOLVE=head \
  ghcr.io/mrworf/detrackify-guard:latest
```

#### With Custom Configuration

```bash
docker run -d \
  --name detrackify-guard \
  -p 9090:9090 \
  -v $(pwd)/templates:/app/templates:ro \
  -v $(pwd)/resources:/app/resources:ro \
  -v $(pwd)/cache:/app/cache \
  -e GUARD_SALT=your_secure_salt_here \
  -e TIMEOUT=5 \
  -e RESOLVE=get \
  -e RESOLVE_CACHE_FILE=/app/cache/resolve_cache.json \
  -e RESOLVE_CACHE_DAYS=30 \
  -e RESOLVE_CACHE_MAX=4096 \
  -e PRIVACY=true \
  detrackify-guard
```

### Running with Docker Compose

The provided `docker-compose.yml` includes a complete setup with optional nginx reverse proxy. The nginx configuration is located in `extras/nginx.conf` and includes security headers, rate limiting, and SSL support.

#### Basic Setup

```bash
# Start the guard server only
docker-compose up -d

# View logs
docker-compose logs -f detrackify-guard
```

#### With Nginx Reverse Proxy

```bash
# Start both guard server and nginx proxy
docker-compose --profile proxy up -d

# View all logs
docker-compose logs -f
```

#### Custom Configuration

Edit the `docker-compose.yml` file to customize:

- **Salt**: Change `GUARD_SALT=changeme123` to your secure salt
- **Port**: Modify the port mapping `"9090:9090"` if needed
- **Volumes**: Uncomment or modify volume mounts for custom templates/resources
- **Environment**: Add environment variables as needed

### Environment Variables

All configuration options are available as environment variables:

#### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `GUARD_SALT` | Secret salt for link verification (required) | `GUARD_SALT=mysecret123` |

#### Optional Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `TIMEOUT` | Seconds before continue button activates | `5` | `TIMEOUT=10` |
| `PRIVACY` | Disable logging of visited links | `false` | `PRIVACY=true` |
| `RESOLVE` | Resolve final destination (choices: `head`, `get`) | `None` (disabled) | `RESOLVE=head` |
| `RESOLVE_CACHE_FILE` | Path to JSON cache file | `None` | `RESOLVE_CACHE_FILE=/app/cache/cache.json` |
| `RESOLVE_CACHE_DAYS` | Days to keep cached items | `30` | `RESOLVE_CACHE_DAYS=60` |
| `RESOLVE_CACHE_MAX` | Maximum number of cached items | `4096` | `RESOLVE_CACHE_MAX=8192` |
| `USER_AGENT` | User-Agent string for link resolution | Chrome browser | `USER_AGENT=MyBot/1.0` |
| `TEMPLATE_DIR` | Directory containing templates | `/app/templates` | `TEMPLATE_DIR=/custom/templates` |
| `RESOURCES_DIR` | Directory containing additional resources | `/app/resources` | `RESOURCES_DIR=/custom/resources` |
| `DENY_ON_WARNINGS` | Comma-separated list of warnings to deny access for | `None` | `DENY_ON_WARNINGS=ssl_certificate,connection_error` |

#### Multiple Values

For parameters that can be specified multiple times (like `--strip-param-prefix`), you should use commas to separate them:

**Comma-separated values**
```bash
STRIP_PARAM_PREFIX=utm_source,utm_medium,utm_campaign
```

#### Example Environment Configuration

```bash
# Basic configuration
GUARD_SALT=mysecret123
TIMEOUT=5
RESOLVE=head

# Advanced configuration
RESOLVE=get
RESOLVE_CACHE_FILE=/app/cache/resolve_cache.json
RESOLVE_CACHE_DAYS=30
RESOLVE_CACHE_MAX=4096
PRIVACY=true
USER_AGENT="Mozilla/5.0 (compatible; MyBot/1.0)"
STRIP_PARAM_PREFIX=utm_source,utm_medium,utm_campaign,fbclid
DENY_ON_WARNINGS=ssl_certificate,connection_error
```

#### Production Configuration

For production deployment:

1. **Use a strong salt**: Generate a secure random salt
2. **Enable HTTPS**: Configure SSL certificates in nginx
3. **Set up monitoring**: Use the health check endpoint
4. **Configure logging**: Mount log volumes if needed
5. **Resource limits**: Add memory and CPU limits

Example production `docker-compose.yml`:

```yaml
version: '3.8'

services:
  detrackify-guard:
    build: .
    container_name: detrackify-guard
    ports:
      - "127.0.0.1:9090:9090"  # Only bind to localhost
    environment:
      # Required
      - GUARD_SALT=${GUARD_SALT}
      
      # Configuration
      - TIMEOUT=5
      - RESOLVE=head
      - RESOLVE_CACHE_FILE=/app/cache/resolve_cache.json
      - RESOLVE_CACHE_DAYS=30
      - RESOLVE_CACHE_MAX=4096
      - PRIVACY=true
      - STRIP_PARAM_PREFIX=utm_source,utm_medium,utm_campaign,fbclid
      - DENY_ON_WARNINGS=ssl_certificate,connection_error
    volumes:
      - ./templates:/app/templates:ro
      - ./resources:/app/resources:ro
      - ./cache:/app/cache
      - ./logs:/app/logs
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
```

### Health Monitoring

The container includes a health check that can be monitored:

```bash
# Check container health
docker ps

# Test health endpoint directly
curl http://localhost:9090/guard/health

# Monitor with docker-compose
docker-compose ps
```

### Updating the Container

To update to a new version:

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

