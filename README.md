# Detrackify

[![Build Status](https://github.com/mrworf/detrackify-email/workflows/Build%20and%20Publish%20Docker%20Image/badge.svg)](https://github.com/mrworf/detrackify-email/actions)
[![Docker Image](https://img.shields.io/docker/image-size/ghcr.io/mrworf/detrackify-guard/latest)](https://ghcr.io/mrworf/detrackify-guard)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Processes standard emails and tries to determine what images within are used to track you. If found, it will replace them with a embedded 1x1 transparent pixel, thus retaining the formatting but preventing the pixel from reporting in.

## Features

- Handles both HTML and non-HTML (well, then there's no tracking either)
- Adds X-Detrackify headers for statistics and debugging
- Integrates with your MTA, allowing server based tracking prevention
- Failsafe, if tool fails for some reason, will revert to passthru of the email (configurable)
- Phishing detection - automatically guards links when sender display name doesn't match email domain

## Example Configurations

See the [examples/](examples/README.md) folder for sample configuration files for both the email processor and guard server, including blocklist, whitelist, and domain alias formats. This folder also contains legacy and advanced configuration examples.

## Requirements

The project uses a single `requirements.txt` file that includes all dependencies. For Docker builds, development tools like `pytest` and `pylint` are automatically excluded during the build process to keep the container size minimal.

## Docker

**Registry:** `ghcr.io/mrworf/detrackify-guard`
**Latest Tag:** `ghcr.io/mrworf/detrackify-guard:latest`
**Specific Versions:** `ghcr.io/mrworf/detrackify-guard:v1.0.com` (replace with actual version)

### Quick Start

```bash
# Pull and run with basic configuration
docker pull ghcr.io/mrworf/detrackify-guard:latest
docker run -d \
  --name detrackify-guard \
  -p 9090:9090 \
  -e GUARD_SALT=your_secure_salt_here \
  ghcr.io/mrworf/detrackify-guard:latest

# Or use Docker Compose
docker-compose up -d
```

For complete Docker deployment instructions, configuration options, and production setup, see [DOCKER.md](DOCKER.md).

## Known issues

- Will break DKIM since content and headers change, but this is expected.
- Doesn't handle elements contained within hidden elements

## Usage

### Basic Options

`--input` and `--output` to run from command line, will also output information about what was blocked

`--message-id` to log the message id in the log output

`--verbose` enable debug logging

`--debug` enable early debug logging

`--logfile` save logging to file instead of stderr

`--config` path to YAML configuration file

### Experimental Features

`--strip` will remove any parameters attached to an image's URL, ie `https://www.shady-site.com/nice-logo.png?track=879384yutr93478` becomes `https://www.shady-site.com/nice-logo.png`. This is *experimental* and without this option the log will show what images it would strip. It's experimental because there's no guarantee that this won't break the image.

`--testurl` detect which query parameters can be stripped from the URL (WARNING! Will make requests to the URLs)

> For now, I recommend using `--strip-param-prefix` instead, a more reliable but less automatic approach.

`--list` list all detected image URLs

`--copy` copy the original email to this folder for debugging

### Guard Server Options

`--guardserver` specify address of the guard server used for rewriting links. Must include http or https.

`--guardsalt` specify salt used when creating guarded links. Must be at least 8 characters.

`--guardlink` link guarding mode: `off`, `mismatch`, or `always` (default `off`).

`--guardcaptureto` include the `To:` address in guarded links so the guard server can log who clicked.

`--guardphishy` enable phishing detection - guard all links when sender display name doesn't match email domain.

`--guard-whitelist-file` path to guard whitelist YAML file (default: guard_whitelist.yml)

`--domain-aliases-file` path to domain aliases YAML file (default: domain_aliases.yml).

`--cache-file` path to cache YAML file for persistent caching of blacklist/whitelist entries.

### Blocklist Options

`--whitelist-file` path to whitelist YAML file (default: whitelist.yml)

`--blacklist-file` path to blacklist YAML file (default: blacklist.yml)

### Guard settings

When link guarding is enabled, every hyperlink in the email is replaced with a
redirect through the guard server. The rewritten link contains a Base64 encoded
JSON payload holding the original URL, the display text of the link and the
domain from the email's `From:` header. Optionally the recipient address can be
included. The payload is hashed together with the salt to ensure it has not been
tampered with before the server redirects the user.

Guard settings can also be provided in the YAML configuration file:

```yaml
guard:
  server: https://guard.example.com
  link: mismatch
  capture_to: false
  phishy: false  # Enable phishing detection

# Common secret between email and guard
salt: mysecret123

# Additional configuration files
domain_aliases_file: domain_aliases.yml  # Path to domain aliases file
whitelist_file: whitelist.yml           # Path to whitelist file
blacklist_file: blacklist.yml           # Path to blacklist file
cache_file: cache.yml                   # Path to cache file for persistent caching

See the [guard server guide](GUARD_SERVER.md) for more details on running the guard server, enabling privacy mode and using a reverse proxy.

## Phishing Detection

The phishing detection feature analyzes sender display names against their email domains to identify potential impersonation attempts. When enabled, it automatically guards all links in suspicious emails with a special "phishy" warning.

### How Phishing Detection Works

The system compares the sender's display name with their email domain using token-based analysis:

1. **Extract Information**: Gets the display name from the `From:` header (e.g., "Microsoft Security Team")
2. **Tokenize Display Name**: Splits the display name into meaningful words (filters out words ≤2 characters)
3. **Extract Domain Root**: Gets the main part of the email domain (e.g., "suspicious-domain" from "suspicious-domain.xyz")
4. **Check for Overlap**: Determines if any display name tokens appear in the domain root
5. **Flag as Suspicious**: If no overlap is found, flags the email as potentially phishing

### Examples

**Flagged as Suspicious (Phishing):**
- Display Name: "Microsoft Security Team", Email: `support@suspicious-domain.com`
- Display Name: "PayPal Security", Email: `noreply@random-site.net`
- Display Name: "Amazon Customer Service", Email: `alerts@fake-amazon.xyz`
- Display Name: "Apple Support", Email: `help@malicious-site.com`

**NOT Flagged (Legitimate):**
- Display Name: "Microsoft Corporation", Email: `support@microsoft.com`
- Display Name: "PayPal", Email: `service@paypal.com`
- Display Name: "Amazon.com", Email: `no-reply@amazon.com`
- Display Name: "Apple Inc.", Email: `notifications@apple.com`

### Configuration

**Command Line:**
```bash
python detrackify_email.py \
  --guardserver https://guard.example.com \
  --guardsalt your_secure_salt \
  --guardlink mismatch \
  --guardphishy \
  --input email.eml \
  --output cleaned.eml
```

**YAML Configuration:**
```yaml
# Email processor configuration
email:
  guard:
    server: https://guard.example.com
    salt: your_secure_salt
    link: mismatch
    phishy: true  # Enable phishing detection
```

### What Happens When Phishing is Detected

1. **Automatic Link Guarding**: All links in the email are automatically guarded, regardless of domain matching
2. **Special Block Reason**: Guarded links get a "phishy" block reason instead of the normal "mismatch" reason
3. **User-Friendly Warning**: The guard server displays a specialized warning message:
   - "The sender of this email doesn't seem to match the content of the email"
   - "Be careful - the sender's name and email domain don't match"
4. **Logging**: The system logs when phishing is detected for monitoring and analysis

### Guard Server Display

When users click a link from a phishing email, they see a warning page that explains:
- The sender's display name doesn't match their email domain
- This could be an impersonation attempt
- Where the link will actually take them
- A clear warning about the domain mismatch

The warning message is designed to be understandable by non-technical users while providing enough information to make informed decisions.

### Integration with Other Features

Phishing detection works alongside existing guard features:
- **Domain Aliases**: Legitimate organizational domains are respected
- **Whitelisting**: Trusted senders can still bypass phishing detection
- **Blacklisting**: Blacklisted senders are handled separately
- **Link Resolution**: The guard server still resolves final destinations for phishing links

## Configuration

Detrackify uses a unified YAML configuration format that allows both the email processor and guard server to use the same configuration file. This reduces configuration fragmentation and makes it easier to manage shared settings.

### Configuration Format

Create a single configuration file with separate sections for each application:

```yaml
# Unified Detrackify Configuration
# This file can be used by both detrackify_email.py and detrackify_guard.py

# Shared configuration (used by both email and guard)
salt: "your-secret-salt-here"
domain_aliases_file: domain_aliases.yml
blacklist_file: blacklist.yml
whitelist_file: whitelist.yml

# Email processor configuration
email:
  verbose: false
  strip:
    enable: false
    file: strip.yml
    cookies: true
    redirect: true
  copy: null
  guard:
    server: http://localhost:9090
    link: mismatch
    capture_to: false
    phishy: false
    whitelist_file: guard_whitelist.yml
  
  # Email-specific file paths (overrides shared settings)
  cache_file: cache.yml

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
```

### Configuration Structure

- **Shared settings** (root level): Common configuration used by both applications
- **`email` section**: Email processor specific settings
- **`guard` section**: Guard server specific settings

### Configuration Precedence

1. **Shared settings** (root level): Used by both applications
2. **Application-specific settings** (`email` or `guard` sections): Override shared settings
3. **Command line arguments**: Override both shared and application-specific settings

### Usage

**Email processor:**
```bash
python detrackify_email.py --config config.yml
```

**Guard server:**
```bash
python detrackify_guard.py --config config.yml
```

### Example Files

- `examples/config_unified.yml` - Complete configuration example
- `examples/config_unified_simple.yml` - Minimal configuration example
- `examples/config_guard_with_phishing_detection.yml` - Guard configuration with phishing detection enabled

### Command Line Options

**Email processor options:**

`--config` path to YAML configuration file

`--verbose` enable verbose logging

`--strip` enable experimental URL parameter stripping

`--copy` copy processed emails to folder

`--guardserver` URL of the guard server (including scheme)

`--guardsalt` specify salt used when creating guarded links. Must be at least 8 characters.

`--guardlink` specify guard link mode (choices: off, mismatch, always)

`--guardcaptureto` capture the To address in guarded links

`--guardphishy` enable phishing detection - guard all links when sender display name doesn't match email domain

`--guard-whitelist-file` path to guard whitelist YAML file

`--domain-aliases-file` path to domain aliases YAML file (default: domain_aliases.yml)

`--cache-file` path to cache YAML file for persistent caching of blacklist/whitelist entries

`--whitelist-file` path to whitelist YAML file (default: whitelist.yml)

`--blacklist-file` path to blacklist YAML file (default: blacklist.yml)

**Guard server options:**

`--config` path to YAML configuration file

`--salt` salt for hash validation (required if not in config file)

`--listen-ip` IP to bind to (default: 127.0.0.1)

`--listen-port` port to listen on (default: 9090)

`--timeout` seconds before continue button activates (default: 5)

`--privacy` disable logging of visited links

`--resolve` resolve the final URL before showing the continue button (choices: head, get, default: None - disabled)

`--template-dir` directory containing templates (default: templates)

`--resources-dir` directory containing additional resources (images only)

`--debug` enable debug mode with template auto-reload

`--force-language` force serving a specific language template (e.g., de, es, fr, zh, ar)

`--strip-param-prefix` remove tracking parameters starting with PREFIX (may be used multiple times)

`--domain-aliases-file` path to domain aliases YAML file (default: domain_aliases.yml)

`--blacklist-file` path to blacklist YAML file (default: blacklist.yml)

## Guard Whitelist Configuration

The guard whitelist system allows you to specify which links and senders should bypass link guarding. This is useful for trusted domains and senders where you don't want the warning page.

### Guard Whitelist File Format

The guard whitelist file uses YAML format with a single `whitelist` section containing both URL and sender entries:

```yaml
# Whitelist entries - URLs and senders that bypass guarding
whitelist:
  # URLs that bypass link guarding
  - url: '^https://trusted\.example\.com/.*'
  - url: '^https://cdn\.example\.org/.*'
  - url: '^https://.*\.trusted-domain\.com/.*'
  
  # Sender email addresses that bypass link guarding
  - sender: '^admin@example\.org$'
  - sender: '^noreply@trusted\.com$'
  - sender: '^security@bank\.com$'
```

### How Guard Whitelisting Works

**Link Whitelisting:**
- URLs that match `url` patterns in the guard whitelist are not rewritten with guard server links
- They still go through normal email processing (tracking pixel detection, etc.)
- Use this for trusted domains where you don't need the warning page

**Sender Whitelisting:**
- All links in emails from senders matching `sender` patterns in the guard whitelist bypass link guarding
- Use this for trusted senders (like your bank, employer, etc.)
- The entire email bypasses link guarding for these senders

**Unified Whitelist:**
- The guard whitelist uses the same format as other whitelists, with both `url` and `sender` entries in a single file
- This allows reuse of existing whitelist handling code and provides a consistent configuration format

### Configuration

**Command Line:**
```bash
python detrackify_email.py --guard-whitelist-file /path/to/guard_whitelist.yml
```

**YAML Configuration:**
```yaml
# In your main config file
guard:
  whitelist_file: guard_whitelist.yml  # Path to guard whitelist file
```

## Blocklist Configuration

The blocklist system allows you to control which URLs and senders are allowed or blocked. This provides fine-grained control over email security by blocking known malicious sources and allowing trusted ones.

Both `detrackify_email.py` and `detrackify_guard.py` use shared configuration files to ensure consistency across the system.

### File Formats

You can use either a combined file or separate files:

#### Combined Blocklist File (`blocklist.yml`)

A single file containing both whitelist and blacklist entries:

```yaml
# Whitelist entries - URLs that are always allowed
whitelist:
  - url: 'https://trusted.example.com/logo.png'
  - url: 'https://cdn.example.org/.*'

# Blacklist entries - URLs or senders that are blocked
blacklist:
  # Block specific sender email addresses
  - sender: '^spam@malicious\.com$'
  - sender: '^test.*@example\.org$'
  
  # Block specific URLs or domains
  - url: '^https://malicious\.com/.*'
  - url: '^https://.*\.phishing\.net/.*'
  - url: '^https://tracking\.example\.com/.*'
```

#### Separate Files

You can also use separate files for whitelist and blacklist:

**Whitelist file (`whitelist.yml`):**
```yaml
whitelist:
  - url: 'https://trusted.example.com/logo.png'
  - url: 'https://cdn.example.org/.*'
```

**Blacklist file (`blacklist.yml`):**
```yaml
blacklist:
  # Block specific sender email addresses
  - sender: '^spam@malicious\.com$'
  - sender: '^test.*@example\.org$'
  
  # Block specific URLs or domains
  - url: '^https://malicious\.com/.*'
  - url: '^https://.*\.phishing\.net/.*'
```

> **Tip**: You can use the same file for both tools since they look for specific keys (`whitelist` and `blacklist`) in the YAML file. If a key is missing, it's simply ignored.

### How Blocking Works

**In detrackify_email.py:**
- Sender blacklisting: If the email sender matches a blacklist pattern, all links in the email are sent to the guard server
- URL blacklisting: If any link in the email matches a blacklist pattern, it's sent to the guard server
- Whitelisting: URLs that match whitelist patterns are never processed or guarded

**In detrackify_guard.py:**
- URL blacklisting: If the original or resolved URL matches a blacklist pattern, the user sees a blocking message
- The blocking message explains why the site is blocked in friendly language
- No redirect is allowed to blacklisted URLs

### Configuration

**YAML Configuration:**
```yaml
# In your main config file
blocklist_file: blocklist.yml  # Path to blocklist file
```

**Command Line:**
```bash
# For detrackify_email.py
python detrackify_email.py --blacklist-file /path/to/blacklist.yml

# For detrackify_guard.py  
python detrackify_guard.py --blacklist-file /path/to/blacklist.yml
```

**Default Files:**
- `detrackify_email.py` looks for `blacklist.yml` by default
- `detrackify_guard.py` looks for `blacklist.yml` by default

## Denied Warnings Configuration

The denied warnings feature allows you to completely deny access to links that trigger specific types of warnings during URL resolution. Instead of showing a warning modal that users can acknowledge, these warnings result in a complete denial with no option to proceed.

### Available Warning Types

The following warning types can be denied:

- `ssl_certificate`: SSL certificate verification failed
- `connection_error`: Connection errors (DNS, network, etc.)
- `connection_timeout`: Connection timeout
- `too_many_redirects`: Too many redirects
- `request_error`: Other request-related errors
- `unexpected_error`: Unexpected errors during resolution

### Configuration

**YAML Configuration:**
```yaml
# In your main config file
deny_on_warnings:
  - "ssl_certificate"      # Deny access for SSL certificate issues
  - "connection_error"     # Deny access for connection errors
  - "too_many_redirects"   # Deny access for suspicious redirect chains
```

**Command Line:**
```bash
python detrackify_guard.py --deny-on-warnings ssl_certificate --deny-on-warnings connection_error
```

### How It Works

When URL resolution detects a warning that's in the denied warnings list:
1. The normal warning modal is not shown
2. Instead, the URL transition display shows "Access denied:" instead of "Final destination:"
3. The denied warning is displayed in the same format as normal warnings, with meaning, action, and optional "Learn more" link
4. No continue button is provided - access is completely denied
5. The specific warning reason and explanation are displayed in a user-friendly format

This provides an additional layer of security by preventing users from proceeding to potentially dangerous sites, while maintaining a familiar and informative user interface that explains why the link was denied.

## Cache System

The cache system provides persistent storage for blacklist and whitelist entries to improve performance across multiple runs. Instead of only caching in-memory, the cache is saved to a YAML file and can be reused in subsequent executions.

### How Caching Works

1. **Cache Priority**: The system first checks the main blacklist/whitelist files, then falls back to the cache
2. **Persistent Storage**: Cache entries are saved to a YAML file and loaded on startup
3. **Automatic Saving**: Cache is automatically saved at the end of processing
4. **Performance**: Reduces repeated lookups and improves processing speed

### Cache File Format

The cache file uses the same format as blocklist files:

```yaml
# Cache entries - automatically generated and managed
blacklist:
  - url: 'https://tracking.example.com/pixel.gif'
  - url: 'https://malicious.com/.*'

whitelist:
  - url: 'https://trusted.example.com/logo.png'
  - url: 'https://cdn.example.org/.*'
```

### Configuration

**Command Line:**
```bash
python detrackify_email.py --cache-file /path/to/cache.yml
```

**YAML Configuration:**
```yaml
# In your main config file
cache_file: cache.yml  # Path to cache file
```

### Cache Management

The cache is automatically managed by the system:
- **Loading**: Cache is loaded on startup if the file exists
- **Adding**: New entries are automatically added to cache during processing (not to main lists)
- **Saving**: Cache is saved at the end of processing
- **Clearing**: Use the cache management methods to clear entries if needed

**Important**: All new blacklist and whitelist entries discovered during processing are added to the cache, not to the main configuration files. This ensures that:
- Main configuration files remain unchanged
- Cache provides persistent storage for learned entries
- Performance improves over time as cache grows

### Benefits

- **Performance**: Faster processing on subsequent runs
- **Persistence**: Cache survives program restarts
- **Flexibility**: Can be shared across multiple instances
- **Transparency**: Cache file is human-readable YAML format

## Domain Aliases

Domain aliases allow you to specify that certain domains belong to the same organization. This is useful when companies use different domains for their email services. For example, Instacart uses `instacartemail.com` for emails but `instacart.com` for their main site.

Both `detrackify_email.py` and `detrackify_guard.py` use shared configuration files to ensure consistency across the system.

### Domain Aliases File Format

The domain aliases file uses YAML format with a single `aliases` section:

```yaml
# Domain aliases - domains that belong to the same organization
aliases:
  instacart.com:
    - instacartemail.com
    - email.instacart.com
  amazon.com:
    - amazon-communications.com
    - amazon-news.com
    - amazon-email.com
  microsoft.com:
    - microsoft-email.com
    - msft.com
```

### How Domain Aliases Work

**In detrackify_email.py:**
- When link guarding is enabled, domain aliases are used to determine if a link matches the sender domain
- Links to aliased domains are treated as if they match the sender domain
- This prevents unnecessary guarding of legitimate organizational links

**In detrackify_guard.py:**
- Domain aliases are used during URL resolution to determine the final destination domain
- The resolved domain is compared against the sender domain and its aliases
- This ensures consistent domain matching across the entire system

### Configuration

**Command Line:**
```bash
python detrackify_email.py --domain-aliases-file /path/to/domain_aliases.yml
python detrackify_guard.py --domain-aliases-file /path/to/domain_aliases.yml
```

**YAML Configuration:**
```yaml
# In your main config file
domain_aliases_file: domain_aliases.yml  # Path to domain aliases file
```

## Testing Tools

### detrackify_url.py

The `detrackify_url.py` tool allows you to generate guarded URLs for testing the guard server. This is useful for:

- Testing guard server configurations
- Creating test cases for different scenarios
- Debugging guard server behavior
- Simulating blocked URLs and warnings

#### Basic Usage

```bash
# Generate a basic guarded URL
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://example.com \
  --from user@example.com

# Output: http://localhost:9090/guard/<hash>/<base64_payload>
```

#### Advanced Usage

```bash
# With recipient address (for logging)
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://example.com \
  --from user@example.com \
  --to recipient@company.com

# With custom display text
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://example.com \
  --from user@example.com \
  --display "Click here for special offer"

# Simulate a blocked URL
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://malicious.com \
  --from spam@evil.com \
  --to victim@company.com \
  --block blacklisted

# Simulate phishing detection
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://example.com \
  --from "Microsoft Security <fake@suspicious.com>" \
  --block phishy

# Verbose output for debugging
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://example.com \
  --from user@example.com \
  --verbose
```

#### Command Line Options

- `--server`: Guard server URL (e.g., http://localhost:9090)
- `--salt`: Guard salt for hash validation (must be at least 8 characters)
- `--url`: Target URL to guard
- `--from`: Sender email address
- `--to`: Optional recipient email address
- `--block`: Optional block reason (e.g., 'blacklisted')
- `--display`: Optional display text (defaults to "Link to {url}")
- `--verbose`, `-v`: Show detailed information including payload and hash

#### Testing Scenarios

**Normal Link:**
```bash
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt test123 \
  --url https://trusted.example.com \
  --from admin@example.com
```

**Domain Mismatch:**
```bash
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt test123 \
  --url https://suspicious.com \
  --from admin@example.com
```

**Blocked Sender:**
```bash
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt test123 \
  --url https://example.com \
  --from spam@malicious.com \
  --block blacklisted
```

**Phishing Detection:**
```bash
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt test123 \
  --url https://example.com \
  --from "Microsoft Security <fake@suspicious.com>" \
  --block phishy
```

**Warning Simulation:**
```bash
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt test123 \
  --url https://expired-ssl.com \
  --from user@example.com \
  --block warning_blocked:ssl_certificate
```

#### Integration with Guard Server

The generated URLs work seamlessly with the guard server:

1. **Copy the generated URL** and paste it in a browser
2. **The guard server will display** the appropriate warning page
3. **Test different scenarios** by varying the parameters
4. **Use verbose mode** to understand the payload structure

This tool is particularly useful for:
- **Development and testing** of guard server configurations
- **Creating test cases** for different warning types
- **Debugging** guard server behavior
- **Demonstrating** the system to stakeholders
- **Validating** blocklist and whitelist configurations

## License

This project is licensed under the GNU General Public License v3.0. See the [COPYING](COPYING) file for the full license text.