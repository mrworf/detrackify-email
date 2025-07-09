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

## Example Configurations

See the [examples/](examples/README.md) folder for sample configuration files for both the email processor and guard server, including blocklist, whitelist, and domain alias formats. This folder also contains legacy and advanced configuration examples.

## Requirements

The project uses a single `requirements.txt` file that includes all dependencies. For Docker builds, development tools like `pytest` and `pylint` are automatically excluded during the build process to keep the container size minimal.

## Docker

**Registry:** `ghcr.io/mrworf/detrackify-guard`
**Latest Tag:** `ghcr.io/mrworf/detrackify-guard:latest`
**Specific Versions:** `ghcr.io/mrworf/detrackify-guard:v1.0.0` (replace with actual version)

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

`--list` list all detected image URLs

`--copy` copy the original email to this folder for debugging

### Guard Server Options

`--guardserver` specify address of the guard server used for rewriting links. Must include http or https.

`--guardsalt` specify salt used when creating guarded links. Must be at least 8 characters.

`--guardlink` link guarding mode: `off`, `mismatch`, or `always` (default `off`).

`--guardcaptureto` include the `To:` address in guarded links so the guard server can log who clicked.

`--guard-whitelist-file` path to guard whitelist YAML file (default: guard_whitelist.yml)

`--domain-aliases-file` path to domain aliases YAML file (default: domain_aliases.yml).

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

Guard settings can also be provided in the YAML configuration file.  All guard
options live under the top-level `options` key:

```yaml
options:
  guard:
    server: https://guard.example.com
    salt: mysecret123
    link: mismatch
    capture_to: false
    whitelist_links:
      - '^https://trusted\.example\.com'
    whitelist_senders:
      - '^admin@example\.org$'
    # sender patterns are checked against the full address
    domain_aliases_file: domain_aliases.yml
  # domain_aliases_file specifies the path to a shared domain aliases configuration file
  # this file is used by both detrackify_email.py and detrackify_guard.py
  # see domain_aliases.yml for the format and examples
```

See the [guard server guide](GUARD_SERVER.md) for more details on running the guard server, enabling privacy mode and using a reverse proxy.

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
- URLs that match `whitelist_links` patterns are not rewritten with guard server links
- They still go through normal email processing (tracking pixel detection, etc.)
- Use this for trusted domains where you don't need the warning page

**Sender Whitelisting:**
- All links in emails from senders matching `whitelist_senders` patterns bypass link guarding
- Use this for trusted senders (like your bank, employer, etc.)
- The entire email bypasses link guarding for these senders

### Configuration

**Command Line:**
```bash
python detrackify_email.py --guard-whitelist-file /path/to/guard_whitelist.yml
```

**YAML Configuration:**
```yaml
# In your main config file
guard_whitelist_file: guard_whitelist.yml  # Path to guard whitelist file
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
- `detrackify_guard.py` looks for `blocklist.yml` by default

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

## Domain Aliases

Domain aliases allow you to specify that certain domains belong to the same organization. This is useful when companies use different domains for their email services. For example, Instacart uses `instacartemail.com` for emails but `instacart.com` for their main site.

Both `