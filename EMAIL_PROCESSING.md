# Email Processing Guide

This guide covers the email processing capabilities of `detrackify_email.py`, which removes tracking pixels and provides link protection for emails.

## Overview

The email processor analyzes emails to:
- **Detect and remove tracking pixels** - Replaces tracking images with transparent 1x1 pixels
- **Protect against phishing** - Guards links when sender display names don't match email domains
- **Strip tracking parameters** - Removes UTM and other tracking parameters from image URLs
- **Apply blocklists/whitelists** - Controls which content is allowed or blocked
- **Add security headers** - Includes X-Detrackify headers for monitoring and debugging

## Quick Start

### Basic Usage

```bash
# Process a single email
python detrackify_email.py \
  --input email.eml \
  --output cleaned.eml

# Process with link protection
python detrackify_email.py \
  --input email.eml \
  --output cleaned.eml \
  --guardserver https://guard.example.com \
  --guardsalt your_secure_salt \
  --guardlink mismatch
```

### Integration with Email Servers

```bash
# Postfix integration (stdin/stdout)
python detrackify_email.py \
  --input - \
  --output - \
  --guardserver https://guard.example.com \
  --guardsalt your_shared_salt \
  --guardlink mismatch
```

## Command Line Options

Most if not all options found here can also be defined in the YAML file in the next section.

### Basic Options

| Option | Description | Default |
|--------|-------------|---------|
| `--input` | Path to input email file (stdin if not specified) | stdin |
| `--output` | Path to output email file (stdout if not specified) | stdout |
| `--message-id` | Log the message ID being processed | None |
| `--verbose` | Enable verbose logging | False |
| `--debug` | Enable early debug logging | False |
| `--logfile` | Save log to file instead of stderr | None |
| `--config` | Path to YAML configuration file | None |
| `--hardfail` | Exit with error code on failures instead of passthrough | False |

### Link Protection Options

| Option | Description | Default |
|--------|-------------|---------|
| `--guardserver` | URL of the guard server (including scheme) | None |
| `--guardsalt` | Salt for guarded links (min 8 characters) | None |
| `--guardlink` | Guard link mode: `off`, `mismatch`, `always` | `off` |
| `--guardcaptureto` | Include recipient address in guarded links | False |
| `--guardphishy` | Enable phishing detection | False |
| `--guard-whitelist-file` | Path to guard whitelist YAML file | `guard_whitelist.yml` |

### Content Control Options

| Option | Description | Default |
|--------|-------------|---------|
| `--whitelist-file` | Path to whitelist YAML file | `whitelist.yml` |
| `--blacklist-file` | Path to blacklist YAML file | `blacklist.yml` |
| `--domain-aliases-file` | Path to domain aliases YAML file | `domain_aliases.yml` |
| `--cache-file` | Path to cache YAML file | None |

### Experimental Features

| Option | Description | Default |
|--------|-------------|---------|
| `--strip` | Remove parameters from image URLs (experimental) | False |
| `--testurl` | Test which parameters can be stripped from URLs | None |
| `--list` | List all detected image URLs | False |
| `--copy` | Copy original email to folder for debugging | None |
| `--strip-param-prefix` | Strip query parameters starting with PREFIX | None |

## Configuration

### YAML Configuration Format

```yaml
# Shared configuration (used by both email and guard)
common:
  salt: "your-secret-salt-here"
  domain_aliases_file: domain_aliases.yml
  blacklist_file: blacklist.yml

# Email processor configuration
email:
  verbose: false
  debug: false
  logfile: null
  
  # Experimental URL parameter stripping
  strip:
    enable: false
    file: strip.yml
    cookies: true
    redirect: true
  
  # Guard server configuration
  guard:
    server: http://localhost:9090
    link: mismatch  # off, mismatch, always
    capture_to: false
    phishy: false  # Enable phishing detection
    whitelist_file: guard_whitelist.yml
  
  # Email-specific file paths (overrides shared settings)
  whitelist_file: whitelist.yml
  cache_file: cache.yml
```

### Configuration Precedence

1. **Command line arguments** (highest priority)
2. **Configuration file** (specified with `--config`)
3. **Default configuration files** (whitelist.yml, blacklist.yml, etc.)
4. **Built-in defaults** (lowest priority)

## Features

### Tracking Pixel Detection and Removal

The email processor automatically detects and removes tracking pixels:

- **Detection**: Analyzes image URLs for tracking characteristics
- **Replacement**: Replaces tracking pixels with transparent 1x1 images
- **Preservation**: Maintains email formatting and layout
- **Logging**: Records what was blocked for monitoring

**Example:**
```
Original: <img src="https://tracking.example.com/pixel.gif?user=123&campaign=email">
Replaced: <img src="data:image/png;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
```

### Link Protection

When enabled, suspicious links are rewritten to route through the guard server:

**Guard Modes:**
- `off`: No link protection
- `mismatch`: Only guard links to different domains than sender
- `always`: Guard all links

**How it works:**
1. Analyzes each link in the email
2. Compares link domain with sender domain
3. Rewrites suspicious links with guard server URLs
4. Includes cryptographic signature for verification

**Example:**
```
Original: <a href="https://suspicious.com/offer">Click here</a>
Rewritten: <a href="https://guard.example.com/guard/abc123/xyz789">Click here</a>
```

### Phishing Detection

Automatically detects potential phishing attempts by analyzing sender information:

**Detection Logic:**
1. Extracts display name from `From:` header
2. Tokenizes display name into meaningful words
3. Compares tokens with email domain
4. Flags as suspicious if no overlap found

**Examples:**
- **Suspicious**: "Microsoft Security Team" <support@suspicious-domain.com>
- **Legitimate**: "Microsoft Corporation" <support@microsoft.com>

When phishing is detected:
- All links are automatically guarded
- Special "phishy" warning is displayed

### URL Parameter Stripping

Removes tracking parameters from URLs based on the provided list of prefixes.

**Example of prefixes:**
- UTM parameters (utm_source, utm_medium, utm_campaign, etc.)
- Facebook click ID (fbclid)
- Google click ID (gclid)
- Custom parameters (configurable)

**Example:**
```
Original: https://example.com/logo.png?utm_source=email&utm_campaign=newsletter&fbclid=abc123
Stripped: https://example.com/logo.png
```

**Configuration:**
```bash
# Command line
--strip-param-prefix utm_ --strip-param-prefix fbclid

# YAML configuration
strip_param_prefix:
  - "utm_"
  - "fbclid"
  - "gclid"
```

> NOTE! Once a prefix matches, all other parameters following the prefix are removed.

### Blocklist and Whitelist System

Fine-grained control over allowed and blocked content, allows admin to bypass protection for certain senders or link. And the reverse, always block for some senders or links.

Note that when we're saying blacklist, we're only talking about preventing the use of the links found in the email.

**Whitelist**: URLs that are always allowed (never processed or guarded)
**Blacklist**: URLs or senders that are blocked (sent to guard server)

**File Format:**
```yaml
# whitelist.yml
whitelist:
  - url: 'https://trusted.example.com/logo.png'
  - url: 'https://cdn.example.org/.*'

# blacklist.yml  
blacklist:
  - sender: '^spam@malicious\.com$'
  - url: '^https://malicious\.com/.*'
  - url: '^https://.*\.phishing\.net/.*'
```

Note on combined files:
- You can put both `whitelist:` and `blacklist:` in the same YAML file.
- The tools only read the top-level keys `whitelist` and `blacklist` in that file and ignore everything else.
- If either key is missing, it is treated as empty. This lets you reuse a single file for both lists without duplication.

**How Blocking Works:**
- **Sender blacklisting**: All links in emails from blacklisted senders are guarded
- **Sender whitelisting**: All links in emails from whitelisted senders bypass all processing
- **URL blacklisting**: Specific URLs matching blacklist patterns are guarded
- **URL whitelisting**: URLs matching whitelist patterns bypass all processing

### Domain Aliases

Configure domains that belong to the same organization, it's not uncommon for companies to use one domain for their email and another one for the links within the email. This allows you to handle that usecase.

**File Format:**
```yaml
# domain_aliases.yml
aliases:
  instacart.com:
    - instacartemail.com
    - email.instacart.com
  amazon.com:
    - amazon-communications.com
    - amazon-news.com
```

**Usage:**
- Links to aliased domains are treated as if they match the sender domain
- Prevents unnecessary guarding of legitimate organizational links
- Works with both email processor and guard server

### Cache System

Persistent caching for improved performance:

**Features:**
- Caches blacklist and whitelist entries
- Survives program restarts
- Automatically saves at end of processing
- Improves performance on subsequent runs

**Configuration:**
```bash
--cache-file cache.yml
```

**File Format:**
```yaml
# cache.yml (automatically generated)
blacklist:
  - url: 'https://tracking.example.com/pixel.gif'
whitelist:
  - url: 'https://trusted.example.com/logo.png'
```

## Output and Headers

### X-Detrackify Headers

The processor adds headers for monitoring and debugging:

```
X-Detrackify: processed
X-Detrackify-Tracking-Pixels: 3
X-Detrackify-Guarded-Links: 2
X-Detrackify-Guard-Mode: mismatch
X-Detrackify-Phishing-Detected: true
```

### Logging

Comprehensive logging for monitoring and debugging:

```
2024-01-01 12:00:00 - INFO - detrackify_email.py:123 - Processing email from user@example.com
2024-01-01 12:00:01 - INFO - detrackify_email.py:145 - Blocked 3 tracking pixels
2024-01-01 12:00:01 - INFO - detrackify_email.py:167 - Guarded 2 suspicious links
2024-01-01 12:00:01 - INFO - detrackify_email.py:189 - Phishing detection: sender mismatch
```

## Error Handling

### Failsafe Mode

By default, the processor uses failsafe mode:
- If processing fails, the original email is passed through unchanged
- Ensures email delivery even if processing encounters errors
- Logs errors for debugging

### Hard Fail Mode

Enable with `--hardfail`:
- Exits with error code on processing failures
- Useful for debugging and development
- Prevents email delivery if processing fails

### Common Error Scenarios

- **Malformed emails**: Invalid MIME structure
- **Encoding issues**: Character encoding problems
- **Large emails**: Memory or processing limits
- **Network errors**: When using `--testurl` or guard server

## Integration Examples

### Postfix Integration

Add to `/etc/postfix/master.cf`:
```
detrackify unix - n n - - pipe
  flags=Rq user=detrackify argv=/usr/local/bin/detrackify_email.py --guardserver https://guard.example.com --guardsalt your_salt --guardlink mismatch
```
> NOTE! This is untested, author uses exim.

### Exim Integration

Add to exim configuration:
```
detrackify_router:
  driver = accept
  domains = +local_domains
  condition = ${if !eq{$received_protocol}{detrackify}{yes}{no}}
  transport = detrackify

detrackify:
  driver = pipe
  use_bsmtp
  transport_filter = /opt/detrackify-email/detrackify_email.py --message-id ${message_id} --logfile /var/log exim4/detrackify.log
  command = /usr/sbin/exim4 -oMr detrackify -bS
  return_fail_output = true
  log_output = true
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
python detrackify_email.py \
  --input email.eml \
  --output cleaned.eml \
  --debug \
  --verbose
```

### Testing

Use the test suite to verify functionality:

```bash
# Run all tests
pytest -v

# Test specific functionality
pytest tests/test_processing.py -v
```

## Security Considerations

### Best Practices

- **Secure salt**: Use a strong, random salt for guard server
- **HTTPS**: Always use HTTPS for guard server communication
- **File permissions**: Restrict access to configuration files
- **Logging**: Monitor logs for suspicious activity
- **Updates**: Keep the tool updated with security patches

### Privacy

- **Link logging**: Guard server can log visited links (disable with privacy mode)
- **Email content**: Original emails are not stored
- **Cache data**: Cache files may contain URL information

## Related Documentation

- **[GUARD_SERVER.md](GUARD_SERVER.md)** - Guard server setup and configuration
- **[DOCKER.md](DOCKER.md)** - Docker deployment instructions
- **[examples/](examples/)** - Configuration examples and templates 