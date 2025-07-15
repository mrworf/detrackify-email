# Configuration Examples

This folder contains example configuration files for both the Detrackify email processor and the guard server.

## Configuration Format

Detrackify uses a unified YAML configuration format that allows both applications to use the same configuration file. This approach reduces configuration fragmentation and allows sharing common settings.
However, should the user choose, they can have separate configuration files, as long as the relevant sections are completed.

### `config_unified.yml`
Complete configuration file that can be used by both `detrackify_email.py` and `detrackify_guard.py`.

**Structure:**
- **Shared settings**: Common configuration used by both applications
- **`email` section**: Email processor specific settings
- **`guard` section**: Guard server specific settings

**Benefits:**
- Single configuration file for both tools
- Shared settings reduce duplication
- Application-specific sections provide clear separation
- Configuration precedence (application-specific overrides shared)

### `config_unified_simple.yml`
Minimal configuration showing only essential settings for both applications.

## Email Processor Configuration

The `email` section contains all settings for processing emails and removing tracking pixels:

**Key sections:**
- `options.verbose`: Enable debug logging
- `options.strip`: Experimental URL parameter stripping
- `options.guard`: Link guarding configuration
- `domain_aliases_file`: Path to domain aliases file
- `whitelist_file`: Path to whitelist file
- `blacklist_file`: Path to blocklist file

## Guard Server Configuration

The `guard` section contains all settings for the guard server:

**Key settings:**
- `guardsalt`: Required salt for hash validation
- `listen_ip`/`listen_port`: Server binding
- `timeout`: Seconds before continue button activates
- `privacy`: Disable logging of visited links
- `resolve`: Link resolution mode (head/get, default: None - disabled)
- `strip_param_prefix`: URL parameters to strip

## Shared Configuration Files

### `domain_aliases.yml`
Defines which domains belong to the same organization. Used by both email processor and guard server.

**Format:**
```yaml
# Owner domain: list of aliases
instacart.com: [instacartemail.com]
amazon.com: [amazon-email.com, amazon-news.com]
```

### `blocklist.yml`
Controls which URLs and senders are allowed or blocked. Used by both email processor and guard server.

**Format:**
```yaml
whitelist:
  - 'https://trusted.example.com/logo.png'

blacklist:
  - sender: '^spam@malicious\.com$'
  - url: '^https://malicious\.com/.*'
```

## Usage

### For Email Processor
```bash
python detrackify_email.py --config examples/config_email.yml
```

### For Guard Server
```bash
python detrackify_guard.py --config examples/config_guard_server.yml
```

## Configuration Priority

1. Command line arguments (highest priority)
2. Configuration file specified with `--config`
3. Default configuration file locations
4. Built-in defaults (lowest priority)

## Testing with detrackify_url.py

The `detrackify_url.py` tool can be used to test your guard server configurations:

```bash
# Test basic functionality
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt test123 \
  --url https://example.com \
  --from user@example.com

# Test with your configuration files
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://trusted.example.com \
  --from admin@example.com \
  --to recipient@company.com

# Test blocked URLs
python detrackify_url.py \
  --server http://localhost:9090 \
  --salt your_secure_salt \
  --url https://malicious.com \
  --from spam@evil.com \
  --block blacklisted
```

### Testing Different Scenarios

1. **Normal Links**: Test trusted domains and senders
2. **Domain Mismatches**: Test links from different domains
3. **Blocked URLs**: Test blacklist functionality
4. **Warning Types**: Test different warning scenarios
5. **Custom Display**: Test custom link text

See the main [README.md](../README.md) for complete documentation of the `detrackify_url.py` tool.

## Security Notes

- Always change the `guardsalt` to a secure random string
- Use `privacy: true` in production to avoid logging sensitive data
- Regularly update blocklists to protect against new threats
- Review domain aliases to ensure legitimate organizations are properly configured 