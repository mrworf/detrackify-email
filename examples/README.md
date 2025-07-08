# Configuration Examples

This folder contains example configuration files for both the Detrackify email processor and the guard server.

## Email Processor Configurations

### `config_email.yml`
Main configuration file for `detrackify_email.py`. This file contains all the settings for processing emails and removing tracking pixels.

**Key sections:**
- `options.verbose`: Enable debug logging
- `options.strip`: Experimental URL parameter stripping
- `options.guard`: Link guarding configuration
- `domain_aliases_file`: Path to domain aliases file
- `whitelist_file`: Path to whitelist file
- `blocklist_file`: Path to blocklist file

## Guard Server Configurations

### `config_guard_server.yml`
Complete configuration file for the guard server (`detrackify_guard.py`) with all available options.

**Key settings:**
- `guardsalt`: Required salt for hash validation
- `listen_ip`/`listen_port`: Server binding
- `timeout`: Seconds before continue button activates
- `privacy`: Disable logging of visited links
- `resolve`: Link resolution mode (head/get)
- `strip_param_prefix`: URL parameters to strip

### `config_guard_server_simple.yml`
Minimal configuration for the guard server with only essential settings.

### `config_guard_server_with_aliases.yml`
Example configuration showing how to use domain aliases and blocklists with the guard server.

### `config_guard_server_with_blocked_warnings.yml`
Example configuration showing how to block specific warning types during URL resolution.

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

### `whitelist.yml` (Legacy)
Legacy whitelist format. Use `blocklist.yml` instead.

### `blacklist.yml` (Legacy)
Legacy blacklist format. Use `blocklist.yml` instead.

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

## Security Notes

- Always change the `guardsalt` to a secure random string
- Use `privacy: true` in production to avoid logging sensitive data
- Regularly update blocklists to protect against new threats
- Review domain aliases to ensure legitimate organizations are properly configured 