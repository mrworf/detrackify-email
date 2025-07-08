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

## Docker

The Detrackify guard server is available as a Docker image from GitHub Container Registry:

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

# Or use Docker Compose from the docker/ directory
cd docker
docker-compose up -d
```

For complete Docker deployment instructions, configuration options, and production setup, see the [Docker documentation](docker/README.md).

## Known issues

- Will break DKIM since content and headers change, but this is expected.
- Doesn't handle elements contained within hidden elements

## Usage

`--input` and `--output` to run from command line, will also output information about what was blocked

`--message-id` to log the message id in the log output

`--verbose` enable debug logging

`--logfile` save logging to file instead of stderr

`--hardfail` instead of outputting unprocessed mail when an error occurs, it stops processing and exits with 1 (note that when run from command line, this is always the behavior)

`--stripquery` will remove any parameters attached to an image's URL, ie `https://www.shady-site.com/nice-logo.png?track=879384yutr93478` becomes `https://www.shady-site.com/nice-logo.png`. This is *experimental* and without this option the log will show what images it would strip. It's experimental because there's no guarantee that this won't break the image.
`--guardserver` specify address of the guard server used for rewriting links. Must include http or https.
`--guardsalt` specify salt used when creating guarded links. Must be at least 8 characters.
`--guardlink` link guarding mode: `off`, `mismatch`, or `always` (default `off`).
`--guardcaptureto` include the `To:` address in guarded links so the guard server can log who clicked.
`--guardwhitelink` regex of links that should never be rewritten (may be used multiple times).
`--guardwhitelistsender` regex of sender addresses that bypass link guarding (may be used multiple times).
`--guarddomainalias` owner domain and aliases in format "owner:alias1,alias2" (may be used multiple times, e.g., "instacart.com:instacartemail.com").
`--guarddomainaliasesfile` path to domain aliases YAML file (default: domain_aliases.yml).

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

## Blocklist Configuration

The blocklist system allows you to control which URLs and senders are allowed or blocked. This provides fine-grained control over email security by blocking known malicious sources and allowing trusted ones.

Both `detrackify_email.py` and `detrackify_guard.py` use a shared blocklist configuration file (`blocklist.yml` by default) to ensure consistency across the system.

### Blocklist File Format

The blocklist file uses YAML format with two main sections:

```yaml
# Whitelist entries - URLs that are always allowed
whitelist:
  - 'https://trusted.example.com/logo.png'
  - 'https://cdn.example.org/.*'

# Blacklist entries - URLs or senders that are blocked
blacklist:
  # Block specific sender email addresses
  - sender: '^spam@malicious\\.com$'
  - sender: '^test.*@example\\.org$'
  
  # Block specific URLs or domains
  - url: '^https://malicious\\.com/.*'
  - url: '^https://.*\\.phishing\\.net/.*'
  - url: '^https://tracking\\.example\\.com/.*'
```

### How Blocking Works

**In detrackify_email.py:**
- Sender blacklisting: If the email sender matches a blacklist pattern, all links in the email are sent to the guard server
- URL blacklisting: If any link in the email matches a blacklist pattern, it's sent to the guard server
- Whitelisting: URLs that match whitelist patterns are never processed or guarded

**In detrackify_guard.py:**
- URL blacklisting: If the original or resolved URL matches a blacklist pattern, the user sees a blocking message
- The blocking message explains why the site is blocked in child-friendly language
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
python detrackify_email.py --blocklistfile /path/to/blocklist.yml

# For detrackify_guard.py  
python detrackify_guard.py --blocklist-file /path/to/blocklist.yml
```

## Blocked Warnings Configuration

The blocked warnings feature allows you to completely block access to links that trigger specific types of warnings during URL resolution. Instead of showing a warning modal that users can acknowledge, these warnings result in a complete block with no option to proceed.

### Available Warning Types

The following warning types can be blocked:

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
block_warnings:
  - "ssl_certificate"      # Block links with SSL certificate issues
  - "connection_error"     # Block links that can't be reached
  - "too_many_redirects"   # Block links with suspicious redirect chains
```

**Command Line:**
```bash
python detrackify_guard.py --block-warnings ssl_certificate --block-warnings connection_error
```

### How It Works

When URL resolution detects a warning that's in the blocked warnings list:
1. The normal warning modal is not shown
2. Instead, the URL transition display shows "Access blocked:" instead of "Final destination:"
3. The blocked warning is displayed in the same format as normal warnings, with meaning, action, and optional "Learn more" link
4. No continue button is provided - access is completely denied
5. The specific warning reason and explanation are displayed in a user-friendly format

This provides an additional layer of security by preventing users from proceeding to potentially dangerous sites, while maintaining a familiar and informative user interface that explains why the link was blocked.

## Domain Aliases

Domain aliases allow you to specify that certain domains belong to the same organization. This is useful when companies use different domains for their email services. For example, Instacart uses `instacartemail.com` for emails but `instacart.com` for their main site.

Both `detrackify_email.py` and `detrackify_guard.py` use a shared domain aliases configuration file (`domain_aliases.yml` by default) to ensure consistency across the system.

### Domain Aliases File Format

The domain aliases file uses a simple key-value format:

```yaml
# Owner domain: list of aliases or single alias
instacart.com: [instacartemail.com]
amazon.com: [amazon-email.com, amazon-news.com, amazon-support.com]
google.com: google-email.com  # Single alias
microsoft.com: [outlook.com, hotmail.com, live.com]
```

### Configuration

**YAML Configuration:**
```yaml
options:
  guard:
    domain_aliases_file: domain_aliases.yml  # Path to aliases file
```

**Command Line:**
```bash
# For detrackify_email.py
python detrackify_email.py --domainaliasesfile /path/to/aliases.yml

# For detrackify_guard.py  
python detrackify_guard.py --domain-aliases-file /path/to/aliases.yml
```

### How It Works

When checking if a link should be guarded, the system:
1. Extracts the link domain and sender domain
2. Checks if they're the same domain (direct match)
3. Checks if they have a subdomain relationship
4. Checks if they're in the same alias group from the shared file
5. Only guards the link if none of these conditions are met (in `mismatch` mode)

This ensures that legitimate links from trusted domains (even if they use different domain names for email services) are not unnecessarily guarded, while still protecting against phishing attempts from unrelated domains.

## Ubuntu installation

Please use the following apt line instead of pip3

```
apt install python3-bs4 python3-pil
```

# EXIM configuration

This assumes you're somewhat comfortable with exim4's configuration.

## Adding a transport

```
detrackify:
  driver = pipe
  transport_filter = /opt/detrackify-email/detrackify_email.py --message-id ${message_id} --logfile /var/log/exim4/detrackify.log
  use_bsmtp
  command = /usr/sbin/exim4 -oMr detrackify -bS
  return_fail_output = true
  log_output = true
```

We run this as a transport filter, to allow us to manipulate the content. Then we use `exim` to redeliver it, while also ensuring it's tagged as `detrackify` so we can avoid an infinite loop.

Should the command fail, the sender will get an email back with the output from the command, ie, `exim4`.

## Adding a new router

```
detrackify_router:
  driver = accept
  domains = +local_domains
  local_parts = someuser
  condition = ${if !eq{$received_protocol}{detrackify}{yes}{no}}
  transport = detrackify
```

Setting `local_parts` to a local user allows you to test this on a single user, instead of doing it for all users. We also make sure we're testing how we received the email. If it came via exim4 (see transport), we don't want to process this email since it has already had a run.

Due to how this all works, it's **important** that you add the router BEFORE any local delivery agents (LDA), such as dovecot, etc. But it also needs to happen after any other massaging you're doing to the email, to avoid wasting cycles on this if the email is spam.

Ideally (and what I did) you put it 2nd to last, ie, right before your LDA.

## Confirming that it works

First of all, send yourself a message. If you've configured it correctly, you can check the `mainlog` for the following:

```
2024-09-09 04:04:47 1snTln-00000002pCO-24ge <= some@email.address.com U=Debian-exim P=detrackify S=85164 id=1006251088.8949486.1725847483059@address.com
2024-09-09 04:04:48 1snTln-00000002pCO-24ge => Me <my@email.com> R=virtual_user T=dovecot_lda
2024-09-09 04:04:48 1snTln-00000002pCO-24ge Completed
2024-09-09 04:04:48 1snTll-00000002pCL-3y1e => Me <my@email.com> R=detrackify_router T=detrackify
2024-09-09 04:04:48 1snTll-00000002pCL-3y1e Completed
```

Obviously there may be some differences, for example, if you don't use dovecot_lda, name of your routers, etc. but the gist of it should be very similar.

You can also open `detrackify.log` and you'll see an entry for each received email with the exim message id and any findings.

Next, look at the headers of your received email, there will be some new `X-Detrackify` headers, such as

```
X-Detrackify: Processed by Detrackify
```

If it removes tracking content, you'll see one or more entries like this:

```
X-Detrackify-Blocked: www.linkedin.com: =?utf-8?q?https=3A//www=2Elinkedin?=
    .... ?= (Size check 1x1)
```

# Thoughts

Does this mean that I'm finally free from the tracking that companies do? No, not really. Many companies leverage the fact that you like to see the styling and graphics of their email and more or less embed the tracking within. Ie, if you load that photo for the evite you got, you might very well be tracked as well.

However, it does minimize the footprint and if you do load the images, it will not load the distinct tracking items.

It's not unreasonable to try and "scramble" or even remove the parameters of some images in an attempt to further minmize the amount of tracking, but that's an exercise for a later day.
