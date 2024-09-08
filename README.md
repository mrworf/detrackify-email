# Detrackify

Processes standard emails and tries to determine what images within are used to track you. If found, it will replace them with a embedded 1x1 transparent pixel, thus retaining the formatting but preventing the pixel from reporting in.

## Features

- Handles both HTML and non-HTML (well, then there's no tracking either)
- Adds X-Detrackify headers for statistics and debugging
- Integrates with your MTA, allowing server based tracking prevention
- Failsafe, if tool fails for some reason, will revert to passthru of the email (configurable)

## Known issues

- Will break DKIM since content and headers change, but this is expected.
- Doesn't handle elements contained within hidden elements

## Usage

`--input` and `--output` to run from command line, will also output information about what was blocked

`--message-id` to log the message id in the log output

`--verbose` enable debug logging

`--logfile` save logging to file instead of stderr

`--hardfail` instead of outputting unprocessed mail when an error occurs, it stops processing and exits with 1 (note that when run from command line, this is always the behavior)

# EXIM configuration

Add new transport 

================ *UNTESTED* ======================

```
detrackify:
  driver = pipe
  command = /path/to/detrackify-email.py --message-id ${message_id} --logfile /var/log/detrackify.log
  user = testuser
  return_fail_output = true
  log_output = true
```

Add new router

```
detrackify_router:
  driver = accept
  domains = +local_domains
  local_parts = testuser
  transport = detrackify
```