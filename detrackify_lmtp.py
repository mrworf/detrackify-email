#!/usr/bin/env python3
#
# This program is free software: you can redistribute it and/or modify it under the terms
# of the GNU General Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

import argparse
import sys
import logging
from detrackify_email import Configuration
from detrackify_email.lmtp import run_lmtp_server


def main():
    """Entry point for the LMTP proxy server."""
    log_format = '%(asctime)s - %(levelname)7s - %(filename)s:%(lineno)3d - %(message)s'
    log_datefmt = '%Y-%m-%d %H:%M:%S'

    parser = argparse.ArgumentParser(
        description='Detrackify LMTP proxy - receive mail via LMTP, process, and forward downstream'
    )

    parser.add_argument('--config', help='Path to the YAML configuration file')
    parser.add_argument('--listen', help='Listen address: host:port or /path/to/socket (default: 127.0.0.1:10024)')
    parser.add_argument('--downstream', help='Downstream LMTP address: host:port or /path/to/socket')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--debug', action='store_true', help='Enable early debug logging')
    parser.add_argument('--logfile', help='Save log to file instead of stderr')

    parser.add_argument('--guardserver', help='URL of the guard server (including scheme)')
    parser.add_argument('--guardsalt', help='Salt used for guarded links')
    parser.add_argument('--guardlink', choices=['off', 'mismatch', 'always'], help='Guard link mode')
    parser.add_argument('--guardcaptureto', action='store_true', help='Capture the To address in guarded links')
    parser.add_argument('--guardphishy', action='store_true', help='Enable phishing detection')
    parser.add_argument('--guard-whitelist-file', help='Path to guard whitelist YAML file')

    parser.add_argument('--whitelist-file', help='Path to whitelist YAML file')
    parser.add_argument('--blacklist-file', help='Path to blacklist YAML file')
    parser.add_argument('--domain-aliases-file', help='Path to domain aliases YAML file')
    parser.add_argument('--cache-file', help='Path to cache YAML file for persistent caching')
    parser.add_argument('--strip-param-prefix', action='append', default=[], help='Strip query parameters starting with PREFIX')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug('Early debug logging enabled')

    if args.logfile:
        logging.basicConfig(level=logging.INFO, filename=args.logfile, format=log_format, datefmt=log_datefmt)
    else:
        logging.basicConfig(level=logging.INFO, format=log_format, datefmt=log_datefmt)

    config = Configuration()

    if args.config:
        if not config.load_from_yaml(args.config):
            logging.error('Error loading configuration file: %s', args.config)
            sys.exit(1)
        logging.debug('Loaded configuration file: %s', args.config)

    # Apply CLI overrides for LMTP-specific settings
    if args.listen:
        config.set(Configuration.CFG_LMTP_LISTEN, args.listen)
    if args.downstream:
        config.set(Configuration.CFG_LMTP_DOWNSTREAM, args.downstream)

    # Apply common detrackify CLI overrides (subset relevant to LMTP mode)
    if args.verbose:
        config.set(Configuration.CFG_VERBOSE, True)
    if args.guardserver:
        config.set(Configuration.CFG_GUARD_SERVER, args.guardserver)
    if args.guardsalt:
        config.set(Configuration.CFG_GUARD_SALT, args.guardsalt)
    if args.guardlink is not None:
        config.set(Configuration.CFG_GUARD_LINK, args.guardlink)
    if args.guardcaptureto:
        config.set(Configuration.CFG_GUARD_CAPTURE_TO, True)
    if args.guardphishy:
        config.set(Configuration.CFG_GUARD_PHISHY, True)
    if args.domain_aliases_file:
        config.set(Configuration.CFG_DOMAIN_ALIASES_FILE, args.domain_aliases_file)
        config.load_domain_aliases_from_file()
    if args.whitelist_file:
        config.set(Configuration.CFG_WHITELIST_FILE, args.whitelist_file)
        config.load_whitelist_from_file()
    if args.blacklist_file:
        config.set(Configuration.CFG_BLACKLIST_FILE, args.blacklist_file)
        config.load_blacklist_from_file()
    if args.guard_whitelist_file:
        config.set(Configuration.CFG_GUARD_WHITELIST_FILE, args.guard_whitelist_file)
        config.load_guard_whitelist_from_file()
    if args.cache_file:
        config.set(Configuration.CFG_CACHE_FILE, args.cache_file)
        config.load_cache_from_file()
    if args.strip_param_prefix:
        config.set(Configuration.CFG_STRIP_PARAM_PREFIX, args.strip_param_prefix)

    if args.verbose or config.get(Configuration.CFG_VERBOSE):
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        config.validate_guard_config()
    except ValueError as e:
        logging.error('Guard configuration error: %s', e)
        sys.exit(1)

    try:
        run_lmtp_server(config, foreground=True)
    except ValueError as e:
        logging.error('LMTP configuration error: %s', e)
        sys.exit(1)
    except Exception as e:
        logging.exception('LMTP server error: %s', e)
        sys.exit(1)


if __name__ == '__main__':
    main()
