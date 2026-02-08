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
import re
from detrackify_email import Detrackify, Configuration


def main():
    """Entry point for command-line execution."""
    # Configure logging
    log_format = '%(asctime)s - %(levelname)7s - %(filename)s:%(lineno)3d - %(message)s'
    log_datefmt = '%Y-%m-%d %H:%M:%S'

    # Create argument parser
    parser = argparse.ArgumentParser(description='Process email and replace tracking URLs')

    # Add input file argument
    parser.add_argument('--input', help='Path to the input email file')
    parser.add_argument('--output', help='Path to the cleaned email file')
    parser.add_argument('--message-id', help='Log the message id we\'re processing')
    parser.add_argument('--verbose', help='Enable verbose logging', action='store_true')
    parser.add_argument('--debug', help='Enable early debug logging', action='store_true')
    parser.add_argument('--logfile', help='Save log instead of using stderr')
    parser.add_argument('--strip', help='Remove parameters for images (experimental)', action='store_true')
    parser.add_argument('--config', help='Path to the configuration file')
    parser.add_argument('--testurl', help='Detect which query parameters can be stripped from the URL (WARNING! Will make requests to the URLs)')
    parser.add_argument('--list', help='List all detected image URLs', action='store_true')
    parser.add_argument('--copy', help='Copy the original email to this folder for debugging')
    parser.add_argument('--whitelist-file', help='Path to whitelist YAML file (default: whitelist.yml)')
    parser.add_argument('--blacklist-file', help='Path to blacklist YAML file (default: blacklist.yml)')
    parser.add_argument('--domain-aliases-file', help='Path to domain aliases YAML file (default: domain_aliases.yml)')
    parser.add_argument('--guardserver', help='URL of the guard server (including scheme)')
    parser.add_argument('--guardsalt', help='Salt used for guarded links')
    parser.add_argument('--guardlink', choices=['off', 'mismatch', 'always'], help='Guard link mode')
    parser.add_argument('--guardcaptureto', action='store_true', help='Capture the To address in guarded links')
    parser.add_argument('--guardphishy', action='store_true', help='Enable phishing detection - guard all links when sender display name doesn\'t match email domain')
    parser.add_argument('--guard-add-html-for-plain', action='store_true', help='Generate HTML part from plain text emails when links need guarding')
    parser.add_argument('--guard-whitelist-file', help='Path to guard whitelist YAML file (default: guard_whitelist.yml)')
    parser.add_argument('--cache-file', help='Path to cache YAML file for persistent caching')
    parser.add_argument('--strip-param-prefix', action='append', default=[], help='Strip query parameters starting with PREFIX and everything after')
    parser.add_argument('--hardfail', action='store_true', help='Exit with error code on processing failures instead of passing through original email')

    # Parse command line arguments
    args = parser.parse_args()

    # Allow early debug logging
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug('Early debug logging enabled')

    # Configure logging
    if args.logfile:
        logging.basicConfig(
            level=logging.INFO,
            filename=args.logfile,
            format=log_format,
            datefmt=log_datefmt
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            datefmt=log_datefmt
        )

    # Initialize configuration
    config = Configuration()
    
    # Load configuration from YAML file if specified
    if args.config:
        if not config.load_from_yaml(args.config):
            logging.error(f'Error loading configuration file: {args.config}')
            sys.exit(1)
        else:
            logging.debug(f'Loaded configuration file: {args.config}')
    
    # Load configuration from command line arguments
    try:
        config.load_from_args(args)
    except ValueError as e:
        logging.error(f'Configuration error: {e}')
        sys.exit(1)
    
    # Set verbose logging if enabled
    if args.verbose or config.get(Configuration.CFG_VERBOSE):
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate guard configuration
    try:
        config.validate_guard_config()
    except ValueError as e:
        logging.error(f'Guard configuration error: {e}')
        sys.exit(1)

    # Initialize Detrackify
    detrack = Detrackify(config)
    
    try:
        if args.testurl:
            logging.info(f'Testing URL: {args.testurl}')
            detector = detrack.detector
            result = detector.detect_needed_rewrite(args.testurl, replace_1x1=True)
            logging.info(f'Returns image: {result}')
            if result != args.testurl:
                # Create rule for this
                logging.info(f'Add this rule to the configuration file:')
                if result is None:
                    logging.info(f'blacklist:')
                    logging.info(f'- {detector.strip_tracking_parameters(args.testurl)}.*')
                else:
                    logging.info(f'rewrite:')
                    logging.info(f'- from: {result}.*')
                    logging.info(f'  to: {result}')
            sys.exit(0)
        
        if args.message_id:
            logging.info(f'Processing message ID: {args.message_id}')
        
        if args.input and args.output:
            detrack.process_file(args.input, args.output, listonly=args.list, hardfail=args.hardfail)
        else:
            detrack.process(sys.stdin.buffer, sys.stdout.buffer, hardfail=args.hardfail)

        if config.get(Configuration.CFG_STRIP_ENABLE):
            config.save_learned(config.get(Configuration.CFG_STRIP_FILE))
        
        # Save cache if enabled
        if config.cache:
            config.save_cache()
            
    except Exception as e:
        # Catch-all for any exceptions
        logging.exception("Error: %s", e)
        sys.exit(1)
    
    sys.exit(0)


if __name__ == '__main__':
    main()
