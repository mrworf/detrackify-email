#!/usr/bin/env python3
"""
Configuration validator CLI for Detrackify.

Usage:
  detrackify_config.py --validate PATH
"""

import argparse
import logging
import sys

from common.config_loader import load_config_sections


def validate_config(path: str) -> int:
    logging.basicConfig(level=logging.INFO)
    try:
        # load_config_sections logs warnings for issues
        common, email, guard = load_config_sections(path)
        # Basic success message
        logging.info("Validation OK")
        return 0
    except Exception as e:
        logging.error("Validation failed: %s", e)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Detrackify configuration validator")
    parser.add_argument('--validate', metavar='PATH', help='Path to YAML configuration to validate')
    args = parser.parse_args()

    if args.validate:
        return validate_config(args.validate)

    parser.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())


