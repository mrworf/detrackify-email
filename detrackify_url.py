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
"""Detrackify URL generator tool."""

import argparse
import base64
import hashlib
import json
import sys
import logging


def generate_guarded_url(server_url, salt, url, from_addr, to_addr=None, block_reason=None):
    """
    Generate a guarded URL for testing.
    
    Args:
        server_url: Base URL of the guard server (e.g., http://localhost:9090)
        salt: Guard salt for hash validation
        url: Target URL to guard
        from_addr: Sender email address
        to_addr: Optional recipient email address
        block_reason: Optional block reason (e.g., 'blacklisted')
    
    Returns:
        The complete guarded URL
    """
    # Create the payload
    payload = {
        'display': f'Link to {url}',
        'domain': from_addr.split('@')[-1] if '@' in from_addr else from_addr,
        'url': url,
    }
    
    # Add optional fields
    if to_addr:
        payload['to'] = to_addr
    if block_reason:
        payload['block'] = block_reason
    
    # Encode the payload
    b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    
    # Generate the hash
    sha = hashlib.sha256((b64 + salt).encode()).hexdigest()
    
    # Create the guarded URL
    guarded_url = f"{server_url.rstrip('/')}/guard/{sha}/{b64}"
    
    return guarded_url


def main():
    parser = argparse.ArgumentParser(
        description='Generate a guarded URL for testing with detrackify_guard.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python detrackify_url.py --server http://localhost:9090 --salt test123 --url https://example.com --from user@example.com
  
  # With recipient and block reason
  python detrackify_url.py --server http://localhost:9090 --salt test123 --url https://malicious.com --from spam@evil.com --to victim@company.com --block blacklisted
  
  # With custom display text (via --display)
  python detrackify_url.py --server http://localhost:9090 --salt test123 --url https://example.com --from user@example.com --display "Click here for special offer"
        """
    )
    
    parser.add_argument('--server', required=True, help='Guard server URL (e.g., http://localhost:9090)')
    parser.add_argument('--salt', required=True, help='Guard salt for hash validation')
    parser.add_argument('--url', required=True, help='Target URL to guard')
    parser.add_argument('--from', dest='from_addr', required=True, help='Sender email address')
    parser.add_argument('--to', dest='to_addr', help='Optional recipient email address')
    parser.add_argument('--block', help='Optional block reason (e.g., blacklisted)')
    parser.add_argument('--display', help='Optional display text (defaults to "Link to {url}")')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed information')
    
    args = parser.parse_args()
    
    # Configure logging for verbose output
    if args.verbose:
        logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    # Validate salt length
    if len(args.salt) < 8:
        sys.stderr.write("Error: Salt must be at least 8 characters long\n")
        sys.exit(1)
    
    # Create the payload
    payload = {
        'display': args.display or f'Link to {args.url}',
        'domain': args.from_addr.split('@')[-1] if '@' in args.from_addr else args.from_addr,
        'url': args.url,
    }
    
    # Add optional fields
    if args.to_addr:
        payload['to'] = args.to_addr
    if args.block:
        payload['block'] = args.block
    
    if args.verbose:
        logging.info("Payload:")
        logging.info(json.dumps(payload, indent=2))
        logging.info("")
    
    # Encode the payload
    b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    
    # Generate the hash
    sha = hashlib.sha256((b64 + args.salt).encode()).hexdigest()
    
    # Create the guarded URL
    guarded_url = f"{args.server.rstrip('/')}/guard/{sha}/{b64}"
    
    if args.verbose:
        logging.info("Base64 encoded payload:")
        logging.info(b64)
        logging.info("")
        logging.info("SHA256 hash:")
        logging.info(sha)
        logging.info("")
        logging.info("Guarded URL:")
    
    print(guarded_url)


if __name__ == '__main__':
    main() 