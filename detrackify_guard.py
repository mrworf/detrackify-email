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
"""Detrackify guard server."""

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import time
import threading
import atexit
import urllib.parse

import requests
import yaml
from bs4 import BeautifulSoup
from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    send_from_directory,
    jsonify,
    make_response,
)
from markupsafe import escape

from guard.config import GuardConfig
from guard.resolve_cache import ResolveCache
from guard.blacklist import Blacklist
from guard.utils import GuardUtils
from common.utils import SharedUtils
from common.alias import DomainAliases


class GuardServer:
    """Flask app handling guarded link redirects."""

    def __init__(self, config: GuardConfig):
        self.cfg = config
        self.app = Flask(__name__, template_folder=config.template_dir)
        # Force template reloading in development
        self.app.config['TEMPLATES_AUTO_RELOAD'] = True
        self.salt = config.salt
        self.timeout = config.timeout
        self.resource_dir = config.resource_dir
        self.privacy = config.privacy
        self.resolve_enabled = config.resolve is not None
        self.resolve_get = config.resolve == 'get'
        self.strip_prefixes = list(config.strip_param_prefixes)
        self.user_agent = config.user_agent
        self.force_language = config.force_language
        self.domain_aliases = DomainAliases(config.domain_aliases_file)
        self.blocklist = Blacklist(config.blacklist_file)
        self.deny_on_warnings = config.deny_on_warnings
        self.auto_redirect = config.auto_redirect
        self.cache = (
            ResolveCache(config.cache_max, config.cache_days, config.cache_file)
            if self.resolve_enabled
            else None
        )

        self.app.add_url_rule('/guard/<sha>/<data>', 'guard', self.guard,
                              methods=['GET', 'POST'])
        if self.resolve_enabled:
            self.app.add_url_rule('/guard/resolve', 'resolve', self.resolve_link,
                                  methods=['POST'])
            self.app.add_url_rule('/guard/go', 'go', self.go, methods=['POST'])
        self.app.add_url_rule('/guard/common.js', 'common_js', self.common_js)
        self.app.add_url_rule('/guard/opts.js', 'opts_js', self.opts_js)
        self.app.add_url_rule('/guard/common.css', 'common_css',
                              lambda: send_from_directory(self.app.template_folder, 'common.css', max_age=0))
        self.app.add_url_rule('/guard/health', 'health', self.health_check)
        if config.resource_dir:
            self.app.add_url_rule('/resource/<path:filename>', 'resource',
                                  self.resource, methods=['GET'])
        
        # Register the after_request handler
        self.app.after_request(self.add_security_headers)

    def strip_query_params(self, url: str) -> str:
        """Strip query parameters based on configured prefixes."""
        return SharedUtils.strip_query_parameters(url, self.strip_prefixes)

    def add_security_headers(self, response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        return response

    def choose_template(self, accept_language):
        """Return best template name based on Accept-Language header."""
        # Force specific language if debug option is set
        if self.force_language:
            # Validate language code format to prevent path traversal
            if not SharedUtils.validate_language_code(self.force_language):
                logging.warning("Invalid language code: %s", self.force_language)
                return 'guard_warning.html'
            
            candidate = f'guard_warning_{self.force_language}.html'
            # Validate template path
            template_path = os.path.join(self.app.template_folder, candidate)
            if not GuardUtils.validate_path_security(candidate, self.app.template_folder):
                logging.warning("Template path traversal attempt: %s", self.force_language)
                return 'guard_warning.html'
            
            if os.path.isfile(template_path):
                return candidate
            logging.warning("Forced language template not found: %s", candidate)
            return 'guard_warning.html'
        
        langs = SharedUtils.parse_accept_language(accept_language)
        for lang in langs:
            code = lang.split('-')[0]
            # Validate language code format
            if not SharedUtils.validate_language_code(code):
                continue
            candidate = f'guard_warning_{code}.html'
            if os.path.isfile(os.path.join(self.app.template_folder, candidate)):
                return candidate
        return 'guard_warning.html'


    def resource(self, filename):
        """Serve optional resource files."""
        if not self.resource_dir:
            abort(404)
        
        # Validate path security
        if not GuardUtils.validate_path_security(filename, self.resource_dir):
            logging.warning("Path traversal attempt: %s", filename)
            abort(404)
        
        path = os.path.join(self.resource_dir, filename)
        if not os.path.isfile(path):
            logging.warning("Resource not found: %s", filename)
            abort(404)
        
        # Validate file extension
        if not GuardUtils.validate_file_extension(filename):
            logging.warning("Disallowed resource type requested: %s", filename)
            abort(404)
        
        return send_from_directory(self.resource_dir, filename)

    def health_check(self):
        """Health check endpoint for monitoring."""
        return jsonify({'status': 'healthy', 'timestamp': time.time()}), 200

    def common_js(self):
        """Serve the shared JavaScript (minified if available)."""
        # Try to serve minified version first
        minified_path = os.path.join(self.app.template_folder, 'common.min.js')
        if os.path.exists(minified_path):
            return send_from_directory(self.app.template_folder, 'common.min.js', max_age=86400)
        else:
            # Fallback to original version
            return send_from_directory(self.app.template_folder, 'common.js', max_age=86400)

    def opts_js(self):
        """Serve dynamic JavaScript with per-request options."""
        referer = request.headers.get('Referer') or ''
        components = SharedUtils.parse_guard_url(referer)
        sha = components['sha'] if components else ''
        data = components['data'] if components else ''
        sender = ''
        block_reason = ''
        valid = sha and data and SharedUtils.verify_hash(data, self.salt, sha)
        if valid:
            try:
                decoded = base64.urlsafe_b64decode(data).decode()
                info = json.loads(decoded)
                
                # Extract domain from the 'from' email address
                from_email = info.get('from', '')
                sender = ''
                if from_email and '@' in from_email:
                    sender = from_email.split('@')[-1]
                
                # For backward compatibility, also check old 'domain' field
                if not sender:
                    sender = info.get('domain', '')
                
                block_reason = info.get('block', '')
                logging.debug(f'opts_js: from_email = "{from_email}", sender_domain = "{sender}", block_reason = "{block_reason}" (type: {type(block_reason)})')
            except Exception:  # pylint: disable=broad-except
                valid = False
        opts = {
            'resolve': self.resolve_enabled,
            'timeout_ms': self.timeout * 1000,
            'sha': sha if valid else '',
            'data': data if valid else '',
            'sender_domain': sender if valid else '',
            'block_reason': block_reason,
            'deny_on_warnings': self.deny_on_warnings,
            'auto_redirect': self.auto_redirect,
        }
        logging.debug(f'opts_js: sending opts = {opts}')
        resp = make_response(render_template('opts.js', opts=opts))
        resp.headers['Content-Type'] = 'application/javascript'
        resp.headers['Cache-Control'] = 'no-store'
        return resp

    def resolve_link(self):
        """Return the final destination of a guarded link."""
        if not self.resolve_enabled:
            abort(404)
        try:
            payload = request.get_json(force=True)
        except Exception:  # pylint: disable=broad-except
            abort(400)
        sha = str(payload.get('sha', ''))
        data = str(payload.get('data', ''))
        if not sha or not data or not SharedUtils.verify_hash(data, self.salt, sha):
            abort(403)
        b64_sha = SharedUtils.generate_hash(data, '')
        key = SharedUtils.generate_hash(data + b64_sha, '')
        entry = self.cache.get(key) if self.cache else None
        resolution_warning = None  # Initialize here for all code paths
        
        # Decode the payload early so info is available in all code paths
        info = SharedUtils.decode_base64_payload(data)
        if not info:
            abort(400)
            
        if entry:
            url = entry['url']
            title = entry.get('title', '')
            resolution_warning = entry.get('warning')  # Retrieve warning from cache
            # Check if the cached warning should be blocked
            if resolution_warning and self.deny_on_warnings:
                warning_type = resolution_warning.split(':', 1)[0] if ':' in resolution_warning else resolution_warning
                if warning_type in self.deny_on_warnings:
                    block_reason = f'warning_blocked:{warning_type}'
        else:
            target_url = info.get('url', '')
            if not SharedUtils.is_safe_url(target_url):
                logging.warning("Unsafe URL in payload: %s", target_url)
                abort(400)
            target = SharedUtils.strip_query_parameters(target_url, self.strip_prefixes)
            url = target
            title = ''
            try:
                # Create a new session for each request to ensure no cookies are persisted
                session = requests.Session()
                session.headers.update({'User-Agent': self.user_agent})
                
                # Disable cookie persistence
                session.cookies.clear()
                
                if self.resolve_get:
                    resp = session.get(target, allow_redirects=True, timeout=self.timeout)
                    url = SharedUtils.strip_query_parameters(resp.url, self.strip_prefixes)
                    try:
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        if soup.title and soup.title.string:
                            title = soup.title.string.strip()
                    except Exception:  # pylint: disable=broad-except
                        pass
                else:
                    resp = session.head(target, allow_redirects=True, timeout=self.timeout)
                    url = SharedUtils.strip_query_parameters(resp.url, self.strip_prefixes)
                    
                # Clear any cookies that might have been set during the request
                session.cookies.clear()
                session.close()
                
            except requests.exceptions.SSLError as ssl_exc:
                # SSL certificate verification failed - log warning but try to get final destination
                logging.warning('SSL certificate verification failed for %s: %s', target, str(ssl_exc))
                try:
                    # Try to follow redirects manually to get the final destination
                    # This bypasses SSL verification but still gets the final URL
                    session = requests.Session()
                    session.headers.update({'User-Agent': self.user_agent})
                    session.cookies.clear()
                    
                    # Disable SSL verification for this request only
                    session.verify = False
                    
                    if self.resolve_get:
                        resp = session.get(target, allow_redirects=True, timeout=self.timeout)
                        url = SharedUtils.strip_query_parameters(resp.url, self.strip_prefixes)
                        try:
                            soup = BeautifulSoup(resp.text, 'html.parser')
                            if soup.title and soup.title.string:
                                title = soup.title.string.strip()
                        except Exception:  # pylint: disable=broad-except
                            pass
                    else:
                        resp = session.head(target, allow_redirects=True, timeout=self.timeout)
                        url = SharedUtils.strip_query_parameters(resp.url, self.strip_prefixes)
                    
                    session.cookies.clear()
                    session.close()
                    resolution_warning = 'ssl_certificate:This website has security certificate issues'
                except Exception as fallback_exc:
                    # If even the fallback fails, use the original URL
                    logging.warning('Fallback resolution also failed for %s: %s', target, str(fallback_exc))
                    url = target
                    title = ''
                    resolution_warning = 'ssl_certificate:This website has security certificate issues and could not be reached'
                
            except requests.exceptions.ConnectionError as conn_exc:
                # Connection errors (DNS, network, etc.) - log warning but continue
                logging.warning('Connection error resolving %s: %s', target, str(conn_exc))
                url = target
                title = ''
                resolution_warning = 'connection_error:Connection error'
                
            except requests.exceptions.Timeout as timeout_exc:
                # Timeout errors - log warning but continue
                logging.warning('Timeout resolving %s: %s', target, str(timeout_exc))
                url = target
                title = ''
                resolution_warning = 'connection_timeout:Connection timeout'
                
            except requests.exceptions.TooManyRedirects as redirect_exc:
                # Too many redirects - log warning but continue
                logging.warning('Too many redirects for %s: %s', target, str(redirect_exc))
                url = target
                title = ''
                resolution_warning = 'too_many_redirects:Too many redirects'
                
            except requests.exceptions.RequestException as req_exc:
                # Other request-related errors - log warning but continue
                logging.warning('Request error resolving %s: %s', target, str(req_exc))
                url = target
                title = ''
                resolution_warning = 'request_error:Request error'
                
            except Exception as exc:  # pylint: disable=broad-except
                # Unexpected errors - log error but continue with original URL
                logging.exception('Unexpected error resolving %s', target)
                url = target
                title = ''
                resolution_warning = 'unexpected_error:Unexpected error'
            if self.cache:
                self.cache.set(key, url, title, resolution_warning)
        # Check if the resolved URL is blacklisted
        block_reason = None
        if self.blocklist.is_url_blacklisted(url):
            block_reason = 'blacklisted'
        
        # Check if the warning should be blocked
        if resolution_warning:
            warning_type = resolution_warning.split(':', 1)[0] if ':' in resolution_warning else resolution_warning
            if warning_type in self.deny_on_warnings:
                block_reason = f'warning_blocked:{warning_type}'
        
        # Check if the resolved URL domain matches the sender domain
        url_domain = SharedUtils.extract_domain_from_url(url)
        
        # Extract domain from the 'from' email address for domain matching
        from_email = info.get('from', '')
        sender_domain = ''
        if from_email and '@' in from_email:
            sender_domain = from_email.split('@')[-1]
        
        # For backward compatibility, also check old 'domain' field
        if not sender_domain:
            sender_domain = info.get('domain', '')
        
        domains_match = False
        if url_domain and sender_domain:
            domains_match = self.domain_aliases.are_aliases(url_domain, sender_domain)
            logging.debug(f'Domain match check: {url_domain} vs {sender_domain} = {domains_match}')
        
        result_sha = SharedUtils.generate_hash(url, self.salt)
        original_normalized = SharedUtils.strip_query_parameters(
            info.get('url', ''), self.strip_prefixes
        )
        response_data = {
            'url': url,
            'hash': result_sha,
            'title': title,
            'domains_match': domains_match
        }
        if original_normalized and original_normalized != url:
            response_data['original_url'] = original_normalized
            response_data['original_hash'] = SharedUtils.generate_hash(
                original_normalized, self.salt
            )
        if block_reason:
            response_data['block'] = block_reason
        if resolution_warning:
            response_data['warning'] = resolution_warning
        
        # Store block reason in cache if caching is enabled
        if self.cache and entry is None:  # Only store if this was a fresh resolution
            self.cache.set(key, url, title, resolution_warning, block_reason)
        return jsonify(response_data), 200

    def go(self):
        """Redirect using a resolved URL."""
        if not self.resolve_enabled:
            abort(404)
        url = SharedUtils.strip_query_parameters(request.form.get('url', ''), self.strip_prefixes)
        sha = request.form.get('sha', '')
        try:
            start = float(request.form.get('ts', '0'))
        except ValueError:
            start = 0.0
        if not url or SharedUtils.generate_hash(url, self.salt) != sha:
            abort(404)
        elapsed = time.time() - start
        if not self.privacy:
            if elapsed < self.timeout:
                logging.warning("Link activated too quickly: %.2fs < %ds", elapsed, self.timeout)
            else:
                logging.info("Redirecting to %s after %.2fs", url, elapsed)
        resp = redirect(url, code=302)
        resp.headers['Referrer-Policy'] = 'no-referrer'
        return resp

    def guard(self, sha, data):
        # Use the centralized guard link verification
        info = SharedUtils.verify_guard_link(f"/guard/{sha}/{data}", self.salt)
        if not info:
            logging.warning("Invalid guard link: %s", sha)
            abort(404)

        if request.method == 'POST':
            try:
                start = float(request.form.get('ts', '0'))
            except ValueError:
                start = 0.0
            elapsed = time.time() - start
            target_url = SharedUtils.strip_query_parameters(info.get('url'), self.strip_prefixes)
            if not self.privacy:
                if elapsed < self.timeout:
                    logging.warning("Link activated too quickly: %.2fs < %ds", elapsed, self.timeout)
                else:
                    display = ' '.join(str(info.get('display', '')).split())
                    if info.get('to'):
                        logging.info(
                            "Redirecting to %s (%s) for %s after %.2fs",
                            target_url,
                            display,
                            info.get('to'),
                            elapsed,
                        )
                    else:
                        logging.info(
                            "Redirecting to %s (%s) after %.2fs",
                            target_url,
                            display,
                            elapsed,
                        )
            resp = redirect(target_url, code=302)
            resp.headers['Referrer-Policy'] = 'no-referrer'
            return resp

        start = time.time()
        url = SharedUtils.strip_query_parameters(info.get('url', ''), self.strip_prefixes)
        valid = bool(url)
        if not valid:
            abort(404)

        # Check for block reason in the original payload
        block_reason = info.get('block', '')
        
        # Also check if the URL itself is blacklisted
        if self.blocklist.is_url_blacklisted(url):
            block_reason = 'blacklisted'
        
        # Extract domain from the 'from' email address for backward compatibility
        from_email = info.get('from', '')
        sender_domain = ''
        if from_email and '@' in from_email:
            sender_domain = from_email.split('@')[-1]
        
        # For backward compatibility, also check old 'domain' field
        if not sender_domain:
            sender_domain = info.get('domain', '')
        
        template = self.choose_template(request.headers.get('Accept-Language'))
        context = {
            'display': escape(info.get('display') or '** No link text provided **'),
            'domain': escape(sender_domain or '** No domain provided **'),
            'sender_domain': sender_domain,
            'sender_email': escape(from_email),
            'sender_display': escape(info.get('sender_display') or ''),
            'url': url,
            'ts': start,
            'timeout_ms': self.timeout * 1000,
            'block_reason': block_reason,
            'resolve': self.resolve_enabled,
            'deny_on_warnings': self.deny_on_warnings,
            'auto_redirect': self.auto_redirect,
        }
        return render_template(template, **context)


def main():
    parser = argparse.ArgumentParser(description='Detrackify guard server')
    parser.add_argument('--config', '-c', help='Path to YAML configuration file')
    parser.add_argument('--listen-ip', default=None, help='Listen IP')
    parser.add_argument('--listen-port', default=None, type=int, help='Listen port')
    parser.add_argument('--salt', help='Salt for hash validation')
    parser.add_argument('--template-dir', default=None, help='Template directory')
    parser.add_argument('--resources-dir', default=None, help='Directory for additional resources')
    parser.add_argument('--timeout', type=int, default=None,
                        help='Seconds before continue button activates')
    parser.add_argument('--privacy', action='store_true',
                        help='Disable logging of visited links')
    parser.add_argument('--resolve', choices=['head', 'get'], default=None,
                        help='Resolve final destination using HEAD or GET requests')
    parser.add_argument('--resolve-cache-file', default=None, help='Path to JSON cache file')
    parser.add_argument('--resolve-cache-days', type=int, default=None,
                        help='Days to keep resolve results (default 30)')
    parser.add_argument('--resolve-cache-max', type=int, default=None,
                        help='Maximum number of cached entries (default 4096)')
    parser.add_argument('--strip-param-prefix', action='append', default=None,
                        help='Strip query parameters starting with PREFIX and everything after')
    parser.add_argument('--user-agent', 
                        default=None,
                        help='User-Agent string for link resolution requests (default: Chrome browser)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode with template auto-reload (command line only)')
    parser.add_argument('--force-language', 
                        help='Force serving a specific language template (e.g., de, es, fr, zh, ar) (command line only)')
    parser.add_argument('--domain-aliases-file', 
                        help='Path to domain aliases YAML file (default: domain_aliases.yml)')
    parser.add_argument('--blacklist-file', 
                        help='Path to blacklist YAML file (default: blacklist.yml)')
    parser.add_argument('--deny-on-warnings', action='append', default=None,
                        help='Deny access for specific warnings (e.g., ssl_certificate, connection_error)')
    parser.add_argument('--auto-redirect', action='store_true',
                        help='Automatically redirect if resolved link matches sender domain')
    args = parser.parse_args()

    # Set logging level based on debug flag
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level)

    try:
        # Create configuration from YAML file and command line arguments
        config = GuardConfig.from_args(args, args.config)
        config.validate()
    except Exception as e:
        logging.error("Configuration error: %s", e)
        return 1

    server = GuardServer(config)
    if config.debug:
        server.app.config['DEBUG'] = True
        server.app.config['TEMPLATES_AUTO_RELOAD'] = True
    if config.privacy:
        logging.info('Privacy Mode Enabled; no logging of email address, link, domain, or recipient will happen')
    if config.resolve:
        atexit.register(server.cache.close)
    server.app.run(host=config.listen_ip, port=config.listen_port)


if __name__ == '__main__':
    main()
