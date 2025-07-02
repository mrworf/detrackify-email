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
import requests
from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    send_from_directory,
    jsonify,
)
from markupsafe import escape


class ResolveCache:
    """Thread-safe cache for resolved URLs."""

    def __init__(self, max_entries=4096, max_age_days=30, path=None):
        self.lock = threading.Lock()
        self.data = {}
        self.max_entries = max_entries
        self.max_age = max_age_days * 24 * 3600
        self.path = path
        if path and os.path.isfile(path):
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    self.data = json.load(fh)
            except Exception:  # pylint: disable=broad-except
                logging.exception('Failed to load cache file')
                self.data = {}
        self.prune()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._maintenance_loop, daemon=True)
        self.thread.start()

    def _maintenance_loop(self):
        while not self.stop.wait(24 * 3600):
            self.prune()
            self.save()

    def prune(self):
        now = time.time()
        with self.lock:
            keys = [k for k, v in self.data.items() if now - v.get('ts', 0) > self.max_age]
            for k in keys:
                self.data.pop(k, None)

    def get(self, key):
        with self.lock:
            return self.data.get(key)

    def set(self, key, url):
        entry = {'url': url, 'ts': time.time()}
        with self.lock:
            self.data[key] = entry
            if len(self.data) > self.max_entries:
                oldest = min(self.data.items(), key=lambda item: item[1]['ts'])[0]
                self.data.pop(oldest, None)

    def save(self):
        if not self.path:
            return
        try:
            with self.lock, open(self.path, 'w', encoding='utf-8') as fh:
                json.dump(self.data, fh)
        except Exception:  # pylint: disable=broad-except
            logging.exception('Failed to save cache file')

    def close(self):
        self.stop.set()
        self.thread.join(timeout=1)
        self.save()


class GuardServer:
    """Flask app handling guarded link redirects."""

    def __init__(self, salt, timeout=5, template_dir="templates", resource_dir=None,
                 privacy=False, resolve=False, cache_file=None, cache_days=30, cache_max=4096):
        self.app = Flask(__name__, template_folder=template_dir)
        self.salt = salt
        self.timeout = timeout
        self.resource_dir = resource_dir
        self.privacy = privacy
        self.resolve_enabled = resolve
        self.cache = ResolveCache(cache_max, cache_days, cache_file) if resolve else None

        self.app.add_url_rule('/guard/<sha>/<data>', 'guard', self.guard,
                              methods=['GET', 'POST'])
        if resolve:
            self.app.add_url_rule('/guard/resolve', 'resolve', self.resolve_link,
                                  methods=['POST'])
            self.app.add_url_rule('/guard/go', 'go', self.go, methods=['POST'])
        self.app.add_url_rule('/guard/common.js', 'common_js',
                              lambda: send_from_directory(self.app.template_folder, 'common.js'))
        self.app.add_url_rule('/guard/common.css', 'common_css',
                              lambda: send_from_directory(self.app.template_folder, 'common.css'))
        if resource_dir:
            self.app.add_url_rule('/resource/<path:filename>', 'resource',
                                  self.resource, methods=['GET'])

    def choose_template(self, accept_language):
        """Return best template name based on Accept-Language header."""
        if not isinstance(accept_language, str):
            accept_language = ''
        langs = []
        for part in accept_language.split(','):
            part = part.strip()
            if not part:
                continue
            try:
                lang = part.split(';')[0].strip().lower()
                langs.append(lang)
            except Exception:  # pylint: disable=broad-except
                # Skip malformed language entries rather than failing
                continue
        for lang in langs:
            code = lang.split('-')[0]
            candidate = f'guard_warning_{code}.html'
            if os.path.isfile(os.path.join(self.app.template_folder, candidate)):
                return candidate
        return 'guard_warning.html'

    def check_hash(self, sent_sha, payload):
        """Validate hash for payload."""
        calc = hashlib.sha1((payload + self.salt).encode()).hexdigest()
        return calc == sent_sha

    def resource(self, filename):
        """Serve optional resource files."""
        if not self.resource_dir:
            abort(404)
        path = os.path.join(self.resource_dir, filename)
        if not os.path.isfile(path):
            logging.warning("Resource not found: %s", filename)
            abort(404)
        ext = os.path.splitext(filename)[1].lower()
        if not ext:
            logging.warning("Requested resource without extension: %s", filename)
            abort(404)
        if ext not in ('.png', '.jpg', '.jpeg', '.gif', '.ico'):
            logging.warning("Disallowed resource type requested: %s", filename)
            abort(404)
        return send_from_directory(self.resource_dir, filename)

    def resolve_link(self):
        """Return the final destination of a guarded link."""
        if not self.resolve_enabled:
            abort(404)
        try:
            payload = request.get_json(force=True)
        except Exception:  # pylint: disable=broad-except
            return jsonify({'error': 'invalid request'}), 400
        sha = str(payload.get('sha', ''))
        data = str(payload.get('data', ''))
        if not sha or not data or not self.check_hash(sha, data):
            return jsonify({'error': 'forbidden'}), 403
        b64_sha = hashlib.sha1(data.encode()).hexdigest()
        key = hashlib.sha1((data + b64_sha).encode()).hexdigest()
        entry = self.cache.get(key) if self.cache else None
        if entry:
            url = entry['url']
        else:
            try:
                decoded = base64.urlsafe_b64decode(data).decode()
                info = json.loads(decoded)
                target = info.get('url', '')
            except Exception:  # pylint: disable=broad-except
                return jsonify({'error': 'invalid payload'}), 400
            url = target
            try:
                resp = requests.head(target, allow_redirects=True, timeout=self.timeout)
                url = resp.url
            except Exception as exc:  # pylint: disable=broad-except
                logging.exception('Failed to resolve %s', target)
                return jsonify({'error': str(exc)}), 500
            if self.cache:
                self.cache.set(key, url)
        result_sha = hashlib.sha1((url + self.salt).encode()).hexdigest()
        return jsonify({'url': url, 'hash': result_sha}), 200

    def go(self):
        """Redirect using a resolved URL."""
        if not self.resolve_enabled:
            abort(404)
        url = request.form.get('url', '')
        sha = request.form.get('sha', '')
        try:
            start = float(request.form.get('ts', '0'))
        except ValueError:
            start = 0.0
        if not url or hashlib.sha1((url + self.salt).encode()).hexdigest() != sha:
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
        sha = str(sha or '')
        data = str(data or '')
        if not sha or not data:
            logging.warning("Missing SHA or data")
            abort(404)
        if not self.check_hash(sha, data):
            logging.warning("Hash mismatch for %s", sha)
            abort(404)
        try:
            decoded = base64.urlsafe_b64decode(data).decode()
            info = json.loads(decoded)
        except Exception:  # pylint: disable=broad-except
            logging.exception("Invalid payload")
            abort(404)

        if request.method == 'POST':
            try:
                start = float(request.form.get('ts', '0'))
            except ValueError:
                start = 0.0
            elapsed = time.time() - start
            if not self.privacy:
                if elapsed < self.timeout:
                    logging.warning("Link activated too quickly: %.2fs < %ds", elapsed, self.timeout)
                else:
                    display = ' '.join(str(info.get('display', '')).split())
                    if info.get('to'):
                        logging.info(
                            "Redirecting to %s (%s) for %s after %.2fs",
                            info.get('url'),
                            display,
                            info.get('to'),
                            elapsed,
                        )
                    else:
                        logging.info(
                            "Redirecting to %s (%s) after %.2fs",
                            info.get('url'),
                            display,
                            elapsed,
                        )
            resp = redirect(info.get('url'), code=302)
            resp.headers['Referrer-Policy'] = 'no-referrer'
            return resp

        start = time.time()
        url = info.get('url', '')
        # Escape URL before displaying to avoid control characters or HTML
        escaped_url = str(escape(url))
        valid = bool(url)
        if valid:
            match = re.search(r'https?://([^/]+)', url)
            if match:
                domain_part = escape(match.group(1))
                highlight = escaped_url.replace(
                    match.group(1),
                    f'<span class="highlight bad">{domain_part}</span>',
                    1,
                )
            else:
                highlight = escaped_url
        else:
            highlight = 'Missing or invalid URL'
        template = self.choose_template(request.headers.get('Accept-Language'))
        return render_template(
            template,
            display=escape(info.get('display') or '** No link text provided **'),
            domain=escape(info.get('domain') or '** No domain provided **'),
            sender_domain=info.get('domain') or '',
            url=highlight,
            ts=start,
            timeout_ms=self.timeout * 1000,
            valid=valid,
            resolve=self.resolve_enabled,
            sha=sha,
            data=data,
        )


def main():
    parser = argparse.ArgumentParser(description='Detrackify guard server')
    parser.add_argument('--listen-ip', default='0.0.0.0', help='Listen IP')
    parser.add_argument('--listen-port', default=9090, type=int, help='Listen port')
    parser.add_argument('--guardsalt', required=True, help='Guard salt')
    parser.add_argument('--template-dir', default='templates', help='Template directory')
    parser.add_argument('--resource-dir', help='Directory for additional resources')
    parser.add_argument('--timeout', type=int, default=5,
                        help='Seconds before continue button activates')
    parser.add_argument('--privacy', action='store_true',
                        help='Disable logging of visited links')
    parser.add_argument('--resolve', action='store_true',
                        help='Resolve final destination before allowing continue')
    parser.add_argument('--resolve-cache-file', help='Path to JSON cache file')
    parser.add_argument('--resolve-cache-days', type=int, default=30,
                        help='Days to keep resolve results (default 30)')
    parser.add_argument('--resolve-cache-max', type=int, default=4096,
                        help='Maximum number of cached entries (default 4096)')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    server = GuardServer(
        args.guardsalt,
        timeout=args.timeout,
        template_dir=args.template_dir,
        resource_dir=args.resource_dir,
        privacy=args.privacy,
        resolve=args.resolve,
        cache_file=args.resolve_cache_file,
        cache_days=args.resolve_cache_days,
        cache_max=args.resolve_cache_max,
    )
    if args.privacy:
        logging.info('Privacy Mode Enabled; no logging of email address, link, domain, or recipient will happen')
    if args.resolve:
        atexit.register(server.cache.close)
    server.app.run(host=args.listen_ip, port=args.listen_port)


if __name__ == '__main__':
    main()
