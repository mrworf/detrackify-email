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
from flask import Flask, abort, redirect, render_template, request, send_from_directory
from markupsafe import escape


class GuardServer:
    """Flask app handling guarded link redirects."""

    def __init__(self, salt, timeout=5, template_dir="templates", resource_dir=None, privacy=False):
        self.app = Flask(__name__, template_folder=template_dir)
        self.salt = salt
        self.timeout = timeout
        self.resource_dir = resource_dir
        self.privacy = privacy

        self.app.add_url_rule('/guard/<sha>/<data>', 'guard', self.guard,
                              methods=['GET', 'POST'])
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
                    f'<span class="highlight">{domain_part}</span>',
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
            url=highlight,
            ts=start,
            timeout_ms=self.timeout * 1000,
            valid=valid,
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
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    server = GuardServer(args.guardsalt, timeout=args.timeout,
                         template_dir=args.template_dir,
                         resource_dir=args.resource_dir,
                         privacy=args.privacy)
    if args.privacy:
        logging.info('Privacy Mode Enabled; no logging of email address, link, domain, or recipient will happen')
    server.app.run(host=args.listen_ip, port=args.listen_port)


if __name__ == '__main__':
    main()
