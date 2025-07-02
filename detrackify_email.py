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

import datetime
import os
import quopri
import re
import base64
from email import policy
from email.parser import BytesParser
from email.generator import BytesGenerator
from bs4 import BeautifulSoup
import argparse
import sys
import logging 
from PIL import Image
import yaml
import json
import hashlib
from io import BytesIO
import email.utils
import requests

class Detector:
    def __init__(self, config):
        self.config = config

    def strip_tracking_parameters(self, url):
        result = None
        # Images typically don't have query parameters, so let's strip them if they exist
        match = re.search(r'(https?:\/\/[^?]+)(\??.*)', url)
        if match:
            if match.group(2) and match.group(2) != '':
                #logging.debug(f'Stripped: {url} -> {match.group(1)}')
                result = match.group(1)
        else:
            logging.warning(f'URL does not confirm: {url}')
        return result

    def detect_needed_rewrite(self, url, replace_1x1=False):
        # Check if the URL contains a query string
        ret = {'url': url, 'reason': []}
        match = re.search(r'(https?:\/\/[^?]+)(\??.*)', url)
        if match:
            if match.group(2) and match.group(2) != '':
                logging.debug(f'Query string detected: {url} -> {match.group(1)} ({match.group(2)})')
                # Break up the query string into parts
                query = match.group(2)[1:] # Skip the question mark
                parts = query.split('&')

                # Blank the last part, this stops us from doing a complete HTTP GET of the (potentially) tracking URL
                # This doesn't guarantee they won't track us anyway, but at least we try to avoid it.
                parts[-1] = ''

                # Reconstruct the URL without the query string
                result = f'{match.group(1)}?'
                while len(parts) > 0:
                    findings = self.interrogate_url(result[:-1])
                    if findings:
                        # Check if the image is 1x1
                        if findings['width'] <= 1 and findings['height'] <= 1:
                            ret['reason'].append('Tracker')
                        ret['url'] = findings['url'] # Allows us to use the final destination directly
                        ret['reason'].extend(findings['detected'])
                        return ret
                    result += f'{parts.pop(0)}&'
                ret = None
        else:
            logging.warning(f'URL does not confirm: {url}')
        return ret

    def interrogate_url(self, url):
        """
        Will attempt to connect to the URL to see if it returns an image

        Returns a dict
        """
        result = {
            'width': -1,
            'height': -1,
            'detected': [],
            'url': url
        }

        try:
            req = requests.get(url, stream=True, timeout=3, allow_redirects=self.config.get(Configuration.CFG_STRIP_REDIRECT)) # Only wait 3s for a response
            if req.status_code == 200:
                if req.cookies:
                    logging.debug(f'URL {url} returns cookies, so it is going to be a tracking device')
                    result['detected'].append('Cookies')
                if req.history:
                    logging.debug(f'Request was redirected, intermediate URLs:')
                    for r in req.history:
                        logging.debug(f'  - {r.url}')
                    logging.debug(f'Final URL: {req.url}')
                    result['detected'].append('Redirect')
                    result['url'] = req.url # Update to the final one
                
                # So far so good, check mimetype
                if 'image' in req.headers['Content-Type']:
                    # Read image so we can determine dimensions
                    # Read the image data
                    image = Image.open(BytesIO(req.content))
                    result['width'], result['height'] = image.size
                    logging.debug(f'URL {url} is an image: {result["width"]}x{result["height"]}')
                else:
                    logging.debug(f'URL {url} does not return an image')
                    result['detected'].append('No Image')
            elif req.status_code == 301 or req.status_code == 302:
                logging.debug(f'URL {url} is a redirect, not likely to be a legit image')
                result['detected'].append('Redirect')
            else:
                logging.debug(f'URL {url} returned status code {req.status_code}')
        except Exception as e:
            # This isn't superpretty, but we'll do some text matching
            error = str(e)
            if "Name or service not known" in error:
                # No need to retry, this is a dead end
                result['detected'].append('DNS error')
            elif "Max retries":
                # Also not a good indicator, so we'll treat it as a tracking image
                result['detected'].append('Connection Issues')
            # All else...
            logging.error(f'Error testing {url}: {e}')
            logging.exception(f"Exception: {e}")
        return result

    def __get_style_size(self, style, property_name):
        """
        Extracts a specific dimension from the style attribute.
        Returns the size as an integer if found, otherwise None.
        """
        # Regex pattern to match property names at the start, after a space, or after a semicolon
        pattern = rf'(^|\s|;){property_name}\s*:\s*([0-9]+|auto)(dp|px|%)?\s*;'
        match = re.search(pattern, style)
        return match.group(2) if match else None

    def __is_invisible(self, style):
        """
        Detects if an element is hidden based on its style attribute.
        Returns True if hidden, False otherwise.
        """
        # Regex pattern to match display: none; or visibility: hidden; in the style attribute
        pattern = r'(display\s*:\s*none|visibility\s*:\s*hidden)'
        return re.search(pattern, style) is not None

    def is_tracking_image(self, img_tag):
        # Define conditions to identify tracking pixels
        try:
            style = img_tag.get('style', '')
            width = img_tag.get('width', self.__get_style_size(style, 'width'))
            height = img_tag.get('height', self.__get_style_size(style, 'height'))
            src = img_tag.get('src', '')
            alt = img_tag.get('alt', None)

            if width == None:
                width = -1
            if height == None:
                height = -1

            # Convert width and height to integers for comparison
            if isinstance(width, str):
                width = int(re.sub(r'\D', '', '0'+width))
            if isinstance(height, str):
                height = int(re.sub(r'\D', '', '0'+height))

            logging.debug(f'Size: {width}x{height}, URL: {src} (Alt: {alt})')

            # Check for small size (1x1 pixels)
            # There's 1x1, 0x0 but also None x None and None x 0, etc.
            size_check = (width <= 1 and height <= 1)

            # However, if there's no size specified, we can't be sure, so we need to take some executive decisions
            if width == -1 and height == -1:
                # see if there's a tracking URL in the src
                stripped_src = self.strip_tracking_parameters(src)
                if not stripped_src:
                    # Unlikely a tracking image, probably just a lazy developer not providing size
                    logging.debug('(No size specified, but no tracking URL detected, assuming not a tracking pixel)')
                    size_check = False

            # Check if the image is hidden based on style attribute
            hidden_element = self.__is_invisible(style)

            # This regex checks for typical tracking URL patterns, can be adjusted as needed
            tracking_url = re.search(r'track|pixel', src, re.IGNORECASE) is not None
        except Exception as e:
            logging.error(f'Error processing image tag: {img_tag}')
            logging.exception(f"Error: {e}")
            # Reraise the exception
            raise e
        logging.debug(f'Size check: {size_check}, Tracking URL: {tracking_url}, Hidden element: {hidden_element}')
        reason = []
        if size_check:
            reason.append(f'Size check {width}x{height}')
        if tracking_url:
            reason.append(f'Tracker URL')
        if hidden_element:
            reason.append('Hidden element')
        return reason

class Detrackify:
    def __init__(self, config):
        self.blank_tracker = self.__create_blank_tracker()
        self.blocked_domains = {}
        self.stripped_domains = []
        self.rewrite_domains = []
        self.guarded_links = 0
        self.config = config
        self.detector = Detector(config)

    def __create_blank_tracker(self):
        # Create a 1x1 transparent image
        image = Image.new('RGBA', (1, 1), (255, 255, 255, 0))  # RGBA mode with 0 alpha (fully transparent)

        # Save the image to a BytesIO object
        buffered = BytesIO()
        image.save(buffered, format="PNG")

        # Encode the image in Base64
        base64_image = base64.b64encode(buffered.getvalue()).decode('utf-8')

        # Format it for use in an img tag
        img_tag_src = f"data:image/png;base64,{base64_image}"

        return img_tag_src

    def get_domain(self, url):
        # Extract domain from URL
        domain = re.search(r'https?://([^/]+)', url)
        return domain.group(1) if domain else 'INVALID: ' + url

    def list_images(self, html_content):
        # Parse HTML with BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')

        # Find all image tags
        img_tags = soup.find_all('img')

        for img_tag in img_tags:
            print(img_tag['src'])
        return

    def replace_tracking_urls(self, html_content, from_domain=None, to_address=None, from_address=None):
        """Rewrite tracking images and optionally guard links."""
        soup = BeautifulSoup(html_content, 'html.parser')

        # Print all links in the email
        #for link in soup.find_all('a'):
        #    print(link['href'][:50])

        # Find all image tags
        img_tags = soup.find_all('img')

        for img_tag in img_tags:
            if not img_tag.has_attr('src'):
                logging.warning('Image tag without src attribute')
                continue
            original = img_tag['src']
            img_tag['src'] = self.config.rewrite_url(img_tag['src'])
            if img_tag['src'] != original:
                self.rewrite_domains.append(original)

            original = url = img_tag['src']
            replacement = self.blank_tracker
            tracker = []

            if url.startswith('cid:'):
                logging.debug(f'Ignoring CID URL: {url}')
                continue

            # Rewrite the URL if needed

            if self.config.is_whitelisted(url):
                logging.debug(f'Whitelisted URL: {url}')
                continue

            if self.config.is_blacklisted(url):
                tracker.append('Blacklist')

            # If we still haven't found something bad, then test the image
            if not tracker:
                tracker.extend(self.detector.is_tracking_image(img_tag))

            if self.config.get(Configuration.CFG_STRIP_ENABLE) and not tracker:
                replacement, reason = self.process_strip(img_tag)
                tracker.extend(reason)

            # Determine if we should replace the tracking pixel
            if tracker:
                # Replace the src of the tracking pixel
                logging.info(f'[{", ".join(tracker)}] {url}')
                domain = self.get_domain(url).lower()
                if domain in self.blocked_domains:
                    self.blocked_domains[domain].append({url: tracker}) 
                else:
                    self.blocked_domains[domain] = [{url: tracker}]
                url = replacement

            img_tag['src'] = url

        # Guard regular links if enabled
        mode = self.config.get(Configuration.CFG_GUARD_LINK, 'off')
        if mode != 'off' and from_domain:
            sender_identity = from_address or from_domain
            if self.config.is_guard_sender_whitelisted(sender_identity):
                logging.debug('Sender %s is whitelisted from guarding', sender_identity)
            else:
                links = soup.find_all('a')
                guard_server = self.config.get(Configuration.CFG_GUARD_SERVER).rstrip('/') if self.config.get(Configuration.CFG_GUARD_SERVER) else None
                for link in links:
                    href = link.get('href', '')
                    if not href.startswith('http'):
                        continue
                    if guard_server and href.startswith(f'{guard_server}/guard/'):
                        continue
                    if self.config.is_guard_link_whitelisted(href):
                        continue
                    link_domain = self.get_domain(href).lower()
                    def is_subdomain(d1, d2):
                        """Return True if d1 is the same as or a subdomain of d2."""
                        return d1 == d2 or d1.endswith('.' + d2)

                    match = is_subdomain(link_domain, from_domain) or is_subdomain(from_domain, link_domain)
                    if mode == 'always' or (mode == 'mismatch' and not match):
                        payload = {
                            'display': link.get_text(),
                            'domain': from_domain,
                            'url': href,
                        }
                        if self.config.get(Configuration.CFG_GUARD_CAPTURE_TO) and to_address:
                            payload['to'] = to_address
                        b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
                        sha = hashlib.sha1((b64 + self.config.get(Configuration.CFG_GUARD_SALT)).encode()).hexdigest()
                        link['href'] = f"{guard_server}/guard/{sha}/{b64}"
                        self.guarded_links += 1

        # Return modified HTML

        # Print all links in the email
        #for link in soup.find_all('a'):
        #    print(link['href'][:50])

        result = soup.encode(formatter="html").decode('utf-8')

        # Print all links in the transformed email
        #soup = BeautifulSoup(result, 'html.parser')

        #for link in soup.find_all('a'):
        #    print(link['href'][:50])

        return result

    def process_strip(self, img_tag):
        stripped_url = url = img_tag['src']
        reason = []
        result = self.detector.detect_needed_rewrite(url)
        if not result or 'No Image' in result['reason']:
            print(f'Result: {result}')
            self.config.add_blacklist(f'{self.detector.strip_tracking_parameters(url)}.*')
            stripped_url = self.blank_tracker
            reason.append('No image')
        else:
            reason = result['reason']
            #logging.debug(f'[{", ".join(result["reason"])}] {url}')
            if 'Tracker' in result['reason']:
                self.config.add_blacklist(f'{self.detector.strip_tracking_parameters(url)}.*')
                stripped_url = self.blank_tracker
            elif stripped_url != url:
                stripped_url = result['url']
                reason.append('Rewritten')
                
                logging.debug(f'Stripped {url} to {stripped_url}')
                
                self.config.add_rewrite(self.detector.strip_tracking_parameters(url)+'.*', stripped_url)
                self.config.add_whitelist(f'{stripped_url}')
        return stripped_url, reason

    def decode_base64(self, content, charset='utf-8'):
        # Decode Base64 content to string using the specified charset
        ret = base64.b64decode(content).decode(charset)
        return ret

    def process_file(self, email_path, output_path, listonly=False):
        with open(email_path, 'rb') as fd_in:
            with open(output_path, 'wb') as fd_out:
                self.process(fd_in, fd_out, hardfail=True, listonly=listonly)

    def process(self, input_fd, output_fd, hardfail=False, listonly=False):
        # Read the raw email content into memory
        raw_message = input_fd.read()

        if self.config.get(Configuration.CFG_COPY):
            # Copy the original email to the copy folder
            try:
                filename = os.path.join(self.config.get(Configuration.CFG_COPY), f'debug_original_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.eml')
                with open(filename, 'wb') as fd:
                    fd.write(raw_message)
            except Exception as e:
                logging.exception(f"Error copying original email: {e}")

        try:
            self.process_buffer(raw_message, output_fd, listonly=listonly)
        except Exception as e:
            logging.exception(f"Error: {e}")
            # Ensure we still allow message to be delivered
            if hardfail:
                logging.error('Hardfail enabled, stopping processing')
                sys.exit(1)
            output_fd.write(raw_message)

    def process_buffer(self, raw_message, output_fd, listonly=False):
        hashtml = False
        self.guarded_links = 0

        # Parse the email content
        msg = BytesParser(policy=policy.default).parsebytes(raw_message)
        from_domain = None
        from_address = None
        to_address = None
        mode = self.config.get(Configuration.CFG_GUARD_LINK, 'off')
        capture_to = self.config.get(Configuration.CFG_GUARD_CAPTURE_TO)

        if mode != 'off':
            from_header = msg.get('From')
            if from_header:
                addrs = email.utils.getaddresses([from_header])
                if addrs and '@' in addrs[0][1]:
                    from_address = addrs[0][1]
                    from_domain = from_address.split('@')[-1].lower()
                else:
                    logging.warning('Unable to parse From header: %s', from_header)
            else:
                logging.warning('No From header present while guardlink enabled')

            if capture_to:
                to_header = msg.get('To')
                if to_header:
                    addrs = email.utils.getaddresses([to_header])
                    if addrs and '@' in addrs[0][1]:
                        to_address = addrs[0][1]
                    else:
                        logging.warning('Unable to parse To header: %s', to_header)
                else:
                    logging.warning('No To header present while capture enabled')


        # Iterate over all parts of the email
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                hashtml = True
                # Check if content is Base64 encoded
                content_transfer_encoding = part.get('Content-Transfer-Encoding', '').lower()
                content_charset = part.get_content_charset() or 'utf-8'
                if content_transfer_encoding == 'base64':
                    # Decode Base64 content
                    html_content = self.decode_base64(part.get_payload(), content_charset)
                else:
                    # Decode normally if not Base64 encoded
                    html_content = part.get_payload(decode=True).decode(content_charset)

                if listonly:
                    self.list_images(html_content)
                    continue # Skip processing, just list URLs
                else:
                    # Replace tracking URLs in the HTML content. Store the
                    # modified HTML so we can put the changed payload back.
                    modified_html = self.replace_tracking_urls(html_content, from_domain, to_address, from_address)

                # Optionally, re-encode the modified HTML back to Base64 if needed
                if content_transfer_encoding == 'base64':
                    encoded_modified_html = base64.b64encode(modified_html.encode('utf-8')).decode('utf-8')
                elif content_transfer_encoding == 'quoted-printable':
                    encoded_modified_html = quopri.encodestring(modified_html.encode('utf-8')).decode('utf-8')
                else:
                    encoded_modified_html = modified_html

                # Replace the part content (re-encoding step might be required if original was Base64)
                part.set_payload(encoded_modified_html, charset='utf-8')

        msg.add_header('X-Detrackify', 'Processed by Detrackify')
        # Only mark pixels as blocked if we actually changed or stripped URLs.
        if self.blocked_domains or self.stripped_domains:
            for domain, items in self.blocked_domains.items():
                for item in items:
                    for url, reason in item.items():
                        msg.add_header('X-Detrackify-Blocked', f'{domain}: {url} ({", ".join(reason)})')
            for url in self.stripped_domains:
                msg.add_header('X-Detrackify-Stripped', url)
        elif hashtml:
            msg.add_header('X-Detrackify-Blocked', 'No tracking pixels found in HTML content')
        else:
            msg.add_header('X-Detrackify-Blocked', 'No tracking pixels found (no html content)')

        mode = self.config.get(Configuration.CFG_GUARD_LINK, 'off')
        if mode != 'off':
            msg.add_header('X-Detrackify-Guarded-Links', str(self.guarded_links))
            msg.add_header('X-Detrackify-Guard-Mode', mode)

        # Save the modified email to a new file
        gen = BytesGenerator(output_fd, policy=policy.default)
        gen.flatten(msg)

    def get_statistics(self):
        # Print the domains that were blocked
        logging.info("Blocked tracking domains:")
        for domain, items in self.blocked_domains.items():
            logging.info(f'{domain}: {len(items)} occurrences')
            for item in items:
                for url, reason in item.items():
                    logging.info(f'  - {url} ({", ".join(reason)})')

        logging.info(f"Stripped tracking parameters from {len(self.stripped_domains)} URLs")
        for url in self.stripped_domains:
            logging.info(f'  - {url}')
        
        logging.info(f"Rewrote {len(self.rewrite_domains)} URLs")
        for url in self.rewrite_domains:
            logging.info(f'  - {url}')

class Configuration:
    CFG_VERBOSE = 'options.verbose'
    CFG_STRIP_FILE = 'options.strip.file'
    CFG_STRIP_COOKIES = 'options.strip.cookies'
    CFG_STRIP_REDIRECT = 'options.strip.redirect'
    CFG_STRIP_ENABLE = 'options.strip.enable'
    CFG_COPY = 'options.copy'
    CFG_GUARD_SERVER = 'guard.server'
    CFG_GUARD_SALT = 'guard.salt'
    CFG_GUARD_LINK = 'guard.link'
    CFG_GUARD_CAPTURE_TO = 'guard.capture_to'
    CFG_GUARD_WHITELINK = 'guard.whitelist_links'
    CFG_GUARD_WHITELIST_SENDER = 'guard.whitelist_senders'

    def __init__(self):
        # Ensure we have a sane default
        self.config = {
            'options': {
                'strip': {
                    'file': 'strip.yml',
                    'cookies': True,
                    'redirect': True,
                    'enable': False
                },
                'verbose': False,
                'copy': None
            },
            'guard': {
                'server': None,
                'salt': None,
                'link': 'off',
                'capture_to': False,
                'whitelist_links': [],
                'whitelist_senders': []
            },
            'blacklist': [],
            'whitelist': [],
            'rewrite': []
        }
        self.last_blacklist = 0
        self.last_rewrite = 0
        self.last_whitelist = 0

    def set(self, key, value):
        parts = key.split('.')
        config = self.config
        for c in range(len(parts)-1):
            if parts[c] in config:
                config = config[parts[c]]
                if c == len(parts)-2:
                    config[parts[c+1]] = value
                    break
        if key == Configuration.CFG_STRIP_ENABLE:
            self.load_learned(self.get(Configuration.CFG_STRIP_FILE))
        return

    def get(self, key, default=None):
        parts = key.split('.')
        config = self.config
        for part in parts:
            if part in config:
                config = config[part]
            else:
                logging.warning(f'Key not found: {part} in {config}')
                return default
        return config

    def load(self, path):
        # Load our configuration file (YAML)
        try:
            with open(path, 'r') as stream:
                try:
                    settings = yaml.safe_load(stream)
                    self.config.update(settings)
                except yaml.YAMLError as exc:
                    logging.exception(f"Error loading configuration file: {exc}")
                    return False
        except FileNotFoundError as e:
            logging.exception(f"Configuration file not found: {path}")
            return False
        except Exception as e:
            logging.exception(f"Error loading configuration file: {e}")
            return False
        
        self.last_blacklist = len(self.config.get('blacklist', []))
        self.last_rewrite = len(self.config.get('rewrite', []))
        self.last_whitelist = len(self.config.get('whitelist', []))
        logging.debug(f'Loaded configuration file: {path} with {self.last_blacklist} blacklisted URLs and {self.last_rewrite} rewrite rules')
        return True

    def save_learned(self, path):
        # Save the learned rewrite rules and blacklisted URLs
        try:
            partial = {'whitelist': self.config.get('whitelist', [])[self.last_whitelist:], 'blacklist': self.config.get('blacklist', [])[self.last_blacklist:], 'rewrite': self.config.get('rewrite', [])[self.last_rewrite:]}
            logging.debug(f'In COnfig: Blacklisted URLs: {len(self.config.get("blacklist", []))}, Whitelisted URLs: {len(self.config.get("whitelist", []))}, Rewrite rules: {len(self.config.get("rewrite", []))}')
            logging.debug(f'Last entry: Blacklisted URLs: {self.last_blacklist}, Whitelisted URLs: {self.last_whitelist}, Rewrite rules: {self.last_rewrite}')
            with open(path, 'w') as stream:
                yaml.dump(partial, stream)
                logging.debug(f'Saved learned file: {path} with {len(partial.get("blacklist", []))} blacklisted URLs, {len(partial.get("whitelist", []))} whitelisted URLs and {len(partial.get("rewrite", []))} rewrite rules')
        except Exception as e:
            logging.exception(f"Error saving learned file: {e}")
            return False
        return True

    def load_learned(self, path):
        # Load the learned rewrite rules and blacklisted URLs
        try:
            with open(path, 'r') as stream:
                learned = yaml.safe_load(stream)
                print(f'Config: {self.config}')
                self.config['whitelist'].extend(learned.get('whitelist', []))
                self.config['blacklist'].extend(learned.get('blacklist', []))
                self.config['rewrite'].extend(learned.get('rewrite', []))
                logging.debug(f'Loaded learned file: {path} with {len(learned.get("blacklist", []))} blacklisted URLs and {len(learned.get("rewrite", []))} rewrite rules')
        except FileNotFoundError as e:
            logging.warning(f"Learned file not found: {path}")
            return True
        except Exception as e:
            logging.exception(f"Error loading learned file: {e}")
            return False
        return True

    def __test_url(self, url, regex):
        # Test if the URL matches the list of regex
        for test in regex:
            # Test is a regex, so use the match method
            try:
                result = re.match(test, url)
                if result:
                    logging.debug(f'Match: {url} ({test})')
                    return True
            except Exception as e:
                logging.error(f'Error testing {url} with {test}')
                logging.exception(f"Exception: {e}")
        return False
    
    def is_blacklisted(self, url):
        # Check if the URL is blacklisted
        return self.__test_url(url, self.config.get('blacklist', []))
    
    def is_whitelisted(self, url):
        # Check if the URL is whitelisted
        return self.__test_url(url, self.config.get('whitelist', []))

    def is_guard_link_whitelisted(self, url):
        """Check if link should bypass guarding."""
        return self.__test_url(url, self.config.get('guard', {}).get('whitelist_links', []))

    def is_guard_sender_whitelisted(self, sender):
        """Check if sender should bypass guarding."""
        return self.__test_url(sender, self.config.get('guard', {}).get('whitelist_senders', []))
    
    def rewrite_url(self, url):
        # Rewrite the URL if needed
        for rule in self.config.get('rewrite', []):
            # Rule is a dict with 'from' and 'to' keys
            f = rule.get('from', None)
            t = rule.get('to', None)
            if f and t:
                try:
                    result = re.sub(rule.get('from'), rule.get('to'), url)
                    if result != url:
                        logging.info(f'Rewriting {url} to {result} ({rule})')
                        return result
                except Exception as e:
                    logging.error(f'Rewriting {url} from {f} to {t} failed.')
                    logging.exception(f"Exception: {e}")
            else:
                logging.error(f'Invalid rewrite rule: {rule}')
        return url

    def add_blacklist(self, url):
        # Add a URL to the blacklist
        if not self.is_blacklisted(url):
            logging.info(f'################## Adding {url} to blacklist')
            self.config['blacklist'].append(url)
            return True
        return False

    def add_whitelist(self, url):
        # Add a URL to the whitelist
        if not self.is_whitelisted(url):
            logging.info(f'################## Adding {url} to whitelist')
            self.config['whitelist'].append(url)
            return True
        return False

    def add_rewrite(self, from_url, to_url):
        # Check if a rewrite rule already exists
        for rule in self.config['rewrite']:
            if rule.get('from') == from_url:
                # Rule already exists, is it the same?
                if rule.get('to') == to_url:
                    logging.debug(f'Rule already exists: {from_url} -> {to_url}')
                    return False
                else:
                    logging.warning(f'Overwriting rewrite rule: {from_url} -> {to_url}')
                    rule['to'] = to_url
                    return True
        # Add a new rewrite rule
        logging.info(f'###################### Adding rewrite rule: {from_url} -> {to_url}')
        self.config['rewrite'].append({'from': from_url, 'to': to_url})
        return True

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
    parser.add_argument('--hardfail', help='Do not passthru email on failure, stop processing', action='store_true')
    parser.add_argument('--strip', help='Remove parameters for images (experimental)', action='store_true')
    parser.add_argument('--config', help='Path to the configuration file')
    parser.add_argument('--testurl', help='Detect which query parameters can be stripped from the URL (WARNING! Will make requests to the URLs)')
    parser.add_argument('--list', help='List all detected image URLs', action='store_true')
    parser.add_argument('--copy', help='Copy the original email to this folder for debugging')
    parser.add_argument('--guardserver', help='URL of the guard server')
    parser.add_argument('--guardsalt', help='Salt used for guarded links')
    parser.add_argument('--guardlink', choices=['off', 'mismatch', 'always'], default='off', help='Guard link mode')
    parser.add_argument('--guardcaptureto', action='store_true', help='Capture the To address in guarded links')
    parser.add_argument('--guardwhitelink', action='append', default=[], help='Regex of links that should not be guarded')
    parser.add_argument('--guardwhitelistsender', action='append', default=[], help='Regex of sender addresses exempt from guarding')

    # Parse command line arguments
    args = parser.parse_args()

    # Allow early debug logging
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug('Early debug logging enabled')

    # Call the scan_and_replace_trackers function with the input file path
    config = Configuration()
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

    if args.config:
        if not config.load(args.config):
            logging.error(f'Error loading configuration file: {args.config}')
            sys.exit(1)
        else:
            logging.debug(f'Loaded configuration file: {args.config}')

    if args.verbose:
        config.set(Configuration.CFG_VERBOSE, True)

    if config.get(Configuration.CFG_VERBOSE):
        logging.getLogger().setLevel(logging.DEBUG)

    if args.strip:
        config.set(Configuration.CFG_STRIP_ENABLE, True)

    if args.copy:
        if not os.path.exists(args.copy):
            logging.error(f'Copy folder does not exist: {args.copy}')
            sys.exit(1)
        else:
            config.set(Configuration.CFG_COPY, args.copy)

    if args.guardserver:
        config.set(Configuration.CFG_GUARD_SERVER, args.guardserver)
    if args.guardsalt:
        config.set(Configuration.CFG_GUARD_SALT, args.guardsalt)
    if args.guardlink:
        config.set(Configuration.CFG_GUARD_LINK, args.guardlink)
    if args.guardcaptureto:
        config.set(Configuration.CFG_GUARD_CAPTURE_TO, True)
    if args.guardwhitelink:
        config.config['guard']['whitelist_links'].extend(args.guardwhitelink)
    if args.guardwhitelistsender:
        config.config['guard']['whitelist_senders'].extend(args.guardwhitelistsender)

    mode = config.get(Configuration.CFG_GUARD_LINK, 'off')
    if mode != 'off':
        server = config.get(Configuration.CFG_GUARD_SERVER)
        salt = config.get(Configuration.CFG_GUARD_SALT)
        if not server:
            logging.error('Guard server must be specified when guardlink is enabled')
            sys.exit(1)
        if not re.match(r'^https?://', server):
            logging.error('Guard server must include http or https scheme')
            sys.exit(1)
        if server.startswith('http://'):
            logging.warning('Guard server is using HTTP, consider HTTPS')
        if not salt or len(salt) < 8:
            logging.error('Guardsalt must be at least 8 characters')
            sys.exit(1)

    detrack = Detrackify(config)
    try:
        if args.testurl:
            logging.info(f'Testing URL: {args.testurl}')
            detector = Detector(config)
            result = detector.detect_needed_rewrite(args.testurl, replace_1x1=True)
            logging.info(f'Returns image: {result}')
            if result != args.testurl:
                # Create rule for this
                logging.info(f'Add this rule to the configuration file:')
                if result is None:
                    print(f'blacklist:')
                    print(f'- {detector.strip_tracking_parameters(args.testurl)}.*')
                else:
                    print(f'rewrite:')
                    print(f'- from: {result}.*')
                    print(f'  to: {result}')
            sys.exit(0)
        if args.message_id:
            logging.info(f'Processing message ID: {args.message_id}')
        if args.input and args.output:
            detrack.process_file(args.input, args.output, listonly=args.list)
            #if not args.list:
            #    detrack.get_statistics()
        else:
            detrack.process(sys.stdin.buffer, sys.stdout.buffer, args.hardfail)

        if config.get(Configuration.CFG_STRIP_ENABLE):
            config.save_learned(config.get(Configuration.CFG_STRIP_FILE))
    except Exception as e:
        # Catch-all for any exceptions
        logging.exception("Error: %s", e)
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
