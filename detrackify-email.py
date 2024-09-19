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
import base64
from io import BytesIO
import yaml
import requests

class Detector:
    def __init__(self):
        pass

    def strip_tracking_parameters(self, url):
        result = None
        # Images typically don't have query parameters, so let's strip them if they exist
        match = re.search(r'(https?:\/\/[^?]+)(\??.*)', url)
        if match:
            if match.group(2) and match.group(2) != '':
                logging.debug(f'Stripped: {url} -> {match.group(1)}')
                result = match.group(1)
        else:
            logging.warning(f'URL does not confirm: {url}')
        return result

    def detect_needed_rewrite(self, url, replace_1x1=False):
        # Check if the URL contains a query string
        result = url
        match = re.search(r'(https?:\/\/[^?]+)(\??.*)', url)
        if match:
            if match.group(2) and match.group(2) != '':
                # Break up the query string into parts
                query = match.group(2)[1:] # Skip the question mark
                parts = query.split('&')

                # Blank the last part, this stops us from doing a complete HTTP GET of the (potentially) tracking URL
                # This doesn't guarantee they won't track us anyway, but at least we try to avoid it.
                parts[-1] = ''

                # Reconstruct the URL without the query string
                result = f'{match.group(1)}?'
                while len(parts) > 0:
                    size = self.get_url_img_size(result)
                    if size:
                        # Check if the image is 1x1
                        if replace_1x1 and size[0] <= 1 and size[1] <= 1:
                            logging.debug(f'1x1 image detected at URL: {url}')
                            return None
                        result = result[:-1] # Remove the last character, the ampersand/question mark
                        return result
                    result += f'{parts.pop(0)}&'
                logging.warning(f'No image at URL: {url}')
                return result
        else:
            logging.warning(f'URL does not confirm: {url}')
        return result

    def get_url_img_size(self, url):
        """
        Will attempt to connect to the URL to see if it returns an image
        """
        try:
            req = requests.get(url, stream=True, timeout=3, allow_redirects=False) # Only wait 3s for a response
            if req.status_code == 200:
                if req.cookies:
                    logging.debug(f'URL {url} returns cookies, so it is going to be a tracking device')
                    return (-1, -1) # This will be considered a tracking image
                
                # So far so good, check mimetype
                if 'image' in req.headers['Content-Type']:
                    # Read image so we can determine dimensions
                    # Read the image data
                    image = Image.open(BytesIO(req.content))
                    logging.debug('Image size: %s', image.size)
                    return image.size
                else:
                    logging.debug(f'URL {url} does not return an image')
            elif req.status_code == 301 or req.status_code == 302:
                logging.debug(f'URL {url} is a redirect, not likely to be a legit image')
                return (-1, -1) # This will be considered a tracking image
        except Exception as e:
            # This isn't superpretty, but we'll do some text matching
            error = str(e)
            if "Name or service not known" in error:
                # No need to retry, this is a dead end
                return (-1, -1) # This will be considered a tracking image
            elif "Max retries":
                # Also not a good indicator, so we'll treat it as a tracking image
                return (-1, -1) # This will be considered a tracking image
            # All else...
            logging.error(f'Error testing {url}: {e}')
            logging.exception(f"Exception: {e}")
        return None

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
    def __init__(self, config, rewrite=False, stripquery=False):
        self.blank_tracker = self.__create_blank_tracker()
        self.blocked_domains = {}
        self.stripped_domains = []
        self.rewrite_domains = []
        self.stripquery = stripquery
        self.rewrite = rewrite
        self.config = config
        self.detector = Detector()

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

    def replace_tracking_urls(self, html_content):
        # Parse HTML with BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')

        # Find all image tags
        img_tags = soup.find_all('img')

        for img_tag in img_tags:
            original = url = img_tag['src']
            replacement = self.blank_tracker
            tracker = []

            if url.startswith('cid:'):
                logging.debug(f'Ignoring CID URL: {url}')
                continue

            if config.is_whitelisted(url):
                logging.debug(f'Whitelisted URL: {url}')
                continue

            if config.is_blacklisted(url):
                tracker.append('Blacklist')

            if self.rewrite:
                url = config.rewrite_url(url)
                if url != original:
                    self.rewrite_domains.append(original)

            # If we still haven't found something bad, then test the image
            if not tracker:
                tracker.extend(self.detector.is_tracking_image(img_tag))

            if self.stripquery and not tracker:
                stripped_url = self.detector.strip_tracking_parameters(url)
                if stripped_url:
                    logging.debug(f'Stripped: {url} -> {stripped_url}')
                    self.stripped_domains.append(url)
                    replacement = stripped_url
                    tracker.append('Stripped')

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

        # Return modified HTML
        return soup.encode(formatter="html")

    def decode_base64(self, content, charset='utf-8'):
        # Decode Base64 content to string using the specified charset
        return base64.b64decode(content).decode(charset)

    def process_file(self, email_path, output_path, listonly=False):
        with open(email_path, 'rb') as fd_in:
            with open(output_path, 'wb') as fd_out:
                self.process(fd_in, fd_out, hardfail=True, listonly=listonly)

    def process(self, input_fd, output_fd, hardfail=False, listonly=False):
        # Read the raw email content into memory
        raw_message = input_fd.read()
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

        # Parse the email content
        msg = BytesParser(policy=policy.default).parsebytes(raw_message)

        modified_html_parts = []

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
                    # Replace tracking URLs in the HTML content
                    modified_html = self.replace_tracking_urls(html_content)
                    modified_html_parts.append(modified_html)

                # Optionally, re-encode the modified HTML back to Base64 if needed
                if content_transfer_encoding == 'base64':
                    encoded_modified_html = base64.b64encode(modified_html.encode('utf-8')).decode('utf-8')

                # Replace the part content (re-encoding step might be required if original was Base64)
                part.set_payload(encoded_modified_html if content_transfer_encoding == 'base64' else modified_html, charset='utf-8')

        msg.add_header('X-Detrackify', 'Processed by Detrackify')
        if modified_html_parts:
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
        if self.stripquery:
            logging.info(f"Stripped tracking parameters from {len(self.stripped_domains)} URLs")
            for url in self.stripped_domains:
                logging.info(f'  - {url}')
        
        if self.rewrite:
            logging.info(f"Rewrote {len(self.rewrite_domains)} URLs")
            for url in self.rewrite_domains:
                logging.info(f'  - {url}')

class Configuration:
    def __init__(self):
        self.config = {}

    def load(self, path):
        # Load our configuration file (YAML)
        try:
            with open(path, 'r') as stream:
                try:
                    self.config = yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    logging.exception(f"Error loading configuration file: {exc}")
                    self.config = {}
                    return False
        except FileNotFoundError as e:
            logging.exception(f"Configuration file not found: {path}")
            return False
        except Exception as e:
            logging.exception(f"Error loading configuration file: {e}")
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


if __name__ == '__main__':
    # Configure logging
    log_format='%(asctime)s - %(levelname)7s - %(filename)s:%(lineno)3d - %(message)s'
    log_datefmt='%Y-%m-%d %H:%M:%S'

    # Create argument parser
    parser = argparse.ArgumentParser(description='Process email and replace tracking URLs')

    # Add input file argument
    parser.add_argument('--input', help='Path to the input email file')
    parser.add_argument('--output', help='Path to the cleaned email file')
    parser.add_argument('--message-id', help='Log the message id we\'re processing')
    parser.add_argument('--verbose', help='Enable verbose logging', action='store_true')
    parser.add_argument('--logfile', help='Save log instead of using stderr')
    parser.add_argument('--hardfail', help='Do not passthru email on failure, stop processing', action='store_true')
    parser.add_argument('--stripquery', help='Remove parameters for images (experimental)', action='store_true')
    parser.add_argument('--rewrite', help='Rewrite image URL (experimental)', action='store_true')
    parser.add_argument('--config', help='Path to the configuration file')
    parser.add_argument('--testurl', help='Detect which query parameters can be stripped from the URL (WARNING! Will make requests to the URLs)')
    parser.add_argument('--list', help='List all detected image URLs', action='store_true')

    # Parse command line arguments
    args = parser.parse_args()

    # Call the scan_and_replace_trackers function with the input file path
    config = Configuration()
    detrack = Detrackify(config, rewrite=args.rewrite, stripquery=args.stripquery)
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

    try:
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        if args.testurl:
            logging.info(f'Testing URL: {args.testurl}')
            detector = Detector()
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
    except Exception as e:
        # Catch-all for any exceptions
        logging.exception(f"Error: {e}")
        sys.exit(1)
    sys.exit(0)