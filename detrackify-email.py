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

class Detrackify:
    def __init__(self, stripquery=False):
        self.blank_tracker = self.__create_blank_tracker()
        self.blocked_domains = {}
        self.stripped_domains = []
        self.stripquery = stripquery

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

    def extract_dimension_from_style(self, style, property_name):
        """
        Extracts a specific dimension (width, height, or border-width) from the style attribute.
        Returns the size as an integer if found, otherwise None.
        """
        # Regex pattern to match property names at the start, after a space, or after a semicolon
        pattern = rf'(^|\s|;){property_name}\s*:\s*([0-9]+|auto)(dp|px|%)?\s*;'
        match = re.search(pattern, style)
        return match.group(2) if match else None

    def detect_hidden_element_from_style(self, style):
        """
        Detects if an element is hidden based on its style attribute.
        Returns True if hidden, False otherwise.
        """
        # Regex pattern to match display: none; or visibility: hidden; in the style attribute
        pattern = r'(display\s*:\s*none|visibility\s*:\s*hidden)'
        return re.search(pattern, style) is not None

    def is_tracking_pixel(self, img_tag):
        # Define conditions to identify tracking pixels
        try:
            style = img_tag.get('style', '')
            width = img_tag.get('width', self.extract_dimension_from_style(style, 'width'))
            height = img_tag.get('height', self.extract_dimension_from_style(style, 'height'))
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

            logging.debug(f'Size check: {width}x{height}, External URL: {src} (Alt: {alt})')

            # Check for small size (1x1 pixels)
            # There's 1x1, 0x0 but also None x None and None x 0, etc.
            size_check = (width <= 1 and height <= 1)

            # However, if there's no size specified, we can't be sure, so we need to take some executive decisions
            if width == -1 and height == -1:
                # see if there's a tracking URL in the src
                stripped_src = self.strip_tracking_parameters(img_tag)
                if not stripped_src:
                    # Unlikely a tracking image, probably just a lazy developer not providing size
                    logging.info('(No size specified, but no tracking URL detected, assuming not a tracking pixel)')
                    size_check = False

            # Check if the image is hidden based on style attribute
            hidden_element = self.detect_hidden_element_from_style(style)

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
            reason.append(f'Tracking URL "{src}"')
        if hidden_element:
            reason.append('Hidden element')
        return (size_check or tracking_url or hidden_element, reason)

    def get_domain(self, url):
        # Extract domain from URL
        domain = re.search(r'https?://([^/]+)', url)
        return domain.group(1) if domain else 'INVALID: ' + url

    def strip_tracking_parameters(self, img_tag):
        result = None
        # Strip tracking parameters from URL
        url = img_tag['src']
        # Images typically don't have query parameters, so let's strip them if they exist
        match = re.search(r'(https?:\/\/[^?]+)(\??.*)', url)
        if match:
            if match.group(2) and match.group(2) != '':
                logging.info(f'Stripped: {url} -> {match.group(1)}')
                result = match.group(1)
        else:
            logging.warning(f'URL does not confirm: {url}')
        return result

    def replace_tracking_urls(self, html_content):
        # Parse HTML with BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')

        # Find all image tags
        img_tags = soup.find_all('img')

        for img_tag in img_tags:
            tracker, why = self.is_tracking_pixel(img_tag)
            if tracker:
                # Replace the src of the tracking pixel
                logging.info(f'`--> Replacing tracking pixel: {img_tag} ({", ".join(why)})')
                domain = self.get_domain(img_tag['src']).lower()
                if domain in self.blocked_domains:
                    self.blocked_domains[domain].append({img_tag['src']: why}) 
                else:
                    self.blocked_domains[domain] = [{img_tag['src']: why}]
                img_tag['src'] = self.blank_tracker
            else:
                # See if there's parameters to be stripped
                url = self.strip_tracking_parameters(img_tag)
                if url and self.stripquery:
                    self.stripped_domains.append(img_tag['src']) 
                    img_tag['src'] = url
                elif url:
                    logging.info(f'Detected URL to strip, but stripquery is disabled: {img_tag["src"]}')

        # Return modified HTML
        return soup.encode(formatter="html")

    def decode_base64(self, content, charset='utf-8'):
        # Decode Base64 content to string using the specified charset
        return base64.b64decode(content).decode(charset)

    def process_file(self, email_path, output_path):
        with open(email_path, 'rb') as fd_in:
            with open(output_path, 'wb') as fd_out:
                self.process(fd_in, fd_out, hardfail=True)

    def process(self, input_fd, output_fd, hardfail=False):
        # Read the raw email content into memory
        raw_message = input_fd.read()
        try:
            self.process_buffer(raw_message, output_fd)
        except Exception as e:
            logging.exception(f"Error: {e}")
            # Ensure we still allow message to be delivered
            if hardfail:
                logging.error('Hardfail enabled, stopping processing')
                sys.exit(1)
            output_fd.write(raw_message)

    def process_buffer(self, raw_message, output_fd):
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
                if content_transfer_encoding == 'base64':
                    # Decode Base64 content
                    html_content = self.decode_base64(part.get_payload(), part.get_content_charset())
                else:
                    # Decode normally if not Base64 encoded
                    html_content = part.get_payload(decode=True).decode(part.get_content_charset())

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

    # Parse command line arguments
    args = parser.parse_args()

    # Call the scan_and_replace_trackers function with the input file path
    detrack = Detrackify(stripquery=args.stripquery)
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
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.message_id:
        logging.info(f'Processing message ID: {args.message_id}')
    if args.input and args.output:
        detrack.process_file(args.input, args.output)
        detrack.get_statistics()
    else:
        detrack.process(sys.stdin.buffer, sys.stdout.buffer, args.hardfail)
