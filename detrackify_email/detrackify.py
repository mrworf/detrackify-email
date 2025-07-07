"""
Main Detrackify class for processing emails and removing tracking pixels.
"""

import datetime
import os
import quopri
import re
import base64
import json
import hashlib
import logging
import sys
from typing import Dict, Any, List
from email import policy
from email.parser import BytesParser
from email.generator import BytesGenerator
from bs4 import BeautifulSoup

from .helpers import EmailHelpers
from .configuration import Configuration
from .detector import Detector


class Detrackify:
    """Main class for processing emails and removing tracking pixels."""
    
    def __init__(self, config: Configuration):
        """Initialize Detrackify with configuration."""
        self.blank_tracker = EmailHelpers.create_blank_tracker()
        self.blocked_domains = {}
        self.stripped_domains = []
        self.rewrite_domains = []
        self.guarded_links = 0
        self.config = config
        self.detector = Detector(config)
    
    def list_images(self, html_content: str) -> None:
        """List all image URLs found in HTML content."""
        soup = BeautifulSoup(html_content, 'html.parser')
        img_tags = soup.find_all('img')
        
        for img_tag in img_tags:
            logging.info(img_tag['src'])
    
    def replace_tracking_urls(self, html_content: str, from_address: str = None, to_address: str = None) -> str:
        """Rewrite tracking images and optionally guard links."""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find all image tags
        img_tags = soup.find_all('img')
        logging.debug(f"Found {len(img_tags)} image tags to process")
        
        for i, img_tag in enumerate(img_tags):
            logging.debug(f"Processing image {i+1}/{len(img_tags)}")
            if not img_tag.has_attr('src'):
                logging.warning('Image tag without src attribute')
                logging.debug(f"Image {i+1} has no src attribute, skipping")
                continue
            
            original = img_tag['src']
            logging.debug(f"Image {i+1} original src: {original}")
            
            # Check rewrite rules
            rewritten_url = self.config.rewrite_url(img_tag['src'])
            if rewritten_url != original:
                logging.debug(f"Image {i+1} rewritten from {original} to {rewritten_url}")
                self.rewrite_domains.append(original)
                img_tag['src'] = rewritten_url
            else:
                logging.debug(f"Image {i+1} no rewrite rule applied")
            
            original = url = img_tag['src']
            replacement = self.blank_tracker
            tracker = []
            
            if url.startswith('cid:'):
                logging.debug(f'Ignoring CID URL: {url}')
                logging.debug(f"Image {i+1} is CID URL, skipping: {url}")
                continue
            
            # Check whitelist
            if self.config.is_whitelisted(url):
                logging.debug(f'Whitelisted URL: {url}')
                logging.debug(f"Image {i+1} is whitelisted, skipping: {url}")
                continue
            
            # Check blacklist
            if self.config.is_blacklisted(url):
                tracker.append('Blacklist')
                logging.debug(f"Image {i+1} is blacklisted: {url}")
            
            # If we still haven't found something bad, then test the image
            if not tracker:
                logging.debug(f"Image {i+1} not blacklisted, checking if tracking image: {url}")
                tracking_reasons = self.detector.is_tracking_image(img_tag)
                tracker.extend(tracking_reasons)
                if tracking_reasons:
                    logging.debug(f"Image {i+1} detected as tracking: {tracking_reasons}")
            
            # Check strip mode
            if self.config.get(Configuration.CFG_STRIP_ENABLE) and not tracker:
                logging.debug(f"Image {i+1} strip mode enabled, processing: {url}")
                replacement, reason = self.process_strip(img_tag)
                tracker.extend(reason)
                if reason:
                    logging.debug(f"Image {i+1} strip processing result: {reason}")
            
            # Determine if we should replace the tracking pixel
            if tracker:
                # Replace the src of the tracking pixel
                logging.info(f'[{", ".join(tracker)}] {url}')
                logging.debug(f"Image {i+1} REPLACING with blank tracker: {url} -> {replacement[:50]}...")
                domain = EmailHelpers.extract_domain_from_url(url).lower()
                if domain in self.blocked_domains:
                    self.blocked_domains[domain].append({url: tracker})
                else:
                    self.blocked_domains[domain] = [{url: tracker}]
                url = replacement
            else:
                logging.debug(f"Image {i+1} KEEPING original: {url}")
            
            img_tag['src'] = url
        
        # Guard regular links if enabled
        mode = self.config.get(Configuration.CFG_GUARD_LINK, 'off')
        from_domain = None
        sender_is_blacklisted = False
        if from_address and '@' in from_address:
            logging.debug(f"Checking sender_is_blacklisted for: '{from_address}'")
            from_domain = from_address.split('@')[-1].lower()
            sender_is_blacklisted = self.config.is_sender_blacklisted(from_address)
            logging.debug(f"From address: {from_address}, domain: {from_domain}, sender blacklisted: {sender_is_blacklisted}")
        
        if mode != 'off' and from_domain:
            logging.debug(f"Guard mode: {mode}, processing links")
            sender_identity = from_address
            if self.config.is_guard_sender_whitelisted(sender_identity):
                logging.debug('Sender %s is whitelisted from guarding', sender_identity)
                logging.debug(f"Sender {sender_identity} is whitelisted from guarding")
            else:
                links = soup.find_all('a')
                logging.debug(f"Found {len(links)} links to process")
                guard_server = self.config.get(Configuration.CFG_GUARD_SERVER).rstrip('/') if self.config.get(Configuration.CFG_GUARD_SERVER) else None
                
                for i, link in enumerate(links):
                    href = link.get('href', '')
                    logging.debug(f"Processing link {i+1}/{len(links)}: {href}")
                    if not href.startswith('http'):
                        logging.debug(f"Link {i+1} not HTTP, skipping: {href}")
                        continue
                    if guard_server and href.startswith(f'{guard_server}/guard/'):
                        logging.debug(f"Link {i+1} already guarded, skipping: {href}")
                        continue
                    
                    pattern = self.config.is_guard_link_whitelisted(href)
                    if pattern:
                        logging.debug('Whitelisted link %s via %s', href, pattern)
                        logging.debug(f"Link {i+1} whitelisted via pattern {pattern}: {href}")
                        continue
                    
                    block_reason = None
                    if sender_is_blacklisted:
                        block_reason = 'blacklisted'
                        logging.debug(f"Link {i+1} sender is blacklisted")
                        match = False  # Force mismatch so the link is always guarded
                    elif self.config.is_blacklisted(href):
                        block_reason = 'blacklisted'
                        logging.debug(f"Link {i+1} URL is blacklisted: {href}")
                    
                    link_domain = EmailHelpers.extract_domain_from_url(href).lower()
                    match = self.config.are_domains_aliases(link_domain, from_domain)
                    logging.debug(f"Link {i+1} domain match: {link_domain} vs {from_domain} = {match}")
                    
                    if sender_is_blacklisted or mode == 'always' or (mode == 'mismatch' and not match) or block_reason:
                        logging.debug(f"Link {i+1} GUARDING: {href}")
                        logging.debug(f"Link {i+1} guard reason: sender_blacklisted={sender_is_blacklisted}, mode={mode}, domain_match={match}, block_reason={block_reason}")
                        display_html = link.decode_contents()
                        logging.debug(f"Link {i+1} original display HTML: {display_html}")
                        display_text = EmailHelpers.clean_display_text(display_html)
                        logging.debug(f"Link {i+1} cleaned display text: {display_text}")
                        payload = {
                            'display': display_text,
                            'domain': from_domain.strip() if from_domain else '',
                            'url': href.strip() if href else '',
                        }
                        if block_reason:
                            payload['block'] = block_reason
                        if self.config.get(Configuration.CFG_GUARD_CAPTURE_TO) and to_address:
                            payload['to'] = to_address.strip()
                        logging.debug(f"Link {i+1} payload: {payload}")
                        salt = self.config.get(Configuration.CFG_GUARD_SALT)
                        new_href = EmailHelpers.create_guarded_url(payload, guard_server, salt)
                        logging.debug(f"Link {i+1} guarded: {href} -> {new_href[:50]}...")
                        logging.debug(f"Link {i+1} full guarded URL: {new_href}")
                        link['href'] = new_href
                        self.guarded_links += 1
                    else:
                        logging.debug(f"Link {i+1} KEEPING original: {href}")
                        logging.debug(f"Link {i+1} keep reason: sender_blacklisted={sender_is_blacklisted}, mode={mode}, domain_match={match}, block_reason={block_reason}")
        
        elif sender_is_blacklisted:
            # Guard server is not in use, but sender is blacklisted: disable all links
            logging.debug(f"Sender blacklisted but no guard server, disabling all links")
            links = soup.find_all('a')
            logging.debug(f"Disabling {len(links)} links")
            for i, link in enumerate(links):
                original_href = link.get('href', '')
                logging.debug(f"Disabling link {i+1}: {original_href}")
                logging.debug(f"Link {i+1} original style: {link.get('style', '')}")
                link['href'] = '#'  # Or remove the href attribute: del link['href']
                new_style = (link.get('style', '') + '; pointer-events: none; color: gray;').strip()
                link['style'] = new_style
                link['title'] = 'Blocked: blacklisted sender'
                logging.debug(f"Link {i+1} disabled: href='#', style='{new_style}', title='Blocked: blacklisted sender'")
        
        # Return modified HTML
        result = soup.encode(formatter="html").decode('utf-8')
        return result
    
    def process_strip(self, img_tag) -> tuple:
        """Process strip mode for an image tag."""
        stripped_url = url = img_tag['src']
        reason = []
        result = self.detector.detect_needed_rewrite(url)
        if not result or 'No Image' in result['reason']:
            logging.debug(f'Result: {result}')
            self.config.add_blacklist(f'{self.detector.strip_tracking_parameters(url)}.*')
            stripped_url = self.blank_tracker
            reason.append('No image')
        else:
            reason = result['reason']
            if 'Tracker' in result['reason']:
                self.config.add_blacklist(f'{self.detector.strip_tracking_parameters(url)}.*')
                stripped_url = self.blank_tracker
            elif stripped_url != url:
                stripped_url = result['url']
                reason.append('Rewritten')
                
                logging.debug(f'Stripped {url} to {stripped_url}')
                
                self.config.add_rewrite(self.detector.strip_tracking_parameters(url) + '.*', stripped_url)
                self.config.add_whitelist(f'{stripped_url}')
        return stripped_url, reason
    
    def process_file(self, email_path: str, output_path: str, listonly: bool = False) -> None:
        """Process an email file."""
        with open(email_path, 'rb') as fd_in:
            with open(output_path, 'wb') as fd_out:
                self.process(fd_in, fd_out, hardfail=True, listonly=listonly)
    
    def process(self, input_fd, output_fd, hardfail: bool = False, listonly: bool = False) -> None:
        """Process email from file descriptor."""
        # Read the raw email content into memory
        raw_message = input_fd.read()
        
        if self.config.get(Configuration.CFG_COPY):
            # Copy the original email to the copy folder
            try:
                filename = os.path.join(
                    self.config.get(Configuration.CFG_COPY), 
                    f'debug_original_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.eml'
                )
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
    
    def process_buffer(self, raw_message: bytes, output_fd, listonly: bool = False) -> None:
        """Process email buffer."""
        hashtml = False
        self.guarded_links = 0
        
        # Parse the email content
        msg = BytesParser(policy=policy.default).parsebytes(raw_message)
        from_address = None
        to_address = None
        mode = self.config.get(Configuration.CFG_GUARD_LINK, 'off')
        capture_to = self.config.get(Configuration.CFG_GUARD_CAPTURE_TO)
        
        if mode != 'off':
            from_header = msg.get('From')
            if from_header:
                from_address = EmailHelpers.extract_email_from_header(from_header)
                if not from_address:
                    logging.warning('Unable to parse From header: %s', from_header)
            else:
                logging.warning('No From header present while guardlink enabled')
            
            if capture_to:
                to_header = msg.get('To')
                if to_header:
                    to_address = EmailHelpers.extract_email_from_header(to_header)
                    if not to_address:
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
                    html_content = EmailHelpers.decode_base64(part.get_payload(), content_charset)
                else:
                    # Decode normally if not Base64 encoded
                    html_content = part.get_payload(decode=True).decode(content_charset)
                
                if listonly:
                    self.list_images(html_content)
                    continue  # Skip processing, just list URLs
                else:
                    # Replace tracking URLs in the HTML content
                    modified_html = self.replace_tracking_urls(html_content, from_address, to_address)
                
                # Optionally, re-encode the modified HTML back to Base64 if needed
                if content_transfer_encoding == 'base64':
                    encoded_modified_html = EmailHelpers.encode_base64(modified_html)
                elif content_transfer_encoding == 'quoted-printable':
                    encoded_modified_html = quopri.encodestring(modified_html.encode('utf-8')).decode('utf-8')
                else:
                    encoded_modified_html = modified_html
                
                # Replace the part content
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
    
    def get_statistics(self) -> None:
        """Print processing statistics."""
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