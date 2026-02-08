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
from typing import Dict, Any, List, Optional, Tuple
from email import policy
from email.parser import BytesParser
from email.generator import BytesGenerator
from email.message import EmailMessage
from bs4 import BeautifulSoup
import html

from .helpers import EmailHelpers
from .configuration import Configuration
from .detector import Detector
from common.utils import SharedUtils


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
    
    def extract_urls_from_text(self, plain_text: str) -> List[str]:
        """Extract all http/https URLs from plain text."""
        # Pattern matches http:// or https:// followed by non-whitespace and non-delimiter characters
        # Stops at whitespace, <, >, ", ', ), or end of string
        url_pattern = re.compile(r'https?://[^\s<>"\'()]+')
        urls = url_pattern.findall(plain_text)
        # Return unique URLs
        return list(dict.fromkeys(urls))  # Preserves order while removing duplicates
    
    def should_guard_url(self, url: str, from_address: str, from_domain: str, mode: str, 
                        sender_is_blacklisted: bool, is_phishy: bool, msg) -> Tuple[bool, Optional[str]]:
        """Determine if a URL should be guarded and return block reason if any."""
        if not url.startswith('http'):
            return False, None
        
        guard_server = self.config.get(Configuration.CFG_GUARD_SERVER)
        if guard_server:
            guard_server_clean = guard_server.rstrip('/')
            if url.startswith(f'{guard_server_clean}/guard/'):
                # Already guarded, don't guard again
                return False, None
        
        # Check guard whitelist
        pattern = self.config.is_guard_link_whitelisted(url)
        if pattern:
            logging.debug(f'Whitelisted link {url} via {pattern}')
            return False, None
        
        # Check sender whitelist
        if from_address and self.config.is_guard_sender_whitelisted(from_address):
            logging.debug(f'Sender {from_address} is whitelisted from guarding')
            return False, None
        
        # Determine block reason and domain match
        block_reason = None
        match = False
        
        if sender_is_blacklisted:
            block_reason = 'blacklisted'
            # Force mismatch so the link is always guarded
            match = False
        elif self.config.is_blacklisted(url):
            block_reason = 'blacklisted'
            match = False
        elif is_phishy:
            block_reason = 'phishy'
            # Force mismatch so the link is always guarded
            match = False
        else:
            # Check domain matching
            link_domain = SharedUtils.extract_domain_from_url(url)
            if link_domain:
                link_domain = link_domain.lower()
                match = self.config.are_domains_aliases(link_domain, from_domain)
            else:
                match = False
        
        # Determine if should guard
        # Always guard if: sender is blacklisted, mode is 'always', mode is 'mismatch' and domains don't match, or there's a block reason
        should_guard = False
        if sender_is_blacklisted or mode == 'always' or (mode == 'mismatch' and not match) or block_reason:
            should_guard = True
        
        return should_guard, block_reason
    
    def convert_plain_to_html_with_guarded_links(self, plain_text: str, from_address: str, 
                                                 to_address: str, msg) -> Optional[str]:
        """Convert plain text to HTML with guarded links. Returns HTML if links were guarded, None otherwise."""
        # Extract URLs
        urls = self.extract_urls_from_text(plain_text)
        if not urls:
            return None
        
        # Get guard configuration
        mode = self.config.get(Configuration.CFG_GUARD_LINK, 'off')
        if mode == 'off':
            return None
        
        if not self.config.get(Configuration.CFG_GUARD_ADD_HTML_FOR_PLAIN, False):
            return None
        
        # Get sender information
        from_domain = None
        sender_is_blacklisted = False
        is_phishy = False
        sender_display_name = ''
        
        if from_address and '@' in from_address:
            from_domain = from_address.split('@')[-1].lower()
            sender_is_blacklisted = self.config.is_sender_blacklisted(from_address)
            
            # Extract display name from the From header
            from_header = msg.get('From')
            if from_header:
                from email.utils import parseaddr
                sender_display_name, _ = parseaddr(from_header)
            
            # Check for phishing if guard-phishy is enabled
            if self.config.get(Configuration.CFG_GUARD_PHISHY, False) and sender_display_name:
                is_phishy = SharedUtils.detect_phishing_mismatch(from_address, sender_display_name)
                if is_phishy:
                    logging.info(f"Phishing detected: sender '{sender_display_name}' <{from_address}> appears suspicious")
                    mode = 'always'
        
        if not from_domain:
            return None
        
        # Check which URLs need guarding
        urls_to_guard = {}
        guard_server = self.config.get(Configuration.CFG_GUARD_SERVER).rstrip('/') if self.config.get(Configuration.CFG_GUARD_SERVER) else None
        salt = self.config.get(Configuration.CFG_GUARD_SALT)
        
        if not guard_server or not salt:
            return None
        
        for url in urls:
            should_guard, block_reason = self.should_guard_url(
                url, from_address, from_domain, mode, sender_is_blacklisted, is_phishy, msg
            )
            if should_guard:
                # Create guarded link
                display_text = url  # Use URL as display text for plain text emails
                to_address_clean = to_address.strip() if to_address and self.config.get(Configuration.CFG_GUARD_CAPTURE_TO) else None
                guarded_url = SharedUtils.create_guard_link(
                    guard_server,
                    salt,
                    display_text,
                    from_address.strip() if from_address else '',
                    url.strip(),
                    to_address_clean,
                    block_reason,
                    sender_display_name
                )
                urls_to_guard[url] = guarded_url
                self.guarded_links += 1
        
        # If no URLs need guarding, return None
        if not urls_to_guard:
            return None
        
        # Escape HTML special characters
        escaped_text = html.escape(plain_text)
        
        # Replace URLs with guarded links (in reverse order to avoid replacing parts of already-replaced URLs)
        for original_url, guarded_url in sorted(urls_to_guard.items(), key=lambda x: len(x[0]), reverse=True):
            # Escape the original URL for HTML replacement
            escaped_original = html.escape(original_url)
            # Replace with HTML link
            escaped_text = escaped_text.replace(
                escaped_original,
                f'<a href="{html.escape(guarded_url)}">{escaped_original}</a>'
            )
        
        # Wrap in HTML structure with Courier font
        html_content = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body {{ font-family: 'Courier New', Courier, monospace; white-space: pre-wrap; }}
</style>
</head>
<body>
{escaped_text}
</body>
</html>"""
        
        return html_content
    
    def process_strip_params(self, img_tag) -> tuple:
        """Process an HTML img tag and strip tracking parameters from its src URL."""
        original_url = img_tag.get('src', '')
        if not original_url:
            return original_url, []
        
        # Strip tracking parameters using the detector
        stripped_url = self.detector.strip_query_params(original_url)
        
        # If URL changed, return the stripped URL and reason
        if stripped_url != original_url:
            return stripped_url, ['Parameter stripping']
        else:
            return original_url, []
    
    def replace_tracking_urls(self, html_content: str, from_address: str = None, to_address: str = None, msg=None) -> str:
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
                domain = SharedUtils.extract_domain_from_url(url)
                if domain:
                    domain = domain.lower()
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
        is_phishy = False
        sender_display_name = ''
        
        if from_address and '@' in from_address:
            logging.debug(f"Checking sender_is_blacklisted for: '{from_address}'")
            from_domain = from_address.split('@')[-1].lower()
            sender_is_blacklisted = self.config.is_sender_blacklisted(from_address)
            logging.debug(f"From address: {from_address}, domain: {from_domain}, sender blacklisted: {sender_is_blacklisted}")
            
            # Extract display name from the From header for use in guard links
            from_header = msg.get('From')
            if from_header:
                from email.utils import parseaddr
                sender_display_name, _ = parseaddr(from_header)
            
            # Check for phishing if guard-phishy is enabled
            if self.config.get(Configuration.CFG_GUARD_PHISHY, False) and sender_display_name:
                is_phishy = SharedUtils.detect_phishing_mismatch(from_address, sender_display_name)
                if is_phishy:
                    logging.info(f"Phishing detected: sender '{sender_display_name}' <{from_address}> appears suspicious")
                    # Override guard mode to 'always' when phishing is detected
                    mode = 'always'
                else:
                    logging.debug(f"No phishing detected for sender: '{sender_display_name}' <{from_address}>")
        
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
                    
                    # Use should_guard_url to determine if link should be guarded
                    should_guard, block_reason = self.should_guard_url(
                        href, from_address, from_domain, mode, sender_is_blacklisted, is_phishy, msg
                    )
                    
                    if not should_guard:
                        logging.debug(f"Link {i+1} KEEPING original: {href}")
                        continue
                    
                    # Get domain match info for logging
                    link_domain = SharedUtils.extract_domain_from_url(href)
                    if link_domain:
                        link_domain = link_domain.lower()
                        match = self.config.are_domains_aliases(link_domain, from_domain)
                        logging.debug(f"Link {i+1} domain match: {link_domain} vs {from_domain} = {match}")
                    else:
                        match = False
                    
                    # Link should be guarded
                    logging.debug(f"Link {i+1} GUARDING: {href}")
                    logging.debug(f"Link {i+1} guard reason: sender_blacklisted={sender_is_blacklisted}, mode={mode}, domain_match={match}, block_reason={block_reason}")
                    display_html = link.decode_contents()
                    logging.debug(f"Link {i+1} original display HTML: {display_html}")
                    display_text = SharedUtils.clean_display_text(display_html)
                    logging.debug(f"Link {i+1} cleaned display text: {display_text}")
                    display_text_clean = display_text.strip() if display_text else ''
                    from_address_clean = from_address.strip() if from_address else ''
                    href_clean = href.strip() if href else ''
                    to_address_clean = to_address.strip() if to_address and self.config.get(Configuration.CFG_GUARD_CAPTURE_TO) else None
                    
                    logging.debug(f"Link {i+1} creating guard link with: display='{display_text_clean}', from='{from_address_clean}', url='{href_clean}', to='{to_address_clean}', block_reason='{block_reason}', sender_display='{sender_display_name}'")
                    salt = self.config.get(Configuration.CFG_GUARD_SALT)
                    new_href = SharedUtils.create_guard_link(
                        guard_server, 
                        salt, 
                        display_text_clean, 
                        from_address_clean, 
                        href_clean, 
                        to_address_clean, 
                        block_reason,
                        sender_display_name
                    )
                    logging.debug(f"Link {i+1} guarded: {href} -> {new_href[:50]}...")
                    logging.debug(f"Link {i+1} full guarded URL: {new_href}")
                    link['href'] = new_href
                    self.guarded_links += 1
        
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
            self.config.add_to_cache_blacklist(f'{self.detector.strip_tracking_parameters(url)}.*')
            stripped_url = self.blank_tracker
            reason.append('No image')
        else:
            reason = result['reason']
            if 'Tracker' in result['reason']:
                self.config.add_to_cache_blacklist(f'{self.detector.strip_tracking_parameters(url)}.*')
                stripped_url = self.blank_tracker
            elif stripped_url != url:
                stripped_url = result['url']
                reason.append('Rewritten')
                
                logging.debug(f'Stripped {url} to {stripped_url}')
                
                self.config.add_rewrite(self.detector.strip_tracking_parameters(url) + '.*', stripped_url)
                self.config.add_to_cache_whitelist(f'{stripped_url}')
        return stripped_url, reason
    
    def process_file(self, email_path: str, output_path: str, listonly: bool = False, hardfail: bool = False) -> None:
        """Process an email file."""
        with open(email_path, 'rb') as fd_in:
            with open(output_path, 'wb') as fd_out:
                self.process(fd_in, fd_out, hardfail=hardfail, listonly=listonly)
    
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
            self.process_buffer(raw_message, output_fd, listonly=listonly, hardfail=hardfail)
        except Exception as e:
            logging.exception(f"Error: {e}")
            # Ensure we still allow message to be delivered
            if hardfail:
                logging.error('Hardfail enabled, stopping processing')
                sys.exit(1)
            output_fd.write(raw_message)
    
    def process_buffer(self, raw_message: bytes, output_fd, listonly: bool = False, hardfail: bool = False) -> None:
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
                from_address = SharedUtils.extract_email_from_header(from_header)
                if not from_address:
                    logging.warning('Unable to parse From header: %s', from_header)
            else:
                logging.warning('No From header present while guardlink enabled')
            
            if capture_to:
                to_header = msg.get('To')
                if to_header:
                    to_address = SharedUtils.extract_email_from_header(to_header)
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
                    try:
                        html_content = SharedUtils.decode_base64(part.get_payload(), content_charset)
                    except UnicodeDecodeError as e:
                        # In hardfail mode, re-raise the exception
                        if hardfail:
                            raise
                        # SharedUtils.decode_base64 already handles errors, but just in case
                        html_content = SharedUtils.decode_base64(part.get_payload(), content_charset)
                else:
                    # Decode normally if not Base64 encoded
                    try:
                        html_content = part.get_payload(decode=True).decode(content_charset)
                    except UnicodeDecodeError as e:
                        # In hardfail mode, re-raise the exception
                        if hardfail:
                            raise
                        # Try with error handling - replace invalid characters
                        try:
                            html_content = part.get_payload(decode=True).decode(content_charset, errors='replace')
                        except Exception:
                            # If all else fails, try latin-1 which can decode any byte sequence
                            html_content = part.get_payload(decode=True).decode('latin-1', errors='replace')
                    except Exception as e:
                        # In hardfail mode, re-raise the exception
                        if hardfail:
                            raise
                        # If decoding fails, skip this part
                        logging.warning(f"Failed to decode email part content: {e}")
                        continue
                
                if listonly:
                    self.list_images(html_content)
                    continue  # Skip processing, just list URLs
                else:
                    # Replace tracking URLs in the HTML content
                    modified_html = self.replace_tracking_urls(html_content, from_address, to_address, msg)
                
                # Optionally, re-encode the modified HTML back to Base64 if needed
                if content_transfer_encoding == 'base64':
                    encoded_modified_html = SharedUtils.encode_base64(modified_html)
                elif content_transfer_encoding == 'quoted-printable':
                    encoded_modified_html = quopri.encodestring(modified_html.encode('utf-8')).decode('utf-8')
                else:
                    encoded_modified_html = modified_html
                
                # Replace the part content
                part.set_payload(encoded_modified_html, charset='utf-8')
        
        # Check if we need to add HTML part for plain text emails
        html_generated = False
        if not hashtml and not listonly:
            # Check if feature is enabled and guard is enabled
            add_html_for_plain = self.config.get(Configuration.CFG_GUARD_ADD_HTML_FOR_PLAIN, False)
            mode = self.config.get(Configuration.CFG_GUARD_LINK, 'off')
            
            if add_html_for_plain and mode != 'off' and from_address:
                # Find text/plain parts
                plain_parts = []
                for part in msg.walk():
                    if part.get_content_type() == 'text/plain':
                        plain_parts.append(part)
                
                if plain_parts:
                    # Process the first text/plain part (typically there's only one)
                    plain_part = plain_parts[0]
                    content_transfer_encoding = plain_part.get('Content-Transfer-Encoding', '').lower()
                    content_charset = plain_part.get_content_charset() or 'utf-8'
                    
                    # Extract plain text content
                    try:
                        if content_transfer_encoding == 'base64':
                            plain_text = SharedUtils.decode_base64(plain_part.get_payload(), content_charset)
                        elif content_transfer_encoding == 'quoted-printable':
                            plain_text = quopri.decodestring(plain_part.get_payload()).decode(content_charset)
                        else:
                            plain_text = plain_part.get_payload(decode=True).decode(content_charset)
                    except Exception as e:
                        if hardfail:
                            raise
                        logging.warning(f"Failed to decode plain text part: {e}")
                        plain_text = None
                    
                    if plain_text:
                        # Convert to HTML with guarded links
                        html_content = self.convert_plain_to_html_with_guarded_links(
                            plain_text, from_address, to_address, msg
                        )
                        
                        if html_content:
                            # HTML was generated, need to add it as a part
                            html_generated = True
                            
                            # Create HTML part
                            html_part = EmailMessage()
                            html_part.set_content(html_content, subtype='html', charset='utf-8')
                            
                            # Check if message is multipart
                            if msg.is_multipart():
                                # Check if it's multipart/alternative
                                main_content_type = msg.get_content_type()
                                if main_content_type == 'multipart/alternative':
                                    # Add HTML part to existing multipart/alternative
                                    msg.attach(html_part)
                                else:
                                    # Need to wrap in multipart/alternative
                                    # Find where text/plain is and wrap it
                                    # This is complex, so we'll create a new multipart/alternative container
                                    # For now, let's add it directly - email clients should handle it
                                    msg.attach(html_part)
                            else:
                                # Single part message - convert to multipart/alternative
                                # Get original payload
                                original_payload = msg.get_payload()
                                
                                # Create text/plain part
                                text_part = EmailMessage()
                                text_part.set_content(original_payload, subtype='plain', charset=content_charset)
                                if content_transfer_encoding:
                                    text_part['Content-Transfer-Encoding'] = content_transfer_encoding
                                
                                # Clear current payload and set as multipart
                                msg.set_payload([])
                                msg.set_type('multipart/alternative')
                                
                                # Attach parts
                                msg.attach(text_part)
                                msg.attach(html_part)
        
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
        
        # Add header if HTML was generated from plain text
        if html_generated:
            msg.add_header('X-Detrackify-Generated-HTML', 'true')
        
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