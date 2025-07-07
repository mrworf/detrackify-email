"""
Static helper class containing common utilities for email processing.
"""

import re
import base64
import hashlib
import json
import logging
from typing import Optional, Dict, Any, List, Tuple


class EmailHelpers:
    """Static helper class containing common utilities for email processing."""
    
    @staticmethod
    def extract_domain_from_url(url: str) -> str:
        """Extract domain from URL."""
        domain = re.search(r'https?://([^/]+)', url)
        return domain.group(1) if domain else 'INVALID: ' + url
    
    @staticmethod
    def strip_tracking_parameters(url: str) -> Optional[str]:
        """Strip tracking parameters from URL."""
        result = None
        # Images typically don't have query parameters, so let's strip them if they exist
        match = re.search(r'(https?:\/\/[^?]+)(\??.*)', url)
        if match:
            if match.group(2) and match.group(2) != '':
                result = match.group(1)
        else:
            logging.warning(f'URL does not confirm: {url}')
        return result
    
    @staticmethod
    def decode_base64(content: bytes, charset: str = 'utf-8') -> str:
        """Decode Base64 content to string using the specified charset."""
        return base64.b64decode(content).decode(charset)
    
    @staticmethod
    def encode_base64(content: str) -> str:
        """Encode string content to Base64."""
        return base64.b64encode(content.encode('utf-8')).decode('utf-8')
    
    @staticmethod
    def create_guarded_url(payload: Dict[str, Any], guard_server: str, salt: str) -> str:
        """Create a guarded URL with hash verification."""
        b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        sha = hashlib.sha256((b64 + salt).encode()).hexdigest()
        return f"{guard_server.rstrip('/')}/guard/{sha}/{b64}"
    
    @staticmethod
    def clean_display_text(html_content: str) -> str:
        """Clean HTML content to extract display text."""
        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(html_content, 'html.parser')
        for img in soup.find_all('img'):
            alt = img.get('alt')
            img.replace_with(f'[IMAGE:{alt}]' if alt else '[IMAGE]')
        display_text = soup.get_text()
        # Clean the display text to remove excess whitespace and newlines
        return ' '.join(display_text.split())
    
    @staticmethod
    def is_subdomain(domain1: str, domain2: str) -> bool:
        """Return True if domain1 is the same as or a subdomain of domain2."""
        return domain1 == domain2 or domain1.endswith('.' + domain2)
    
    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize domain to lowercase."""
        return domain.lower() if domain else ''
    
    @staticmethod
    def parse_email_addresses(header_value: str) -> List[Tuple[str, str]]:
        """Parse email addresses from header value."""
        import email.utils
        return email.utils.getaddresses([header_value]) if header_value else []
    
    @staticmethod
    def extract_email_from_header(header_value: str) -> Optional[str]:
        """Extract email address from header value."""
        addresses = EmailHelpers.parse_email_addresses(header_value)
        if addresses and '@' in addresses[0][1]:
            return addresses[0][1]
        return None
    
    @staticmethod
    def test_url_against_patterns(url: str, patterns: List[str], context: str = "patterns") -> Optional[str]:
        """Test URL against a list of regex patterns."""
        logging.debug(f"Testing {url} against {len(patterns)} patterns in {context}")
        for i, pattern in enumerate(patterns):
            try:
                # Fix double-escaped patterns from YAML loading
                if isinstance(pattern, str):
                    original_pattern = pattern
                    pattern = pattern.replace('\\\\', '\\')
                    if original_pattern != pattern:
                        logging.debug(f"Unescaped pattern {i+1}: {original_pattern} -> {pattern}")
                
                if re.match(pattern, url):
                    logging.debug(f'Match in {context}: {url} ({pattern})')
                    return pattern
            except Exception as e:
                logging.error(f'Error testing {url} with {pattern} in {context}: {e}')
        return None
    
    @staticmethod
    def create_blank_tracker() -> str:
        """Create a 1x1 transparent PNG image as base64 data URL."""
        from PIL import Image
        from io import BytesIO
        
        # Create a 1x1 transparent image
        image = Image.new('RGBA', (1, 1), (255, 255, 255, 0))
        
        # Save the image to a BytesIO object
        buffered = BytesIO()
        image.save(buffered, format="PNG")
        
        # Encode the image in Base64
        base64_image = base64.b64encode(buffered.getvalue()).decode('utf-8')
        
        # Format it for use in an img tag
        return f"data:image/png;base64,{base64_image}"
    
    @staticmethod
    def extract_style_size(style: str, property_name: str) -> Optional[str]:
        """Extract a specific dimension from the style attribute."""
        pattern = rf'(^|\s|;){property_name}\s*:\s*([0-9]+|auto)(dp|px|%)?\s*;'
        match = re.search(pattern, style)
        return match.group(2) if match else None
    
    @staticmethod
    def is_invisible_element(style: str) -> bool:
        """Detect if an element is hidden based on its style attribute."""
        pattern = r'(display\s*:\s*none|visibility\s*:\s*hidden)'
        return re.search(pattern, style) is not None
    
    @staticmethod
    def parse_size_value(size_value) -> int:
        """Parse size value to integer, handling various formats."""
        if size_value is None:
            return -1
        if isinstance(size_value, str):
            return int(re.sub(r'\D', '', '0' + size_value))
        return int(size_value) 