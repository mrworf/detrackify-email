"""
Shared utility functions used by both detrackify_email and detrackify_guard.
"""

import re
import base64
import hashlib
import json
import logging
import urllib.parse
from typing import Optional, Dict, Any, List, Tuple


class SharedUtils:
    """Shared utility functions for domain processing, URL handling, and common operations."""
    
    # Common regex patterns
    SHA256_PATTERN = re.compile(r'^[a-f0-9]{64}$')
    BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/=\r\n_-]+$')
    LANGUAGE_CODE_PATTERN = re.compile(r'^[a-z]{2,3}(-[A-Z]{2})?$')
    URL_PATTERN = re.compile(r'^https?://[^\s]+$')
    DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$')
    
    # ============================================================================
    # Domain Processing Functions
    # ============================================================================
    
    @staticmethod
    def extract_domain_from_url(url: str) -> Optional[str]:
        """Extract domain from URL using urllib.parse for better reliability."""
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                return None
            # Only allow http and https schemes
            if parsed.scheme not in ('http', 'https'):
                return None
            # Remove port if present
            domain = parsed.netloc.split(':')[0].lower()
            return domain if domain else None
        except Exception:
            return None
    
    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize domain for comparison."""
        if not domain:
            return ""
        return domain.lower().strip()
    
    @staticmethod
    def is_subdomain(domain1: str, domain2: str) -> bool:
        """Check if domain1 is the same as or a subdomain of domain2."""
        if not domain1 or not domain2:
            return False
        domain1 = SharedUtils.normalize_domain(domain1)
        domain2 = SharedUtils.normalize_domain(domain2)
        return domain1 == domain2 or domain1.endswith('.' + domain2)
    
    @staticmethod
    def share_parent_domain(domain1: str, domain2: str) -> bool:
        """Check if two domains share the same parent domain (e.g., both are subdomains of the same domain)."""
        if not domain1 or not domain2:
            return False
        
        domain1 = SharedUtils.normalize_domain(domain1)
        domain2 = SharedUtils.normalize_domain(domain2)
        
        # If they're the same, they share the same parent
        if domain1 == domain2:
            return True
            
        # Split into parts and check if they have at least 2 parts
        parts1 = domain1.split('.')
        parts2 = domain2.split('.')
        
        if len(parts1) < 2 or len(parts2) < 2:
            return False
            
        # Check if they share the same parent domain (last 2 parts)
        parent1 = '.'.join(parts1[-2:])
        parent2 = '.'.join(parts2[-2:])
        
        return parent1 == parent2

    @staticmethod
    def are_domains_aliases(domain1: str, domain2: str, aliases: Dict[str, Any] = None) -> bool:
        """
        Check if two domains are aliases of each other.
        
        Args:
            domain1: First domain to compare
            domain2: Second domain to compare  
            aliases: Optional dictionary of domain aliases in format {owner: [alias1, alias2, ...]}
        
        Returns:
            True if domains are aliases, False otherwise
        """
        if not domain1 or not domain2:
            return False
        
        domain1 = SharedUtils.normalize_domain(domain1)
        domain2 = SharedUtils.normalize_domain(domain2)
        
        # Direct match
        if domain1 == domain2:
            return True
        
        # Check subdomain relationship
        if SharedUtils.is_subdomain(domain1, domain2) or SharedUtils.is_subdomain(domain2, domain1):
            return True
        
        # Check if they share the same parent domain (e.g., both are subdomains of the same domain)
        if SharedUtils.share_parent_domain(domain1, domain2):
            logging.debug(f'Domain parent match: {domain1} and {domain2} share same parent domain')
            return True
        
        # Check configured aliases if provided
        if aliases:
            for owner, alias_list in aliases.items():
                owner = SharedUtils.normalize_domain(owner)
                if isinstance(alias_list, str):
                    alias_list = [alias_list]
                elif not isinstance(alias_list, list):
                    continue
                
                alias_list = [SharedUtils.normalize_domain(alias) for alias in alias_list]
                alias_group = {owner} | set(alias_list)
                
                domain1_in_group = (domain1 == owner or domain1 in alias_list or 
                                   any(SharedUtils.is_subdomain(domain1, d) for d in alias_group))
                domain2_in_group = (domain2 == owner or domain2 in alias_list or 
                                   any(SharedUtils.is_subdomain(domain2, d) for d in alias_group))
                
                if domain1_in_group and domain2_in_group:
                    logging.debug(f'Domain alias match: {domain1} and {domain2} in {owner} -> {alias_list}')
                    return True
        
        return False
    
    # ============================================================================
    # URL Processing Functions
    # ============================================================================
    
    @staticmethod
    def strip_query_parameters(url: str, strip_prefixes: list) -> str:
        """Remove query parameters starting with configured prefixes (case-insensitive)."""
        if not strip_prefixes or not url:
            return url
        
        try:
            parts = urllib.parse.urlsplit(url)
        except Exception:
            return url
        
        if not parts.query:
            return url
        
        params = parts.query.split("&")
        keep = []
        
        # Convert prefixes to lowercase for case-insensitive matching
        lower_prefixes = [prefix.lower() for prefix in strip_prefixes]
        
        for param in params:
            if not param:  # Skip empty parameters
                continue
            key = param.split("=")[0].lower()
            if any(key.startswith(p) for p in lower_prefixes):
                break  # Stop processing when a matching prefix is found
            keep.append(param)
        
        new_query = "&".join(keep)
        parts = parts._replace(query=new_query)
        return urllib.parse.urlunsplit(parts)
    
    @staticmethod
    def normalize_url_for_comparison(url: str) -> str:
        """
        Normalize URL for comparison by removing trailing slashes and trailing question marks.
        
        Browsers and servers treat these URLs as equivalent:
        - https://example.com/ == https://example.com
        - https://example.com? == https://example.com
        - https://example.com/? == https://example.com
        
        Args:
            url: URL string to normalize
            
        Returns:
            Normalized URL string
        """
        if not url:
            return url
        
        # Remove trailing question mark and trailing slash
        # rstrip('/?') removes both / and ? from the end
        return url.rstrip('/?')
    
    @staticmethod
    def extract_url_info(url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Extract scheme, domain, and path from URL. Only supports http/https."""
        if not url:
            return None, None, None
        try:
            parsed = urllib.parse.urlparse(url)
            # Only consider it valid if it has a scheme and netloc, and scheme is http/https
            if not parsed.scheme or not parsed.netloc:
                return None, None, None
            if parsed.scheme not in ("http", "https"):
                return None, None, None
            return parsed.scheme, parsed.netloc, parsed.path
        except Exception:
            return None, None, None
    
    # ============================================================================
    # Base64 and Hash Functions
    # ============================================================================
    
    @staticmethod
    def decode_base64(content, charset: str = 'utf-8') -> str:
        """
        Decode Base64 content to string using the specified charset.
        
        Accepts both bytes and strings (base64.b64decode handles both).
        Automatically strips whitespace including newlines.
        """
        try:
            return base64.b64decode(content).decode(charset)
        except UnicodeDecodeError:
            # Try with error handling - replace invalid characters
            try:
                return base64.b64decode(content).decode(charset, errors='replace')
            except Exception:
                # If all else fails, try latin-1 which can decode any byte sequence
                return base64.b64decode(content).decode('latin-1', errors='replace')
        except Exception:
            # If base64 decoding fails, return the original content as string
            return content.decode(charset, errors='replace') if isinstance(content, bytes) else str(content)
    
    @staticmethod
    def encode_base64(content: str) -> str:
        """
        Encode string content to Base64 with email formatting.
        
        Formats base64 content according to RFC 2045:
        - Wraps lines at 76 characters
        - Adds trailing \\n\\n for MTA compatibility
        """
        encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        # Wrap at 76 characters per line (RFC 2045 standard)
        wrapped = '\n'.join(encoded[i:i+76] for i in range(0, len(encoded), 76))
        # Add trailing newlines that MTAs expect
        return wrapped + '\n\n'
    
    @staticmethod
    def generate_hash(data: str, salt: str) -> str:
        """Generate SHA-256 hash of data with salt."""
        return hashlib.sha256((data + salt).encode()).hexdigest()
    
    @staticmethod
    def verify_hash(data: str, salt: str, expected_hash: str) -> bool:
        """Verify hash matches expected value."""
        return SharedUtils.generate_hash(data, salt) == expected_hash
    
    @staticmethod
    def decode_base64_payload(data: str) -> Optional[Dict[str, Any]]:
        """Decode base64 payload and parse as JSON."""
        try:
            decoded = base64.urlsafe_b64decode(data).decode()
            return json.loads(decoded)
        except Exception as e:
            logging.debug(f"Failed to decode base64 payload: {e}")
            return None
    
    @staticmethod
    def create_guarded_url(payload: Dict[str, Any], guard_server: str, salt: str) -> str:
        """Create a guarded URL with hash verification."""
        b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        sha = hashlib.sha256((b64 + salt).encode()).hexdigest()
        return f"{guard_server.rstrip('/')}/guard/{sha}/{b64}"
    
    # ============================================================================
    # Validation Functions
    # ============================================================================
    
    @staticmethod
    def validate_sha256(sha: str) -> bool:
        """Validate SHA-256 format (64 hex characters)."""
        return bool(sha and SharedUtils.SHA256_PATTERN.match(sha))
    
    @staticmethod
    def validate_base64(data: str) -> bool:
        """Validate base64 format."""
        if not data:
            return False
        # Check if it matches the pattern
        if not SharedUtils.BASE64_PATTERN.match(data):
            return False
        # Check if it has proper padding
        if len(data) % 4 != 0:
            return False
        return True
    
    @staticmethod
    def validate_language_code(lang_code: str) -> bool:
        """Validate language code format."""
        return bool(lang_code and SharedUtils.LANGUAGE_CODE_PATTERN.match(lang_code))
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format."""
        return bool(url and SharedUtils.URL_PATTERN.match(url))
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate domain format."""
        return bool(domain and SharedUtils.DOMAIN_PATTERN.match(domain))
    
    # ============================================================================
    # Language Processing Functions
    # ============================================================================
    
    @staticmethod
    def parse_accept_language(accept_language: str) -> list:
        """Parse Accept-Language header into list of language codes."""
        if not isinstance(accept_language, str):
            return []
        
        langs = []
        for part in accept_language.split(','):
            part = part.strip()
            if not part:
                continue
            try:
                lang = part.split(';')[0].strip().lower()
                # Only add valid language codes
                if SharedUtils.validate_language_code(lang) or SharedUtils.validate_language_code(lang.split('-')[0]):
                    langs.append(lang)
            except Exception:
                continue
        
        return langs
    
    # ============================================================================
    # Utility Functions
    # ============================================================================
    
    @staticmethod
    def sanitize_string(text: str, max_length: int = 1000) -> str:
        """Sanitize string for safe display."""
        if not text:
            return ""
        
        # Truncate if too long
        if len(text) > max_length:
            text = text[:max_length] + "..."
        
        # Basic HTML escaping (can be enhanced with markupsafe.escape)
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        
        return text
    
    @staticmethod
    def safe_json_loads(data: str, default: Any = None) -> Any:
        """Safely parse JSON string with error handling."""
        try:
            return json.loads(data)
        except Exception as e:
            logging.debug(f"Failed to parse JSON: {e}")
            return default
    
    @staticmethod
    def merge_dicts(dict1: dict, dict2: dict) -> dict:
        """Merge two dictionaries, with dict2 values overriding dict1."""
        result = dict1.copy()
        result.update(dict2)
        return result 

    @staticmethod
    def test_url_against_patterns(url: str, patterns: list, context: str = "patterns") -> Optional[str]:
        """Test URL against a list of regex patterns."""
        logging.debug(f"Testing {url} against {len(patterns)} patterns in {context}")
        for i, pattern in enumerate(patterns):
            try:
                # Fix double-escaped patterns from YAML loading
                if isinstance(pattern, str):
                    original_pattern = pattern
                    pattern = pattern.replace('\\\\\\\\', '\\\\')
                    if original_pattern != pattern:
                        logging.debug(f"Unescaped pattern {i+1}: {original_pattern} -> {pattern}")
                if re.match(pattern, url):
                    logging.debug(f'Match in {context} pattern {i+1}: {pattern}')
                    return pattern
            except re.error as e:
                logging.warning(f"Invalid regex pattern {i+1} in {context}: {pattern} - {e}")
        return None

    # ============================================================================
    # Email Processing Functions
    # ============================================================================

    @staticmethod
    def parse_email_addresses(header_value: str) -> List[Tuple[str, str]]:
        """Parse email addresses from header value."""
        import email.utils
        return email.utils.getaddresses([header_value]) if header_value else []

    @staticmethod
    def extract_email_from_header(header_value: str) -> Optional[str]:
        """Extract email address from header value."""
        addresses = SharedUtils.parse_email_addresses(header_value)
        if addresses and '@' in addresses[0][1]:
            return addresses[0][1]
        return None

    # ============================================================================
    # HTML Processing Functions
    # ============================================================================

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

    @staticmethod
    def strip_tracking_parameters(url: str) -> Optional[str]:
        """Strip tracking parameters from URL (removes query string if present)."""
        result = None
        match = re.search(r'(https?:\/\/[^?]+)(\??.*)', url)
        if match:
            if match.group(2) and match.group(2) != '':
                result = match.group(1)
        else:
            logging.warning(f'URL does not confirm: {url}')
        return result

    @staticmethod
    def is_safe_url(url: str, allowed_schemes: List[str] = None) -> bool:
        """Check if URL uses safe schemes (http, https by default)."""
        if not url:
            return False
        allowed_schemes = allowed_schemes or ['http', 'https']
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.scheme in allowed_schemes and parsed.netloc
        except Exception:
            return False

    @staticmethod
    def parse_guard_url(url: str) -> Optional[Dict[str, str]]:
        """Parse guard server URL to extract components."""
        if not url:
            return None
        # Pattern: /guard/{sha}/{data}
        match = re.search(r'/guard/([^/]+)/([^/]+)', url)
        if match:
            return {
                'sha': match.group(1),
                'data': match.group(2)
            }
        return None

    @staticmethod
    def create_guard_payload(display: str, from_email: str, url: str, to_address: str = None, block_reason: str = None, sender_display: str = None) -> Dict[str, Any]:
        """Create standardized guard payload."""
        payload = {
            'display': display,
            'from': from_email,
            'url': url,
        }
        if to_address:
            payload['to'] = to_address
        if block_reason:
            payload['block'] = block_reason
        if sender_display:
            payload['sender_display'] = sender_display
        return payload

    @staticmethod
    def create_guard_link(server: str, salt: str, display: str, from_email: str, url: str, to_address: str = None, block_reason: str = None, sender_display: str = None) -> str:
        """Create complete guard link with hash and payload."""
        payload = SharedUtils.create_guard_payload(display, from_email, url, to_address, block_reason, sender_display)
        return SharedUtils.create_guarded_url(payload, server, salt)

    @staticmethod
    def verify_guard_link(url: str, salt: str) -> Optional[Dict[str, Any]]:
        """Verify and decode guard link."""
        components = SharedUtils.parse_guard_url(url)
        if not components:
            return None
        
        sha = components['sha']
        data = components['data']
        
        if not SharedUtils.verify_hash(data, salt, sha):
            return None
        
        return SharedUtils.decode_base64_payload(data) 

    @staticmethod
    def detect_phishing_mismatch(sender_email, display_name):
        """
        Detect potential phishing based on sender email vs display name mismatch.
        
        Args:
            sender_email: The email address from the 'From' header
            display_name: The display name from the 'From' header
            
        Returns:
            bool: True if potential phishing detected, False otherwise
        """
        if not sender_email or not display_name:
            return False
            
        # Extract email address if it's in "Display Name <email@domain.com>" format
        from email.utils import parseaddr
        _, email_addr = parseaddr(sender_email)
        
        if '@' not in email_addr:
            return False
            
        domain = email_addr.split('@')[1].lower()
        # Get domain root without TLD
        domain_root = domain.split('.')[0]
        
        # Split display name into words, filter short/meaningless ones
        import re
        display_tokens = [w.lower() for w in re.findall(r'\w+', display_name) if len(w) > 2]
        
        # Main check: Is there *any* overlap between display name and domain?
        overlap = any(token in domain_root for token in display_tokens)
        
        # Return True if NO overlap detected (suspicious)
        return not overlap 