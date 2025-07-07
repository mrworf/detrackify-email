"""Utility functions for the guard server."""

import base64
import hashlib
import logging
import os
import re
import urllib.parse
from typing import Optional, Tuple, Dict, Any


class GuardUtils:
    """Static utility class containing common helper functions."""
    
    # Common regex patterns
    SHA256_PATTERN = re.compile(r'^[a-f0-9]{64}$')
    BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/=\r\n_-]+$')
    LANGUAGE_CODE_PATTERN = re.compile(r'^[a-z]{2,3}(-[A-Z]{2})?$')
    URL_PATTERN = re.compile(r'^https?://[^\s]+$')
    DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$')
    
    # Allowed file extensions for resources
    ALLOWED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.ico'}
    
    @staticmethod
    def validate_sha256(sha: str) -> bool:
        """Validate SHA-256 format (64 hex characters)."""
        return bool(sha and GuardUtils.SHA256_PATTERN.match(sha))
    
    @staticmethod
    def validate_base64(data: str) -> bool:
        """Validate base64 format."""
        if not data:
            return False
        # Check if it matches the pattern
        if not GuardUtils.BASE64_PATTERN.match(data):
            return False
        # Check if it has proper padding
        if len(data) % 4 != 0:
            return False
        return True
    
    @staticmethod
    def validate_language_code(lang_code: str) -> bool:
        """Validate language code format."""
        return bool(lang_code and GuardUtils.LANGUAGE_CODE_PATTERN.match(lang_code))
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format."""
        return bool(url and GuardUtils.URL_PATTERN.match(url))
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate domain format."""
        return bool(domain and GuardUtils.DOMAIN_PATTERN.match(domain))
    
    @staticmethod
    def generate_hash(data: str, salt: str) -> str:
        """Generate SHA-256 hash of data with salt."""
        return hashlib.sha256((data + salt).encode()).hexdigest()
    
    @staticmethod
    def verify_hash(data: str, salt: str, expected_hash: str) -> bool:
        """Verify hash matches expected value."""
        return GuardUtils.generate_hash(data, salt) == expected_hash
    
    @staticmethod
    def decode_base64_payload(data: str) -> Optional[Dict[str, Any]]:
        """Decode base64 payload and parse as JSON."""
        try:
            decoded = base64.urlsafe_b64decode(data).decode()
            import json
            return json.loads(decoded)
        except Exception as e:
            logging.debug(f"Failed to decode base64 payload: {e}")
            return None
    
    @staticmethod
    def extract_domain_from_url(url: str) -> Optional[str]:
        """Extract domain from URL."""
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
    def strip_query_parameters(url: str, strip_prefixes: list) -> str:
        """Remove query parameters starting with configured prefixes."""
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
        for param in params:
            if not param:  # Skip empty parameters
                continue
            key = param.split("=")[0]
            if any(key.startswith(p) for p in strip_prefixes):
                break  # Stop processing when a matching prefix is found
            keep.append(param)
        
        new_query = "&".join(keep)
        parts = parts._replace(query=new_query)
        return urllib.parse.urlunsplit(parts)
    
    @staticmethod
    def validate_path_security(path: str, base_dir: str) -> bool:
        """Validate path for security (prevent path traversal)."""
        try:
            normalized_path = os.path.normpath(path)
            if normalized_path.startswith('..') or normalized_path.startswith('/'):
                return False
            
            full_path = os.path.join(base_dir, normalized_path)
            real_path = os.path.realpath(full_path)
            base_real = os.path.realpath(base_dir)
            
            return real_path.startswith(base_real)
        except OSError:
            return False
    
    @staticmethod
    def validate_file_extension(filename: str, allowed_extensions: set = None) -> bool:
        """Validate file extension."""
        if allowed_extensions is None:
            allowed_extensions = GuardUtils.ALLOWED_EXTENSIONS
        
        ext = os.path.splitext(filename)[1].lower()
        return bool(ext and ext in allowed_extensions)
    
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
                if GuardUtils.validate_language_code(lang) or GuardUtils.validate_language_code(lang.split('-')[0]):
                    langs.append(lang)
            except Exception:
                continue
        
        return langs
    
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
        domain1 = GuardUtils.normalize_domain(domain1)
        domain2 = GuardUtils.normalize_domain(domain2)
        return domain1 == domain2 or domain1.endswith('.' + domain2)
    
    @staticmethod
    def extract_url_info(url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Extract scheme, domain, and path from URL."""
        if not url:
            return None, None, None
        try:
            parsed = urllib.parse.urlparse(url)
            # Only consider it valid if it has a scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return None, None, None
            return parsed.scheme, parsed.netloc, parsed.path
        except Exception:
            return None, None, None
    
    @staticmethod
    def create_secure_filename(filename: str) -> str:
        """Create a secure filename by removing dangerous characters."""
        # Remove or replace dangerous characters
        dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Remove leading/trailing spaces and dots
        filename = filename.strip('. ')
        
        # Ensure filename is not empty
        if not filename:
            filename = 'unnamed'
        
        return filename
    
    @staticmethod
    def format_time_elapsed(seconds: float) -> str:
        """Format elapsed time for logging."""
        if seconds < 1:
            return f"{seconds:.3f}s"
        elif seconds < 60:
            return f"{seconds:.2f}s"
        else:
            minutes = int(seconds // 60)
            remaining_seconds = seconds % 60
            return f"{minutes}m {remaining_seconds:.1f}s"
    
    @staticmethod
    def safe_json_loads(data: str, default: Any = None) -> Any:
        """Safely parse JSON string with error handling."""
        try:
            import json
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