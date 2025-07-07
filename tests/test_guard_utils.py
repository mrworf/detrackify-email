#!/usr/bin/env python3
"""Unit tests for GuardUtils class."""

import os
import sys
import tempfile
import unittest
import json
import base64
import hashlib

# Add the parent directory to the path so we can import guard modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from guard.utils import GuardUtils


class TestGuardUtilsValidation(unittest.TestCase):
    """Test validation functions in GuardUtils."""
    
    def test_validate_sha256_valid(self):
        """Test SHA-256 validation with valid hashes."""
        valid_hashes = [
            'a' * 64,
            'f' * 64,
            '0123456789abcdef' * 4,
            'deadbeef' * 8
        ]
        for sha in valid_hashes:
            self.assertTrue(GuardUtils.validate_sha256(sha), f"Should validate: {sha}")
    
    def test_validate_sha256_invalid(self):
        """Test SHA-256 validation with invalid hashes."""
        invalid_hashes = [
            '',  # Empty
            'a' * 63,  # Too short
            'a' * 65,  # Too long
            'g' * 64,  # Invalid character
            'a' * 63 + 'G',  # Invalid character at end
        ]
        for sha in invalid_hashes:
            self.assertFalse(GuardUtils.validate_sha256(sha), f"Should not validate: {sha}")
    
    def test_validate_base64_valid(self):
        """Test base64 validation with valid data."""
        valid_data = [
            'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=',
            'MTIzNDU2Nzg5MA==',
            'SGVsbG8gV29ybGQ=',
            'dGVzdA==',
            'cGFzc3dvcmQ=',
            'ZGF0YQ==',
        ]
        for data in valid_data:
            self.assertTrue(GuardUtils.validate_base64(data), f"Should validate: {data}")
    
    def test_validate_base64_invalid(self):
        """Test base64 validation with invalid data."""
        invalid_data = [
            '',  # Empty
            'invalid base64!@#',
            'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo',  # Missing padding
            'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo==',  # Extra padding
            'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo!',  # Invalid character
        ]
        for data in invalid_data:
            self.assertFalse(GuardUtils.validate_base64(data), f"Should not validate: {data}")
    
    def test_validate_language_code_valid(self):
        """Test language code validation with valid codes."""
        valid_codes = [
            'en',
            'es',
            'fr',
            'de',
            'zh',
            'ar',
            'en-US',
            'es-ES',
            'fr-FR',
            'de-DE',
            'zh-CN',
            'ar-SA',
        ]
        for code in valid_codes:
            self.assertTrue(GuardUtils.validate_language_code(code), f"Should validate: {code}")
    
    def test_validate_language_code_invalid(self):
        """Test language code validation with invalid codes."""
        invalid_codes = [
            '',  # Empty
            'a',  # Too short
            'EN',  # Uppercase
            'en-us',  # Lowercase region
            'en_US',  # Underscore
            'en-US-EXTRA',  # Too many parts
            '123',  # Numbers
            'en-',  # Missing region
            '-US',  # Missing language
        ]
        for code in invalid_codes:
            self.assertFalse(GuardUtils.validate_language_code(code), f"Should not validate: {code}")
    
    def test_validate_url_valid(self):
        """Test URL validation with valid URLs."""
        valid_urls = [
            'http://example.com',
            'https://example.com',
            'http://example.com/path',
            'https://example.com/path?param=value',
            'http://sub.example.com',
            'https://example.com:8080',
        ]
        for url in valid_urls:
            self.assertTrue(GuardUtils.validate_url(url), f"Should validate: {url}")
    
    def test_validate_url_invalid(self):
        """Test URL validation with invalid URLs."""
        invalid_urls = [
            '',  # Empty
            'not-a-url',
            'ftp://example.com',  # Wrong scheme
            'example.com',  # No scheme
            'http://',  # No domain
            'https://',  # No domain
        ]
        for url in invalid_urls:
            self.assertFalse(GuardUtils.validate_url(url), f"Should not validate: {url}")
    
    def test_validate_domain_valid(self):
        """Test domain validation with valid domains."""
        valid_domains = [
            'example.com',
            'sub.example.com',
            'example.co.uk',
            'example-domain.com',
            'example123.com',
            'a.b.c.d',
        ]
        for domain in valid_domains:
            self.assertTrue(GuardUtils.validate_domain(domain), f"Should validate: {domain}")
    
    def test_validate_domain_invalid(self):
        """Test domain validation with invalid domains."""
        invalid_domains = [
            '',  # Empty
            'example',  # No TLD
            '.example.com',  # Leading dot
            'example.com.',  # Trailing dot
            'example..com',  # Double dot
            'example-.com',  # Trailing hyphen
            '-example.com',  # Leading hyphen
            'example.com/path',  # Path included
            'http://example.com',  # Scheme included
        ]
        for domain in invalid_domains:
            self.assertFalse(GuardUtils.validate_domain(domain), f"Should not validate: {domain}")


class TestGuardUtilsHash(unittest.TestCase):
    """Test hash generation and verification functions."""
    
    def test_generate_hash(self):
        """Test hash generation."""
        data = "test data"
        salt = "test salt"
        hash1 = GuardUtils.generate_hash(data, salt)
        hash2 = GuardUtils.generate_hash(data, salt)
        
        # Should be consistent
        self.assertEqual(hash1, hash2)
        
        # Should be different with different salt
        hash3 = GuardUtils.generate_hash(data, "different salt")
        self.assertNotEqual(hash1, hash3)
        
        # Should be different with different data
        hash4 = GuardUtils.generate_hash("different data", salt)
        self.assertNotEqual(hash1, hash4)
        
        # Should be SHA-256 format
        self.assertTrue(GuardUtils.validate_sha256(hash1))
    
    def test_verify_hash(self):
        """Test hash verification."""
        data = "test data"
        salt = "test salt"
        expected_hash = GuardUtils.generate_hash(data, salt)
        
        # Should verify correctly
        self.assertTrue(GuardUtils.verify_hash(data, salt, expected_hash))
        
        # Should fail with wrong data
        self.assertFalse(GuardUtils.verify_hash("wrong data", salt, expected_hash))
        
        # Should fail with wrong salt
        self.assertFalse(GuardUtils.verify_hash(data, "wrong salt", expected_hash))
        
        # Should fail with wrong hash
        self.assertFalse(GuardUtils.verify_hash(data, salt, "wrong hash"))


class TestGuardUtilsBase64(unittest.TestCase):
    """Test base64 payload decoding."""
    
    def test_decode_base64_payload_valid(self):
        """Test decoding valid base64 payload."""
        test_data = {"url": "https://example.com", "domain": "example.com"}
        encoded = base64.urlsafe_b64encode(json.dumps(test_data).encode()).decode()
        
        result = GuardUtils.decode_base64_payload(encoded)
        self.assertEqual(result, test_data)
    
    def test_decode_base64_payload_invalid(self):
        """Test decoding invalid base64 payload."""
        invalid_payloads = [
            "",  # Empty
            "invalid base64",  # Invalid base64
            base64.urlsafe_b64encode(b"invalid json").decode(),  # Invalid JSON
        ]
        
        for payload in invalid_payloads:
            result = GuardUtils.decode_base64_payload(payload)
            self.assertIsNone(result)


class TestGuardUtilsURL(unittest.TestCase):
    """Test URL processing functions."""
    
    def test_extract_domain_from_url(self):
        """Test domain extraction from URLs."""
        test_cases = [
            ("https://example.com", "example.com"),
            ("http://sub.example.com/path", "sub.example.com"),
            ("https://example.com:8080", "example.com"),
            ("http://example.com/path?param=value", "example.com"),
            ("https://example.co.uk", "example.co.uk"),
        ]
        
        for url, expected_domain in test_cases:
            result = GuardUtils.extract_domain_from_url(url)
            self.assertEqual(result, expected_domain)
    
    def test_extract_domain_from_url_invalid(self):
        """Test domain extraction from invalid URLs."""
        invalid_urls = [
            "",  # Empty
            "not-a-url",  # Not a URL
            "ftp://example.com",  # Wrong scheme
            "http://",  # No domain
            "https://",  # No domain
        ]
        
        for url in invalid_urls:
            result = GuardUtils.extract_domain_from_url(url)
            self.assertIsNone(result)
    
    def test_strip_query_parameters(self):
        """Test query parameter stripping."""
        url = "https://example.com/path?param1=value1&utm_source=test&param2=value2&utm_campaign=test"
        strip_prefixes = ["utm_"]
        
        result = GuardUtils.strip_query_parameters(url, strip_prefixes)
        expected = "https://example.com/path?param1=value1"
        self.assertEqual(result, expected)
    
    def test_strip_query_parameters_no_match(self):
        """Test query parameter stripping with no matches."""
        url = "https://example.com/path?param1=value1&param2=value2"
        strip_prefixes = ["utm_"]
        
        result = GuardUtils.strip_query_parameters(url, strip_prefixes)
        self.assertEqual(result, url)
    
    def test_strip_query_parameters_multiple_prefixes(self):
        """Test query parameter stripping with multiple prefixes."""
        url = "https://example.com/path?param1=value1&utm_source=test&fbclid=test&param2=value2&gclid=test"
        strip_prefixes = ["utm_", "fbclid", "gclid"]
        
        result = GuardUtils.strip_query_parameters(url, strip_prefixes)
        expected = "https://example.com/path?param1=value1"
        self.assertEqual(result, expected)
    
    def test_strip_query_parameters_no_query(self):
        """Test query parameter stripping with no query string."""
        url = "https://example.com/path"
        strip_prefixes = ["utm_"]
        
        result = GuardUtils.strip_query_parameters(url, strip_prefixes)
        self.assertEqual(result, url)
    
    def test_extract_url_info(self):
        """Test URL info extraction."""
        url = "https://example.com/path?param=value"
        scheme, domain, path = GuardUtils.extract_url_info(url)
        
        self.assertEqual(scheme, "https")
        self.assertEqual(domain, "example.com")
        self.assertEqual(path, "/path")
    
    def test_extract_url_info_invalid(self):
        """Test URL info extraction from invalid URLs."""
        invalid_urls = ["", "not-a-url"]
        
        for url in invalid_urls:
            scheme, domain, path = GuardUtils.extract_url_info(url)
            self.assertIsNone(scheme)
            self.assertIsNone(domain)
            self.assertIsNone(path)


class TestGuardUtilsPathSecurity(unittest.TestCase):
    """Test path security validation."""
    
    def setUp(self):
        """Set up temporary directory for testing."""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_validate_path_security_valid(self):
        """Test path security validation with valid paths."""
        valid_paths = [
            "file.txt",
            "subdir/file.txt",
            "subdir/subsubdir/file.txt",
            "file with spaces.txt",
        ]
        
        for path in valid_paths:
            self.assertTrue(GuardUtils.validate_path_security(path, self.temp_dir))
    
    def test_validate_path_security_invalid(self):
        """Test path security validation with invalid paths."""
        invalid_paths = [
            "../file.txt",  # Path traversal
            "../../file.txt",  # Multiple path traversal
            "/absolute/path",  # Absolute path
            "..\\file.txt",  # Windows path traversal
        ]
        
        for path in invalid_paths:
            self.assertFalse(GuardUtils.validate_path_security(path, self.temp_dir))
    
    def test_validate_file_extension_valid(self):
        """Test file extension validation with valid extensions."""
        valid_files = [
            "image.png",
            "photo.jpg",
            "picture.jpeg",
            "icon.gif",
            "favicon.ico",
        ]
        
        for filename in valid_files:
            self.assertTrue(GuardUtils.validate_file_extension(filename))
    
    def test_validate_file_extension_invalid(self):
        """Test file extension validation with invalid extensions."""
        invalid_files = [
            "script.js",  # Not allowed
            "style.css",  # Not allowed
            "document.pdf",  # Not allowed
            "file.txt",  # No extension
            "file",  # No extension
            ".htaccess",  # Hidden file
        ]
        
        for filename in invalid_files:
            self.assertFalse(GuardUtils.validate_file_extension(filename))
    
    def test_validate_file_extension_custom(self):
        """Test file extension validation with custom allowed extensions."""
        custom_extensions = {'.txt', '.md', '.py'}
        
        self.assertTrue(GuardUtils.validate_file_extension("file.txt", custom_extensions))
        self.assertTrue(GuardUtils.validate_file_extension("readme.md", custom_extensions))
        self.assertTrue(GuardUtils.validate_file_extension("script.py", custom_extensions))
        self.assertFalse(GuardUtils.validate_file_extension("image.png", custom_extensions))


class TestGuardUtilsString(unittest.TestCase):
    """Test string manipulation functions."""
    
    def test_parse_accept_language(self):
        """Test Accept-Language header parsing."""
        test_cases = [
            ("en-US,en;q=0.9,es;q=0.8", ["en-us", "en", "es"]),
            ("fr-FR,fr;q=0.9", ["fr-fr", "fr"]),
            ("de", ["de"]),
            ("", []),
            ("en-US,en;q=0.9,invalid", ["en-us", "en"]),  # Invalid part ignored
        ]
        
        for header, expected in test_cases:
            result = GuardUtils.parse_accept_language(header)
            self.assertEqual(result, expected)
    
    def test_parse_accept_language_invalid_input(self):
        """Test Accept-Language parsing with invalid input."""
        invalid_inputs = [None, 123, [], {}]
        
        for invalid_input in invalid_inputs:
            result = GuardUtils.parse_accept_language(invalid_input)
            self.assertEqual(result, [])
    
    def test_sanitize_string(self):
        """Test string sanitization."""
        test_cases = [
            ("<script>alert('xss')</script>", "&lt;script&gt;alert('xss')&lt;/script&gt;"),
            ("& < >", "&amp; &lt; &gt;"),
            ("normal text", "normal text"),
            ("", ""),
            (None, ""),
        ]
        
        for input_str, expected in test_cases:
            result = GuardUtils.sanitize_string(input_str)
            self.assertEqual(result, expected)
    
    def test_sanitize_string_truncation(self):
        """Test string sanitization with truncation."""
        long_string = "a" * 1500
        result = GuardUtils.sanitize_string(long_string, max_length=1000)
        
        self.assertEqual(len(result), 1003)  # 1000 chars + "..."
        self.assertTrue(result.endswith("..."))
    
    def test_normalize_domain(self):
        """Test domain normalization."""
        test_cases = [
            ("EXAMPLE.COM", "example.com"),
            ("Example.Com", "example.com"),
            ("  example.com  ", "example.com"),
            ("", ""),
            (None, ""),
        ]
        
        for input_domain, expected in test_cases:
            result = GuardUtils.normalize_domain(input_domain)
            self.assertEqual(result, expected)
    
    def test_is_subdomain(self):
        """Test subdomain checking."""
        test_cases = [
            ("example.com", "example.com", True),  # Same domain
            ("sub.example.com", "example.com", True),  # Subdomain
            ("sub.sub.example.com", "example.com", True),  # Nested subdomain
            ("example.com", "sub.example.com", False),  # Parent not subdomain of child
            ("other.com", "example.com", False),  # Different domains
            ("", "example.com", False),  # Empty domain
            ("example.com", "", False),  # Empty domain
        ]
        
        for domain1, domain2, expected in test_cases:
            result = GuardUtils.is_subdomain(domain1, domain2)
            self.assertEqual(result, expected, f"is_subdomain({domain1}, {domain2})")
    
    def test_create_secure_filename(self):
        """Test secure filename creation."""
        test_cases = [
            ("file.txt", "file.txt"),
            ("file with spaces.txt", "file with spaces.txt"),
            ("file/with/path.txt", "file_with_path.txt"),
            ("file\\with\\backslashes.txt", "file_with_backslashes.txt"),
            ("file:with:colons.txt", "file_with_colons.txt"),
            ("file*with*asterisks.txt", "file_with_asterisks.txt"),
            ("file?with?question.txt", "file_with_question.txt"),
            ('file"with"quotes.txt', "file_with_quotes.txt"),
            ("file<with>brackets.txt", "file_with_brackets.txt"),
            ("file|with|pipes.txt", "file_with_pipes.txt"),
            ("  .file.txt  ", "file.txt"),  # Leading/trailing spaces and dots
            ("", "unnamed"),  # Empty filename
        ]
        
        for input_filename, expected in test_cases:
            result = GuardUtils.create_secure_filename(input_filename)
            self.assertEqual(result, expected)
    
    def test_format_time_elapsed(self):
        """Test time formatting."""
        test_cases = [
            (0.5, "0.500s"),
            (1.0, "1.00s"),
            (30.5, "30.50s"),  # Fixed: Python formats as 30.50s
            (60.0, "1m 0.0s"),
            (90.0, "1m 30.0s"),
            (125.5, "2m 5.5s"),
        ]
        
        for seconds, expected in test_cases:
            result = GuardUtils.format_time_elapsed(seconds)
            self.assertEqual(result, expected)


class TestGuardUtilsJSON(unittest.TestCase):
    """Test JSON utility functions."""
    
    def test_safe_json_loads_valid(self):
        """Test safe JSON loading with valid JSON."""
        valid_json = '{"key": "value", "number": 123, "array": [1, 2, 3]}'
        result = GuardUtils.safe_json_loads(valid_json)
        
        self.assertEqual(result["key"], "value")
        self.assertEqual(result["number"], 123)
        self.assertEqual(result["array"], [1, 2, 3])
    
    def test_safe_json_loads_invalid(self):
        """Test safe JSON loading with invalid JSON."""
        invalid_json_strings = [
            "",  # Empty
            "invalid json",  # Invalid JSON
            '{"key": "value",}',  # Trailing comma
            '{"key": value}',  # Unquoted string
        ]
        
        for invalid_json in invalid_json_strings:
            result = GuardUtils.safe_json_loads(invalid_json)
            self.assertIsNone(result)
    
    def test_safe_json_loads_with_default(self):
        """Test safe JSON loading with custom default."""
        invalid_json = "invalid json"
        default_value = {"default": "value"}
        
        result = GuardUtils.safe_json_loads(invalid_json, default_value)
        self.assertEqual(result, default_value)
    
    def test_merge_dicts(self):
        """Test dictionary merging."""
        dict1 = {"a": 1, "b": 2}
        dict2 = {"b": 3, "c": 4}
        
        result = GuardUtils.merge_dicts(dict1, dict2)
        expected = {"a": 1, "b": 3, "c": 4}  # dict2 values override dict1
        
        self.assertEqual(result, expected)
    
    def test_merge_dicts_empty(self):
        """Test dictionary merging with empty dictionaries."""
        # Empty dict1
        result = GuardUtils.merge_dicts({}, {"a": 1})
        self.assertEqual(result, {"a": 1})
        
        # Empty dict2
        result = GuardUtils.merge_dicts({"a": 1}, {})
        self.assertEqual(result, {"a": 1})
        
        # Both empty
        result = GuardUtils.merge_dicts({}, {})
        self.assertEqual(result, {})


if __name__ == '__main__':
    unittest.main() 