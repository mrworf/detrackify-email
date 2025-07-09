#!/usr/bin/env python3
"""Unit tests for shared utilities (SharedUtils)."""

import os
import sys
import tempfile
import unittest
import json
import base64
import hashlib

# Add the parent directory to the path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from common.utils import SharedUtils

class TestSharedUtilsValidation(unittest.TestCase):
    """Test validation functions in SharedUtils."""
    def test_validate_sha256_valid(self):
        valid_hashes = [
            'a' * 64,
            'f' * 64,
            '0123456789abcdef' * 4,
            'deadbeef' * 8,
        ]
        for hash_str in valid_hashes:
            self.assertTrue(SharedUtils.validate_sha256(hash_str))
    def test_validate_sha256_invalid(self):
        invalid_hashes = [
            '',  # Empty
            'a' * 63,  # Too short
            'a' * 65,  # Too long
            'g' * 64,  # Invalid character
        ]
        for hash_str in invalid_hashes:
            self.assertFalse(SharedUtils.validate_sha256(hash_str))
        # Test that mixed case and uppercase are actually valid (they are hex)
        valid_hashes = [
            '1234567890abcdef' * 4,  # Mixed case
        ]
        for hash_str in valid_hashes:
            self.assertTrue(SharedUtils.validate_sha256(hash_str))
        # Test that uppercase is invalid (only lowercase hex is accepted)
        self.assertFalse(SharedUtils.validate_sha256('A' * 64))

class TestSharedUtilsEncoding(unittest.TestCase):
    def test_encode_decode_base64(self):
        test_data = [
            'Hello, World!',
            'Test with special chars: !@#$%^&*()',
            'Unicode: 你好世界',
            '',
            'a' * 1000,
        ]
        for original in test_data:
            encoded = SharedUtils.encode_base64(original)
            decoded = SharedUtils.decode_base64(encoded, 'utf-8')
            self.assertEqual(decoded, original)
    def test_decode_base64_with_charset(self):
        test_cases = [
            ('SGVsbG8sIFdvcmxkIQ==', 'utf-8', 'Hello, World!'),
            ('VGVzdCB3aXRoIHNwZWNpYWwgY2hhcnM=', 'utf-8', 'Test with special chars'),
        ]
        for encoded, charset, expected in test_cases:
            decoded = SharedUtils.decode_base64(encoded, charset)
            self.assertEqual(decoded, expected)

class TestSharedUtilsURLProcessing(unittest.TestCase):
    def test_extract_url_info_valid(self):
        test_cases = [
            ('https://example.com/path', ('https', 'example.com', '/path')),
            ('http://sub.example.com/', ('http', 'sub.example.com', '/')),
            ('https://example.com', ('https', 'example.com', '')),
            ('http://example.com:8080/path?param=value', ('http', 'example.com:8080', '/path')),
        ]
        for url, expected in test_cases:
            result = SharedUtils.extract_url_info(url)
            self.assertEqual(result, expected)
    def test_extract_url_info_invalid(self):
        invalid_urls = ['', 'not-a-url']
        for url in invalid_urls:
            result = SharedUtils.extract_url_info(url)
            self.assertEqual(result, (None, None, None))
        result = SharedUtils.extract_url_info('ftp://example.com')
        self.assertEqual(result, (None, None, None))
    def test_strip_query_parameters(self):
        test_cases = [
            ('https://example.com/path', 'https://example.com/path'),
            ('https://example.com/path?param=value', 'https://example.com/path?param=value'),
            ('https://example.com/path?param1=value1&param2=value2', 'https://example.com/path?param1=value1&param2=value2'),
            ('https://example.com/path#fragment', 'https://example.com/path#fragment'),
            ('https://example.com/path?param=value#fragment', 'https://example.com/path?param=value#fragment'),
        ]
        for url, expected in test_cases:
            result = SharedUtils.strip_query_parameters(url, [])
            self.assertEqual(result, expected)
    def test_strip_query_parameters_with_prefixes(self):
        url = 'https://example.com/path?utm_source=test&param=value&utm_medium=email'
        prefixes = ['utm_']
        result = SharedUtils.strip_query_parameters(url, prefixes)
        self.assertEqual(result, 'https://example.com/path')
    def test_strip_query_parameters_specific_cases(self):
        """Test specific cases from the original test_processing.py tests."""
        # Test case 1: Strip utm_ parameters
        url = SharedUtils.strip_query_parameters("https://example.com/?a=1&utm_source=x&b=2", ["utm_"])
        self.assertEqual(url, "https://example.com/?a=1")
        
        # Test case 2: No matching prefixes
        url = SharedUtils.strip_query_parameters("https://example.com/?a=1&b=2", ["utm_"])
        self.assertEqual(url, "https://example.com/?a=1&b=2")
        
        # Test case 3: Multiple prefixes
        url = SharedUtils.strip_query_parameters("https://example.com/?a=1&foo_id=2&utm_x=3&b=4", ["foo", "utm_"])
        self.assertEqual(url, "https://example.com/?a=1")
    def test_strip_query_parameters_edge_cases(self):
        """Test edge cases for strip_query_parameters."""
        # Empty URL
        self.assertEqual(SharedUtils.strip_query_parameters("", ["utm_"]), "")
        self.assertEqual(SharedUtils.strip_query_parameters(None, ["utm_"]), None)
        
        # Empty prefixes
        url = "https://example.com/?utm_source=test&param=value"
        self.assertEqual(SharedUtils.strip_query_parameters(url, []), url)
        self.assertEqual(SharedUtils.strip_query_parameters(url, None), url)
        
        # URL without query parameters
        url = "https://example.com/path"
        self.assertEqual(SharedUtils.strip_query_parameters(url, ["utm_"]), url)
        
        # URL with empty query
        url = "https://example.com/path?"
        self.assertEqual(SharedUtils.strip_query_parameters(url, ["utm_"]), url)
        
        # URL with fragment only
        url = "https://example.com/path#fragment"
        self.assertEqual(SharedUtils.strip_query_parameters(url, ["utm_"]), url)
        
        # URL with query and fragment
        url = "https://example.com/path?utm_source=test#fragment"
        result = SharedUtils.strip_query_parameters(url, ["utm_"])
        self.assertEqual(result, "https://example.com/path#fragment")
    def test_strip_query_parameters_complex_scenarios(self):
        """Test complex scenarios for strip_query_parameters."""
        # Multiple parameters, some matching
        url = "https://example.com/?param1=value1&utm_source=test&param2=value2&utm_medium=email&param3=value3"
        result = SharedUtils.strip_query_parameters(url, ["utm_"])
        self.assertEqual(result, "https://example.com/?param1=value1")
        
        # Parameters with empty values
        url = "https://example.com/?param1=&utm_source=&param2=value2"
        result = SharedUtils.strip_query_parameters(url, ["utm_"])
        self.assertEqual(result, "https://example.com/?param1=")
        
        # Parameters without values
        url = "https://example.com/?param1&utm_source&param2"
        result = SharedUtils.strip_query_parameters(url, ["utm_"])
        self.assertEqual(result, "https://example.com/?param1")
        
        # Multiple prefixes, different matching patterns
        url = "https://example.com/?param1=value1&fbclid=test&utm_source=test&param2=value2"
        result = SharedUtils.strip_query_parameters(url, ["fbclid", "utm_"])
        self.assertEqual(result, "https://example.com/?param1=value1")
        
        # Case sensitivity - should NOT match uppercase
        url = "https://example.com/?param1=value1&UTM_SOURCE=test&param2=value2"
        result = SharedUtils.strip_query_parameters(url, ["utm_"])
        self.assertEqual(result, "https://example.com/?param1=value1&UTM_SOURCE=test&param2=value2")
        
        # Partial prefix matches
        url = "https://example.com/?param1=value1&utm_param=test&param2=value2"
        result = SharedUtils.strip_query_parameters(url, ["utm_"])
        self.assertEqual(result, "https://example.com/?param1=value1")
    def test_strip_query_parameters_invalid_urls(self):
        """Test strip_query_parameters with invalid URLs."""
        # Invalid URL format
        invalid_urls = [
            "not-a-url",
            "ftp://example.com/path?param=value",
            "javascript:alert('test')",
            "data:text/html,<html></html>"
        ]
        
        for url in invalid_urls:
            # Should return the original URL without modification
            result = SharedUtils.strip_query_parameters(url, ["utm_"])
            self.assertEqual(result, url)

class TestSharedUtilsDomainProcessing(unittest.TestCase):
    """Test the domain processing utility functions."""

    def test_normalize_domain(self):
        """Test domain normalization."""
        # Test basic normalization
        self.assertEqual(SharedUtils.normalize_domain('EXAMPLE.COM'), 'example.com')
        self.assertEqual(SharedUtils.normalize_domain('  Test.Domain  '), 'test.domain')
        self.assertEqual(SharedUtils.normalize_domain('team.talkspace.com'), 'team.talkspace.com')
        
        # Test edge cases
        self.assertEqual(SharedUtils.normalize_domain(''), '')
        self.assertEqual(SharedUtils.normalize_domain(None), '')
        self.assertEqual(SharedUtils.normalize_domain('   '), '')

    def test_is_subdomain(self):
        """Test subdomain detection."""
        # Test same domain
        self.assertTrue(SharedUtils.is_subdomain('example.com', 'example.com'))
        self.assertTrue(SharedUtils.is_subdomain('TEAM.TALKSPACE.COM', 'team.talkspace.com'))
        
        # Test subdomain relationships
        self.assertTrue(SharedUtils.is_subdomain('sub.example.com', 'example.com'))
        self.assertTrue(SharedUtils.is_subdomain('deep.sub.example.com', 'example.com'))
        self.assertTrue(SharedUtils.is_subdomain('deep.sub.example.com', 'sub.example.com'))
        
        # Test reverse relationships (should not be subdomain)
        self.assertFalse(SharedUtils.is_subdomain('example.com', 'sub.example.com'))
        self.assertFalse(SharedUtils.is_subdomain('sub.example.com', 'deep.sub.example.com'))
        
        # Test different domains
        self.assertFalse(SharedUtils.is_subdomain('team.talkspace.com', 'try.talkspace.com'))
        self.assertFalse(SharedUtils.is_subdomain('mail.google.com', 'drive.google.com'))
        
        # Test edge cases
        self.assertFalse(SharedUtils.is_subdomain('', 'example.com'))
        self.assertFalse(SharedUtils.is_subdomain('example.com', ''))
        self.assertFalse(SharedUtils.is_subdomain('', ''))
        self.assertFalse(SharedUtils.is_subdomain(None, 'example.com'))
        self.assertFalse(SharedUtils.is_subdomain('example.com', None))

    def test_share_parent_domain(self):
        """Test parent domain sharing detection."""
        # Test same domain
        self.assertTrue(SharedUtils.share_parent_domain('example.com', 'example.com'))
        self.assertTrue(SharedUtils.share_parent_domain('TEAM.TALKSPACE.COM', 'team.talkspace.com'))
        
        # Test domains with same parent
        self.assertTrue(SharedUtils.share_parent_domain('team.talkspace.com', 'try.talkspace.com'))
        self.assertTrue(SharedUtils.share_parent_domain('mail.google.com', 'drive.google.com'))
        self.assertTrue(SharedUtils.share_parent_domain('www.example.com', 'api.example.com'))
        self.assertTrue(SharedUtils.share_parent_domain('sub1.example.org', 'sub2.example.org'))
        
        # Test domains with different parents
        self.assertFalse(SharedUtils.share_parent_domain('team.talkspace.com', 'mail.google.com'))
        self.assertFalse(SharedUtils.share_parent_domain('example.com', 'other.com'))
        self.assertFalse(SharedUtils.share_parent_domain('example.com', 'example.org'))
        
        # Test subdomain relationships (should share parent domain)
        self.assertTrue(SharedUtils.share_parent_domain('sub.example.com', 'example.com'))
        self.assertTrue(SharedUtils.share_parent_domain('example.com', 'sub.example.com'))
        
        # Test domains with different numbers of levels (but same parent)
        self.assertTrue(SharedUtils.share_parent_domain('example.com', 'sub.example.com'))
        self.assertTrue(SharedUtils.share_parent_domain('sub.example.com', 'example.com'))
        
        # Test very long subdomains
        self.assertTrue(SharedUtils.share_parent_domain('very.deep.sub.example.com', 'another.deep.sub.example.com'))
        
        # Test case sensitivity
        self.assertTrue(SharedUtils.share_parent_domain('TEAM.TALKSPACE.COM', 'try.talkspace.com'))
        self.assertTrue(SharedUtils.share_parent_domain('team.talkspace.com', 'TRY.TALKSPACE.COM'))
        
        # Test domains with extra whitespace
        self.assertTrue(SharedUtils.share_parent_domain(' team.talkspace.com ', 'try.talkspace.com'))
        self.assertTrue(SharedUtils.share_parent_domain('team.talkspace.com', ' try.talkspace.com '))
        
        # Test edge cases
        self.assertFalse(SharedUtils.share_parent_domain('', 'example.com'))
        self.assertFalse(SharedUtils.share_parent_domain('example.com', ''))
        self.assertFalse(SharedUtils.share_parent_domain('', ''))
        self.assertFalse(SharedUtils.share_parent_domain(None, 'example.com'))
        self.assertFalse(SharedUtils.share_parent_domain('example.com', None))
        
        # Test domains with less than 2 parts
        self.assertFalse(SharedUtils.share_parent_domain('com', 'org'))
        self.assertFalse(SharedUtils.share_parent_domain('example', 'other'))

    def test_comprehensive_domain_matching_scenarios(self):
        """Test comprehensive real-world domain matching scenarios."""
        # Test cases that should match (same parent domain)
        positive_cases = [
            # Talkspace case that was broken
            ('team.talkspace.com', 'try.talkspace.com'),
            ('mail.talkspace.com', 'support.talkspace.com'),
            ('www.talkspace.com', 'api.talkspace.com'),
            
            # Google domains
            ('mail.google.com', 'drive.google.com'),
            ('docs.google.com', 'calendar.google.com'),
            ('www.google.com', 'api.google.com'),
            ('maps.google.com', 'translate.google.com'),
            
            # Microsoft domains
            ('outlook.live.com', 'onedrive.live.com'),
            ('mail.microsoft.com', 'support.microsoft.com'),
            ('www.microsoft.com', 'docs.microsoft.com'),
            
            # Example domains
            ('www.example.com', 'api.example.com'),
            ('mail.example.org', 'support.example.org'),
            ('sub1.example.net', 'sub2.example.net'),
            ('dev.example.co.uk', 'prod.example.co.uk'),
            
            # Single-level domains (should match themselves)
            ('example.com', 'example.com'),
            ('google.com', 'google.com'),
            ('talkspace.com', 'talkspace.com'),
        ]
        
        for domain1, domain2 in positive_cases:
            with self.subTest(domain1=domain1, domain2=domain2):
                self.assertTrue(
                    SharedUtils.share_parent_domain(domain1, domain2),
                    f"Expected {domain1} and {domain2} to share parent domain"
                )
        
        # Test cases that should NOT match (different parent domains)
        negative_cases = [
            # Different companies
            ('team.talkspace.com', 'mail.google.com'),
            ('example.com', 'other.com'),
            ('google.com', 'microsoft.com'),
            ('talkspace.com', 'amazon.com'),
            
            # Different TLDs
            ('example.com', 'example.org'),
            ('google.com', 'google.net'),
            ('talkspace.com', 'talkspace.org'),
            ('example.co.uk', 'example.com'),
            
            # Different second-level domains
            ('team.talkspace.com', 'team.otherspace.com'),
            ('mail.google.com', 'mail.gmail.com'),
            ('www.example.com', 'www.example2.com'),
            ('api.example.com', 'api.example.org'),
        ]
        
        for domain1, domain2 in negative_cases:
            with self.subTest(domain1=domain1, domain2=domain2):
                self.assertFalse(
                    SharedUtils.share_parent_domain(domain1, domain2),
                    f"Expected {domain1} and {domain2} NOT to share parent domain"
                )

    def test_edge_cases_and_error_handling(self):
        """Test edge cases and error handling in domain matching."""
        # Test invalid domains
        invalid_domains = [
            '', None, '   ', 'invalid', 'too.many.dots.in.this.domain.com',
            'domain-with-dashes.com', 'domain_with_underscores.com',
            'domain.with.multiple..dots.com', '.domain.com', 'domain.',
            'domain..com', 'domain.com.', '.domain.com.'
        ]
        
        for invalid_domain in invalid_domains:
            with self.subTest(invalid_domain=invalid_domain):
                # Should handle gracefully without raising exceptions
                try:
                    result = SharedUtils.share_parent_domain(invalid_domain, 'example.com')
                    # Should return False for invalid domains
                    self.assertFalse(result)
                except Exception as e:
                    self.fail(f"share_parent_domain raised exception for {invalid_domain}: {e}")
                
                try:
                    result = SharedUtils.share_parent_domain('example.com', invalid_domain)
                    # Should return False for invalid domains
                    self.assertFalse(result)
                except Exception as e:
                    self.fail(f"share_parent_domain raised exception for {invalid_domain}: {e}")

    def test_performance_edge_cases(self):
        """Test performance edge cases with very long domains."""
        # Test with very long domain names
        long_domain = 'a' * 100 + '.example.com'
        self.assertTrue(SharedUtils.share_parent_domain(long_domain, long_domain))
        
        # Test with many subdomain levels
        deep_domain = '.'.join(['sub' + str(i) for i in range(10)]) + '.example.com'
        self.assertTrue(SharedUtils.share_parent_domain(deep_domain, 'example.com'))
        
        # Test with domains that have many dots but are still valid
        many_dots_domain = 'a.b.c.d.e.f.g.h.i.j.example.com'
        self.assertTrue(SharedUtils.share_parent_domain(many_dots_domain, 'example.com'))

class TestSharedUtilsDomainAliases(unittest.TestCase):
    """Test the centralized domain alias checking function."""
    
    def test_are_domains_aliases_basic(self):
        """Test basic domain alias functionality."""
        aliases = {
            'example.com': ['example-email.com'],
            'google.com': ['google-email.com', 'gmail.com']
        }
        
        # Test direct matches
        self.assertTrue(SharedUtils.are_domains_aliases('example.com', 'example.com'))
        self.assertTrue(SharedUtils.are_domains_aliases('google.com', 'google.com'))
        
        # Test configured aliases
        self.assertTrue(SharedUtils.are_domains_aliases('example.com', 'example-email.com', aliases))
        self.assertTrue(SharedUtils.are_domains_aliases('google.com', 'google-email.com', aliases))
        self.assertTrue(SharedUtils.are_domains_aliases('google.com', 'gmail.com', aliases))
        self.assertTrue(SharedUtils.are_domains_aliases('google-email.com', 'gmail.com', aliases))
        
        # Test cross-group (should fail)
        self.assertFalse(SharedUtils.are_domains_aliases('example.com', 'google.com', aliases))
        self.assertFalse(SharedUtils.are_domains_aliases('example-email.com', 'google-email.com', aliases))
    
    def test_are_domains_aliases_subdomains(self):
        """Test subdomain relationships."""
        aliases = {
            'example.com': ['example-email.com']
        }
        
        # Test subdomain relationships (should work regardless of aliases)
        self.assertTrue(SharedUtils.are_domains_aliases('sub.example.com', 'example.com'))
        self.assertTrue(SharedUtils.are_domains_aliases('example.com', 'sub.example.com'))
        self.assertTrue(SharedUtils.are_domains_aliases('deep.sub.example.com', 'example.com'))
        
        # Test subdomain of alias
        self.assertTrue(SharedUtils.are_domains_aliases('sub.example-email.com', 'example.com', aliases))
        self.assertTrue(SharedUtils.are_domains_aliases('example.com', 'sub.example-email.com', aliases))
    
    def test_are_domains_aliases_parent_domain(self):
        """Test parent domain sharing."""
        aliases = {
            'talkspace.com': ['talkspace-email.com']
        }
        
        # Test domains sharing same parent
        self.assertTrue(SharedUtils.are_domains_aliases('team.talkspace.com', 'try.talkspace.com'))
        self.assertTrue(SharedUtils.are_domains_aliases('mail.google.com', 'drive.google.com'))
        
        # Test with aliases
        self.assertTrue(SharedUtils.are_domains_aliases('team.talkspace.com', 'talkspace-email.com', aliases))
    
    def test_are_domains_aliases_no_aliases(self):
        """Test behavior when no aliases are provided."""
        # Should only match same domain and subdomains
        self.assertTrue(SharedUtils.are_domains_aliases('example.com', 'example.com'))
        self.assertTrue(SharedUtils.are_domains_aliases('sub.example.com', 'example.com'))
        self.assertFalse(SharedUtils.are_domains_aliases('example.com', 'other.com'))
    
    def test_are_domains_aliases_edge_cases(self):
        """Test edge cases and invalid inputs."""
        aliases = {
            'example.com': ['example-email.com']
        }
        
        # Test empty/None domains
        self.assertFalse(SharedUtils.are_domains_aliases('', 'example.com'))
        self.assertFalse(SharedUtils.are_domains_aliases('example.com', ''))
        self.assertFalse(SharedUtils.are_domains_aliases('', ''))
        self.assertFalse(SharedUtils.are_domains_aliases(None, 'example.com'))
        self.assertFalse(SharedUtils.are_domains_aliases('example.com', None))
        
        # Test case insensitivity
        self.assertTrue(SharedUtils.are_domains_aliases('EXAMPLE.COM', 'example.com'))
        self.assertTrue(SharedUtils.are_domains_aliases('Example.Com', 'EXAMPLE.COM'))
        
        # Test with aliases
        self.assertTrue(SharedUtils.are_domains_aliases('EXAMPLE.COM', 'EXAMPLE-EMAIL.COM', aliases))
    
    def test_are_domains_aliases_invalid_alias_config(self):
        """Test handling of invalid alias configurations."""
        aliases = {
            'valid.com': ['valid-email.com'],
            'invalid.com': None,  # Invalid: None value
            'another.com': 123,   # Invalid: non-string/list value
            'empty.com': []       # Invalid: empty list
        }
        
        # Valid aliases should still work
        self.assertTrue(SharedUtils.are_domains_aliases('valid.com', 'valid-email.com', aliases))
        
        # Invalid configurations should be ignored
        self.assertFalse(SharedUtils.are_domains_aliases('invalid.com', 'some-other.com', aliases))
        self.assertFalse(SharedUtils.are_domains_aliases('another.com', 'some-other.com', aliases))
        self.assertFalse(SharedUtils.are_domains_aliases('empty.com', 'some-other.com', aliases))

class TestSharedUtilsLanguageProcessing(unittest.TestCase):
    def test_parse_accept_language_valid(self):
        test_cases = [
            ('en-US,en;q=0.9', ['en-us', 'en']),
            ('es-ES,es;q=0.8,en;q=0.6', ['es-es', 'es', 'en']),
            ('fr-FR,fr;q=0.9,en;q=0.8,en-US;q=0.7', ['fr-fr', 'fr', 'en', 'en-us']),
            ('de', ['de']),
            ('zh-CN,zh;q=0.9', ['zh-cn', 'zh']),
        ]
        for header, expected in test_cases:
            result = SharedUtils.parse_accept_language(header)
            self.assertEqual(result, expected)
    def test_parse_accept_language_invalid_input(self):
        invalid_inputs = [None, '', 'invalid']
        for invalid in invalid_inputs:
            result = SharedUtils.parse_accept_language(invalid)
            self.assertEqual(result, [])
        result = SharedUtils.parse_accept_language('EN-US,INVALID')
        self.assertEqual(result, ['en-us'])
    def test_validate_language_code(self):
        valid_codes = ['en', 'en-US', 'es-ES', 'fr-FR', 'de', 'zh-CN']
        for code in valid_codes:
            self.assertTrue(SharedUtils.validate_language_code(code))
        invalid_codes = ['', 'invalid', 'EN', 'en_US', 'en-', '-US']
        for code in invalid_codes:
            self.assertFalse(SharedUtils.validate_language_code(code))

class TestSharedUtilsSanitization(unittest.TestCase):
    def test_sanitize_string(self):
        test_cases = [
            ('<script>alert("xss")</script>', '&lt;script&gt;alert("xss")&lt;/script&gt;'),
            ('& < >', '&amp; &lt; &gt;'),
            ('', ''),
            (None, ''),
        ]
        for input_str, expected in test_cases:
            result = SharedUtils.sanitize_string(input_str)
            self.assertEqual(result, expected)

class TestSharedUtilsHashing(unittest.TestCase):
    def test_generate_hash(self):
        data = "test data"
        salt = "test salt"
        hash_result = SharedUtils.generate_hash(data, salt)
        self.assertTrue(SharedUtils.validate_sha256(hash_result))
        hash_result2 = SharedUtils.generate_hash(data, salt)
        self.assertEqual(hash_result, hash_result2)
        hash_result3 = SharedUtils.generate_hash(data, "different salt")
        self.assertNotEqual(hash_result, hash_result3)
    def test_verify_hash(self):
        data = "test data"
        salt = "test salt"
        hash_result = SharedUtils.generate_hash(data, salt)
        self.assertTrue(SharedUtils.verify_hash(data, salt, hash_result))
        self.assertFalse(SharedUtils.verify_hash("wrong data", salt, hash_result))
        self.assertFalse(SharedUtils.verify_hash(data, "wrong salt", hash_result))
        self.assertFalse(SharedUtils.verify_hash(data, salt, "wrong hash"))

class TestSharedUtilsNewFunctions(unittest.TestCase):
    """Test the new URL processing and base64/hash operation functions."""

    def test_is_safe_url(self):
        """Test URL safety validation."""
        # Valid URLs
        self.assertTrue(SharedUtils.is_safe_url('https://example.com'))
        self.assertTrue(SharedUtils.is_safe_url('http://example.com/path'))
        self.assertTrue(SharedUtils.is_safe_url('https://sub.example.com:8080/path?q=1'))
        
        # Invalid URLs
        self.assertFalse(SharedUtils.is_safe_url(''))
        self.assertFalse(SharedUtils.is_safe_url(None))
        self.assertFalse(SharedUtils.is_safe_url('ftp://example.com'))
        self.assertFalse(SharedUtils.is_safe_url('javascript:alert(1)'))
        self.assertFalse(SharedUtils.is_safe_url('not-a-url'))
        
        # Custom allowed schemes
        self.assertTrue(SharedUtils.is_safe_url('ftp://example.com', ['ftp']))
        self.assertFalse(SharedUtils.is_safe_url('https://example.com', ['ftp']))



    def test_parse_guard_url(self):
        """Test guard URL parsing."""
        # Valid guard URL
        result = SharedUtils.parse_guard_url('https://guard.example.com/guard/abc123/data456')
        self.assertEqual(result, {'sha': 'abc123', 'data': 'data456'})
        
        # Invalid URLs
        self.assertIsNone(SharedUtils.parse_guard_url('https://example.com'))
        self.assertIsNone(SharedUtils.parse_guard_url(''))
        self.assertIsNone(SharedUtils.parse_guard_url(None))

    def test_create_guard_payload(self):
        """Test guard payload creation."""
        payload = SharedUtils.create_guard_payload('Click here', 'example.com', 'https://example.com/link')
        expected = {
            'display': 'Click here',
            'domain': 'example.com',
            'url': 'https://example.com/link'
        }
        self.assertEqual(payload, expected)
        
        # With optional fields
        payload = SharedUtils.create_guard_payload(
            'Click here', 'example.com', 'https://example.com/link',
            to_address='user@example.com', block_reason='blacklisted'
        )
        expected.update({
            'to': 'user@example.com',
            'block': 'blacklisted'
        })
        self.assertEqual(payload, expected)

    def test_create_guard_link(self):
        """Test complete guard link creation."""
        link = SharedUtils.create_guard_link(
            'https://guard.example.com', 'testsalt',
            'Click here', 'example.com', 'https://example.com/link'
        )
        
        # Verify the link structure
        self.assertTrue(link.startswith('https://guard.example.com/guard/'))
        self.assertIn('/', link)
        
        # Parse and verify the components
        components = SharedUtils.parse_guard_url(link)
        self.assertIsNotNone(components)
        
        # Verify the payload
        payload = SharedUtils.decode_base64_payload(components['data'])
        self.assertEqual(payload['display'], 'Click here')
        self.assertEqual(payload['domain'], 'example.com')
        self.assertEqual(payload['url'], 'https://example.com/link')

    def test_verify_guard_link(self):
        """Test guard link verification."""
        # Create a valid link
        link = SharedUtils.create_guard_link(
            'https://guard.example.com', 'testsalt',
            'Click here', 'example.com', 'https://example.com/link'
        )
        
        # Verify it
        result = SharedUtils.verify_guard_link(link, 'testsalt')
        self.assertIsNotNone(result)
        self.assertEqual(result['display'], 'Click here')
        self.assertEqual(result['domain'], 'example.com')
        self.assertEqual(result['url'], 'https://example.com/link')
        
        # Test with wrong salt
        result = SharedUtils.verify_guard_link(link, 'wrongsalt')
        self.assertIsNone(result)
        
        # Test with invalid URL
        result = SharedUtils.verify_guard_link('https://example.com', 'testsalt')
        self.assertIsNone(result)




    def test_integration_guard_link_creation_and_verification(self):
        """Test integration between guard link creation and verification."""
        # Create a link with all fields
        link = SharedUtils.create_guard_link(
            'https://guard.example.com', 'testsalt',
            'Click here', 'example.com', 'https://example.com/link',
            to_address='user@example.com', block_reason='blacklisted'
        )
        
        # Verify the link
        result = SharedUtils.verify_guard_link(link, 'testsalt')
        self.assertIsNotNone(result)
        self.assertEqual(result['display'], 'Click here')
        self.assertEqual(result['domain'], 'example.com')
        self.assertEqual(result['url'], 'https://example.com/link')
        self.assertEqual(result['to'], 'user@example.com')
        self.assertEqual(result['block'], 'blacklisted')
        
        # Verify the link structure matches the old create_guarded_url function
        old_link = SharedUtils.create_guarded_url({
            'display': 'Click here',
            'domain': 'example.com',
            'url': 'https://example.com/link',
            'to': 'user@example.com',
            'block': 'blacklisted'
        }, 'https://guard.example.com', 'testsalt')
        
        # Both should produce the same result
        self.assertEqual(link, old_link)

if __name__ == '__main__':
    unittest.main() 