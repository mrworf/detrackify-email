#!/usr/bin/env python3
"""Test cases for url_utils module."""

import unittest
import sys
import os

# Add the parent directory to the path so we can import url_utils
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.url_utils import strip_query_params, normalize_prefixes, is_tracking_parameter


class TestUrlUtils(unittest.TestCase):
    """Test URL utility functions."""

    def test_strip_query_params_case_insensitive_utm(self):
        """Test case-insensitive UTM parameter stripping."""
        test_cases = [
            # Basic case-insensitive tests
            ("https://example.com/?param1=value1&utm_source=test&param2=value2", ["utm_"], "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&UTM_SOURCE=test&param2=value2", ["utm_"], "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&Utm_Source=test&param2=value2", ["utm_"], "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&UTM_MEDIUM=test&param2=value2", ["utm_"], "https://example.com/?param1=value1"),
            
            # Mixed case prefixes
            ("https://example.com/?param1=value1&utm_source=test&param2=value2", ["UTM_"], "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&UTM_SOURCE=test&param2=value2", ["UTM_"], "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&Utm_Source=test&param2=value2", ["Utm_"], "https://example.com/?param1=value1"),
        ]
        
        for url, prefixes, expected in test_cases:
            with self.subTest(url=url, prefixes=prefixes):
                result = strip_query_params(url, prefixes)
                self.assertEqual(result, expected)

    def test_strip_query_params_case_insensitive_fbclid(self):
        """Test case-insensitive Facebook click ID parameter stripping."""
        test_cases = [
            ("https://example.com/?param1=value1&fbclid=123&param2=value2", ["fbclid"], "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&FBCLID=123&param2=value2", ["fbclid"], "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&FbClId=123&param2=value2", ["fbclid"], "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&fbclid=123&param2=value2", ["FBCLID"], "https://example.com/?param1=value1"),
        ]
        
        for url, prefixes, expected in test_cases:
            with self.subTest(url=url, prefixes=prefixes):
                result = strip_query_params(url, prefixes)
                self.assertEqual(result, expected)

    def test_strip_query_params_case_insensitive_gclid(self):
        """Test case-insensitive Google click ID parameter stripping."""
        test_cases = [
            ("https://example.com/?param1=value1&gclid=123&param2=value2", ["gclid"], "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&GCLID=123&param2=value2", ["gclid"], "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&GcLiD=123&param2=value2", ["gclid"], "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&gclid=123&param2=value2", ["GCLID"], "https://example.com/?param1=value1"),
        ]
        
        for url, prefixes, expected in test_cases:
            with self.subTest(url=url, prefixes=prefixes):
                result = strip_query_params(url, prefixes)
                self.assertEqual(result, expected)

    def test_strip_query_params_multiple_prefixes_case_insensitive(self):
        """Test multiple prefixes with case-insensitive matching."""
        prefixes = ["utm_", "fbclid", "gclid"]
        test_cases = [
            ("https://example.com/?param1=value1&UTM_SOURCE=test&param2=value2", "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&FBCLID=123&param2=value2", "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&GCLID=456&param2=value2", "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&Utm_Medium=email&param2=value2", "https://example.com/?param1=value1"),
        ]
        
        for url, expected in test_cases:
            with self.subTest(url=url):
                result = strip_query_params(url, prefixes)
                self.assertEqual(result, expected)

    def test_strip_query_params_no_match_case_insensitive(self):
        """Test that parameters not matching prefixes are preserved."""
        prefixes = ["utm_", "fbclid"]
        test_cases = [
            # These should not match because they don't start with the prefix
            "https://example.com/?param1=value1&source_utm=test&param2=value2",
            "https://example.com/?param1=value1&id_fbclid=123&param2=value2",
            "https://example.com/?param1=value1&utm=test&param2=value2",  # utm without underscore
            "https://example.com/?param1=value1&fbcli=123&param2=value2",  # fbcli without d
        ]
        
        for url in test_cases:
            with self.subTest(url=url):
                result = strip_query_params(url, prefixes)
                self.assertEqual(result, url)  # Should be unchanged

    def test_strip_query_params_first_param_matches_case_insensitive(self):
        """Test when first parameter matches prefix (case-insensitive)."""
        test_cases = [
            ("https://example.com/?utm_source=test&param1=value1", ["utm_"], "https://example.com/"),
            ("https://example.com/?UTM_SOURCE=test&param1=value1", ["utm_"], "https://example.com/"),
            ("https://example.com/?Utm_Source=test&param1=value1", ["utm_"], "https://example.com/"),
        ]
        
        for url, prefixes, expected in test_cases:
            with self.subTest(url=url, prefixes=prefixes):
                result = strip_query_params(url, prefixes)
                self.assertEqual(result, expected)

    def test_strip_query_params_complex_mixed_case(self):
        """Test complex scenarios with mixed case parameters."""
        prefixes = ["utm_", "fbclid", "gclid", "msclkid"]
        test_cases = [
            # Multiple tracking parameters in mixed case
            ("https://example.com/?param1=keep&UTM_SOURCE=email&FBCLID=123&param2=discard", "https://example.com/?param1=keep"),
            ("https://example.com/?param1=keep&Utm_Medium=newsletter&Gclid=456&param2=discard", "https://example.com/?param1=keep"),
            ("https://example.com/?param1=keep&MSCLKID=789&param2=discard", "https://example.com/?param1=keep"),
            
            # Tracking parameter at the end
            ("https://example.com/?param1=keep&param2=keep&UTM_CAMPAIGN=test", "https://example.com/?param1=keep&param2=keep"),
        ]
        
        for url, expected in test_cases:
            with self.subTest(url=url):
                result = strip_query_params(url, prefixes)
                self.assertEqual(result, expected)

    def test_strip_query_params_edge_cases(self):
        """Test edge cases for case-insensitive stripping."""
        test_cases = [
            # Empty URL
            ("", ["utm_"], ""),
            
            # No query string
            ("https://example.com/path", ["utm_"], "https://example.com/path"),
            
            # Empty prefixes
            ("https://example.com/?utm_source=test", [], "https://example.com/?utm_source=test"),
            
            # Malformed URL
            ("not-a-url", ["utm_"], "not-a-url"),
            
            # Fragment with case-insensitive parameter
            ("https://example.com/path?param1=value1&UTM_SOURCE=test&param2=value2#section", ["utm_"], "https://example.com/path?param1=value1#section"),
            
            # Port with case-insensitive parameter  
            ("https://example.com:8080/path?param1=value1&UTM_SOURCE=test&param2=value2", ["utm_"], "https://example.com:8080/path?param1=value1"),
        ]
        
        for url, prefixes, expected in test_cases:
            with self.subTest(url=url, prefixes=prefixes):
                result = strip_query_params(url, prefixes)
                self.assertEqual(result, expected)

    def test_normalize_prefixes(self):
        """Test prefix normalization."""
        test_cases = [
            # String input
            ("utm_", ["utm_"]),
            
            # List input
            (["utm_", "fbclid"], ["utm_", "fbclid"]),
            
            # Empty inputs
            ("", []),
            ([], []),
            (None, []),
            
            # Whitespace handling
            (["  utm_  ", "fbclid", "  "], ["utm_", "fbclid"]),
        ]
        
        for input_val, expected in test_cases:
            with self.subTest(input_val=input_val):
                result = normalize_prefixes(input_val)
                self.assertEqual(result, expected)

    def test_is_tracking_parameter(self):
        """Test tracking parameter detection (case-insensitive)."""
        prefixes = ["utm_", "fbclid", "gclid"]
        
        # Should match (case-insensitive)
        matching_cases = [
            ("utm_source", True),
            ("UTM_SOURCE", True),
            ("Utm_Source", True),
            ("utm_medium", True),
            ("fbclid", True),
            ("FBCLID", True),
            ("FbClId", True),
            ("gclid", True),
            ("GCLID", True),
            ("GcLiD", True),
        ]
        
        for param, expected in matching_cases:
            with self.subTest(param=param):
                result = is_tracking_parameter(param, prefixes)
                self.assertEqual(result, expected)
        
        # Should not match
        non_matching_cases = [
            ("source_utm", False),
            ("id_fbclid", False),
            ("utm", False),  # Missing underscore
            ("fbcli", False),  # Missing 'd'
            ("regular_param", False),
            ("", False),
        ]
        
        for param, expected in non_matching_cases:
            with self.subTest(param=param):
                result = is_tracking_parameter(param, prefixes)
                self.assertEqual(result, expected)

    def test_is_tracking_parameter_edge_cases(self):
        """Test edge cases for tracking parameter detection."""
        test_cases = [
            # Empty inputs
            ("", [], False),
            ("utm_source", [], False),
            ("", ["utm_"], False),
            
            # None inputs
            (None, ["utm_"], False),
            ("utm_source", None, False),
        ]
        
        for param, prefixes, expected in test_cases:
            with self.subTest(param=param, prefixes=prefixes):
                result = is_tracking_parameter(param, prefixes)
                self.assertEqual(result, expected)


if __name__ == '__main__':
    unittest.main() 