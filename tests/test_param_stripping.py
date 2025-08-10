#!/usr/bin/env python3
"""Test cases for URL parameter stripping functionality."""

import unittest
import sys
import os
import tempfile
import yaml

# Add the parent directory to the path so we can import detrackify_email
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detrackify_email import Configuration, Detector, Detrackify


class TestParameterStripping(unittest.TestCase):
    """Test URL parameter stripping functionality."""

    def setUp(self):
        """Set up test configuration."""
        self.config = Configuration()
        self.config.set(Configuration.CFG_STRIP_PARAM_PREFIX, ['utm_', 'fbclid', 'gclid'])
        self.config.set(Configuration.CFG_STRIP_ENABLE, True)
        self.detector = Detector(self.config)
        self.detrackify = Detrackify(self.config)

    def test_strip_query_params_basic(self):
        """
        Test basic URL parameter stripping functionality.
        
        Expected outcome: When a URL contains tracking parameters (utm_source)
        mixed with legitimate parameters, only the tracking parameter and all
        subsequent parameters should be removed while preserving earlier parameters.
        """
        url = "https://example.com/?param1=value1&utm_source=test&param2=value2"
        result = self.detector.strip_query_params(url)
        self.assertEqual(result, "https://example.com/?param1=value1")

    def test_strip_query_params_multiple_prefixes(self):
        """
        Test parameter stripping with multiple configured prefixes.
        
        Expected outcome: Different tracking parameter prefixes (utm_, fbclid, gclid)
        should all be detected and stripped correctly, demonstrating multi-prefix support.
        """
        url = "https://example.com/?param1=value1&fbclid=12345&param2=value2"
        result = self.detector.strip_query_params(url)
        self.assertEqual(result, "https://example.com/?param1=value1")

    def test_strip_query_params_first_param_matches(self):
        """
        Test parameter stripping when the first parameter matches a tracking prefix.
        
        Expected outcome: When the first query parameter is a tracking parameter,
        all parameters should be removed, leaving only the base URL.
        """
        url = "https://example.com/?utm_source=test&param1=value1"
        result = self.detector.strip_query_params(url)
        self.assertEqual(result, "https://example.com/")

    def test_strip_query_params_no_match(self):
        """
        Test parameter stripping when no parameters match configured prefixes.
        
        Expected outcome: When no tracking parameters are present, the URL should
        remain unchanged, preserving all legitimate parameters.
        """
        url = "https://example.com/?param1=value1&param2=value2"
        result = self.detector.strip_query_params(url)
        self.assertEqual(result, url)

    def test_strip_query_params_no_query_string(self):
        """
        Test parameter stripping on URLs without query strings.
        
        Expected outcome: URLs without query parameters should remain unchanged,
        demonstrating that the function handles URLs with no parameters gracefully.
        """
        url = "https://example.com/path"
        result = self.detector.strip_query_params(url)
        self.assertEqual(result, url)

    def test_strip_query_params_empty_url(self):
        """
        Test parameter stripping with empty URL input.
        
        Expected outcome: Empty strings should be handled gracefully without
        errors, returning the empty string unchanged.
        """
        url = ""
        result = self.detector.strip_query_params(url)
        self.assertEqual(result, url)

    def test_strip_query_params_malformed_url(self):
        """
        Test parameter stripping with malformed URL input.
        
        Expected outcome: Invalid URLs should be handled gracefully without
        crashing, returning the input unchanged to avoid breaking email content.
        """
        url = "not-a-url"
        result = self.detector.strip_query_params(url)
        self.assertEqual(result, url)

    def test_strip_query_params_no_prefixes_configured(self):
        """
        Test parameter stripping when no prefixes are configured.
        
        Expected outcome: When no tracking prefixes are configured, URLs should
        remain unchanged regardless of their parameters, demonstrating opt-in behavior.
        """
        config = Configuration()
        config.set(Configuration.CFG_STRIP_PARAM_PREFIX, [])
        detector = Detector(config)
        url = "https://example.com/?utm_source=test&param1=value1"
        result = detector.strip_query_params(url)
        self.assertEqual(result, url)

    def test_strip_query_params_with_fragments(self):
        """
        Test parameter stripping on URLs with fragment identifiers.
        
        Expected outcome: URL fragments (hash sections) should be preserved
        while tracking parameters are stripped from the query string portion.
        """
        url = "https://example.com/path?param1=value1&utm_source=test&param2=value2#section"
        result = self.detector.strip_query_params(url)
        self.assertEqual(result, "https://example.com/path?param1=value1#section")

    def test_strip_query_params_with_port(self):
        """
        Test parameter stripping on URLs with port numbers.
        
        Expected outcome: Port numbers should be preserved in the URL
        while tracking parameters are stripped from the query string.
        """
        url = "https://example.com:8080/path?param1=value1&utm_source=test&param2=value2"
        result = self.detector.strip_query_params(url)
        self.assertEqual(result, "https://example.com:8080/path?param1=value1")

    def test_strip_query_params_partial_match(self):
        """
        Test that partial parameter name matches trigger stripping correctly.
        
        Expected outcome: Parameters that start with configured prefixes should
        be stripped even if they have additional characters after the prefix.
        """
        url = "https://example.com/?param1=value1&utm_test=value2&param2=value3"
        result = self.detector.strip_query_params(url)
        # utm_test should match utm_ prefix because it starts with utm_
        self.assertEqual(result, "https://example.com/?param1=value1")

    def test_strip_query_params_case_insensitive(self):
        """
        Test that parameter stripping is case-insensitive.
        
        Expected outcome: Tracking parameters should be detected and stripped
        regardless of case (utm_source, UTM_SOURCE, Utm_Source should all match),
        ensuring robust tracking parameter detection.
        """
        test_cases = [
            # UTM parameters in various cases
            ("https://example.com/?param1=value1&utm_source=test&param2=value2", "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&UTM_SOURCE=test&param2=value2", "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&Utm_Source=test&param2=value2", "https://example.com/?param1=value1"),
            
            # Facebook click ID in various cases
            ("https://example.com/?param1=value1&fbclid=123&param2=value2", "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&FBCLID=123&param2=value2", "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&FbClId=123&param2=value2", "https://example.com/?param1=value1"),
            
            # Google click ID in various cases
            ("https://example.com/?param1=value1&gclid=456&param2=value2", "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&GCLID=456&param2=value2", "https://example.com/?param1=value1"),
            ("https://example.com/?param1=value1&GcLiD=456&param2=value2", "https://example.com/?param1=value1"),
        ]
        
        for url, expected in test_cases:
            with self.subTest(url=url):
                result = self.detector.strip_query_params(url)
                self.assertEqual(result, expected)

    def test_strip_query_params_exact_prefix_match(self):
        """
        Test exact prefix matching including edge cases.
        
        Expected outcome: Parameters that exactly match the prefix (like utm_=value)
        should be stripped, demonstrating that prefix matching works even
        when there are no characters after the prefix.
        """
        url = "https://example.com/?param1=value1&utm_=value2&param2=value3"
        result = self.detector.strip_query_params(url)
        self.assertEqual(result, "https://example.com/?param1=value1")

    def test_process_strip_params_method(self):
        """
        Test the process_strip_params method on HTML elements.
        
        Expected outcome: The method should process HTML img tags, strip tracking
        parameters from src URLs, and return both the cleaned URL and reasons
        for the changes made.
        """
        from bs4 import BeautifulSoup
        
        # Create a fake image tag
        html = '<img src="https://example.com/image.png?param1=value1&utm_source=test&param2=value2" />'
        soup = BeautifulSoup(html, 'html.parser')
        img_tag = soup.find('img')
        
        result_url, reasons = self.detrackify.process_strip_params(img_tag)
        
        self.assertEqual(result_url, "https://example.com/image.png?param1=value1")
        self.assertIn('Parameter stripping', reasons)

    def test_process_strip_params_no_change(self):
        """
        Test process_strip_params when no parameters need stripping.
        
        Expected outcome: When HTML elements contain no tracking parameters,
        the URL should remain unchanged and no reasons should be provided,
        demonstrating that the method only acts when necessary.
        """
        from bs4 import BeautifulSoup
        
        # Create a fake image tag with no tracking parameters
        html = '<img src="https://example.com/image.png?param1=value1&param2=value2" />'
        soup = BeautifulSoup(html, 'html.parser')
        img_tag = soup.find('img')
        
        result_url, reasons = self.detrackify.process_strip_params(img_tag)
        
        self.assertEqual(result_url, "https://example.com/image.png?param1=value1&param2=value2")
        self.assertEqual(reasons, [])

    def test_config_file_loading(self):
        """
        Test loading parameter prefixes from YAML configuration file.
        
        Expected outcome: Configuration should be loaded from YAML file correctly,
        demonstrating that parameter prefixes can be configured via external
        configuration files rather than just command-line arguments.
        """
        config_data = {
            'email': {
                'strip': {
                    'param_prefix': ['utm_', 'fbclid', 'custom_']
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            config = Configuration()
            config.load(config_path)
            prefixes = config.get(Configuration.CFG_STRIP_PARAM_PREFIX, [])
            # The config file values should be loaded (replaces defaults)
            self.assertEqual(prefixes, ['utm_', 'fbclid', 'custom_'])
        finally:
            os.unlink(config_path)

    def test_integration_with_image_processing(self):
        """
        Test integration of parameter stripping with main image processing workflow.
        
        Expected outcome: Parameter stripping should work seamlessly within the
        main email processing pipeline, cleaning tracking parameters from image
        URLs while preserving legitimate parameters and maintaining HTML structure.
        """
        from bs4 import BeautifulSoup
        
        # Test the process_strip_params method directly on HTML img elements
        html = '''
        <html>
        <body>
            <img src="https://example.com/image1.png?param1=value1&utm_source=test&param2=value2" width="200" height="150" />
            <img src="https://example.com/image2.png?param1=value1&param2=value2" width="200" height="150" />
            <img src="https://example.com/image3.png?fbclid=12345&param1=value1" width="200" height="150" />
        </body>
        </html>
        '''
        
        soup = BeautifulSoup(html, 'html.parser')
        img_tags = soup.find_all('img')
        
        # Test parameter stripping on each image
        result_url1, reasons1 = self.detrackify.process_strip_params(img_tags[0])
        result_url2, reasons2 = self.detrackify.process_strip_params(img_tags[1])
        result_url3, reasons3 = self.detrackify.process_strip_params(img_tags[2])
        
        # Check that tracking parameters were stripped
        self.assertEqual(result_url1, "https://example.com/image1.png?param1=value1")
        self.assertIn('Parameter stripping', reasons1)
        
        # Check that non-tracking parameters remain unchanged
        self.assertEqual(result_url2, "https://example.com/image2.png?param1=value1&param2=value2")
        self.assertEqual(reasons2, [])
        
        # Check that fbclid parameter was stripped
        self.assertEqual(result_url3, "https://example.com/image3.png")
        self.assertIn('Parameter stripping', reasons3)


if __name__ == '__main__':
    unittest.main() 