"""Tests for rewrite rules functionality in detrackify_email."""

import email
import os
import subprocess
import sys
import tempfile
import yaml
import pytest
from bs4 import BeautifulSoup
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detrackify_email.configuration import Configuration
from detrackify_email.detrackify import Detrackify


class TestRewriteRules:
    """Test class for rewrite rules functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = Configuration()
        self.detrackify = Detrackify(self.config)
        
        # Create a simple test email content
        self.test_email_content = """From: sender@example.com
To: recipient@test.com
Subject: Test Email
Content-Type: text/html; charset=utf-8

<html>
<body>
<img src="https://old.example.com/image1.jpg" alt="Image 1">
<img src="https://old.example.com/image2.png" alt="Image 2">
<img src="https://new.example.com/logo.png" alt="Logo">
<img src="https://tracking.example.com/pixel.gif" alt="Tracking">
<a href="https://old.example.com/page1">Link 1</a>
<a href="https://new.example.com/page2">Link 2</a>
</body>
</html>
"""
    
    def create_test_email_file(self, content=None):
        """Create a temporary email file for testing."""
        if content is None:
            content = self.test_email_content
            
        with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
            return f.name
    
    def process_email_with_config(self, email_path, config_data=None):
        """Process an email with the given configuration."""
        if config_data is None:
            config_data = {}
            
        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name
            f.flush()
            os.fsync(f.fileno())
        
        # Create temporary output file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            output_path = f.name
        
        try:
            # Run detrackify_email.py
            script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "detrackify_email.py")
            subprocess.run([
                sys.executable,
                script_path,
                "--input", email_path,
                "--output", output_path,
                "--config", config_path,
                "--verbose"
            ], check=True, capture_output=True, text=True)
            
            # Read the processed email
            with open(output_path, 'rb') as f:
                return email.message_from_bytes(f.read())
        finally:
            # Clean up temporary files
            os.unlink(config_path)
            os.unlink(output_path)
    
    def extract_images_from_email(self, msg):
        """Extract image URLs from email message."""
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
                soup = BeautifulSoup(html, "html.parser")
                return [img.get('src') for img in soup.find_all('img') if img.get('src')]
        return []
    
    def extract_links_from_email(self, msg):
        """Extract link URLs from email message."""
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
                soup = BeautifulSoup(html, "html.parser")
                return [a.get('href') for a in soup.find_all('a') if a.get('href')]
        return []


class TestRewriteRulesConfiguration:
    """Test rewrite rules configuration loading and validation."""
    
    def test_rewrite_rules_loaded_from_config(self):
        """Test that rewrite rules are properly loaded from configuration."""
        config = Configuration()
        
        # Test data
        config_data = {
            'email': {
                'rewrite': [
                {
                    'from': r'https://old\.example\.com/(.+)',
                    'to': r'https://new.example.com/\1'
                },
                {
                    'from': r'https://tracking\.example\.com/(.+)',
                    'to': r'https://clean.example.com/\1'
                }
                ]
            }
        }
        
        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name
            f.flush()
            os.fsync(f.fileno())
        
        try:
            # Load configuration
            assert config.load_from_yaml(config_path)
            
            # Verify rewrite rules are loaded
            rewrite_rules = config.config.get('rewrite', [])
            assert len(rewrite_rules) == 2
            assert rewrite_rules[0]['from'] == r'https://old\.example\.com/(.+)'
            assert rewrite_rules[0]['to'] == r'https://new.example.com/\1'
            assert rewrite_rules[1]['from'] == r'https://tracking\.example\.com/(.+)'
            assert rewrite_rules[1]['to'] == r'https://clean.example.com/\1'
        finally:
            os.unlink(config_path)
    
    def test_rewrite_rules_empty_config(self):
        """Test that empty rewrite rules are handled correctly."""
        config = Configuration()
        
        # Test with no rewrite rules
        config_data = {}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name
            f.flush()
            os.fsync(f.fileno())
        
        try:
            assert config.load_from_yaml(config_path)
            rewrite_rules = config.config.get('rewrite', [])
            assert len(rewrite_rules) == 0
        finally:
            os.unlink(config_path)
    
    def test_rewrite_rules_invalid_format(self):
        """Test that invalid rewrite rule format is handled gracefully."""
        config = Configuration()
        
        # Test with invalid rewrite rule (missing 'to' field)
        config_data = {
            'email': {
                'rewrite': [
                {
                    'from': 'https://old.example.com/(.*)'
                    # Missing 'to' field
                }
                ]
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name
            f.flush()
            os.fsync(f.fileno())
        
        try:
            # Should still load successfully, but log error for invalid rule
            assert config.load_from_yaml(config_path)
            rewrite_rules = config.config.get('rewrite', [])
            assert len(rewrite_rules) == 1
        finally:
            os.unlink(config_path)


class TestRewriteRulesFunctionality:
    """Test the actual rewrite functionality."""
    
    def test_simple_url_rewrite(self):
        """Test simple URL rewriting with regex replacement."""
        config = Configuration()
        config.config['rewrite'] = [
            {
                'from': r'https://old\.example\.com/(.+)',
                'to': r'https://new.example.com/\1'
            }
        ]
        
        # Test URLs
        test_cases = [
            ('https://old.example.com/image.jpg', 'https://new.example.com/image.jpg'),
            ('https://old.example.com/path/to/file.png', 'https://new.example.com/path/to/file.png'),
            ('https://other.example.com/image.jpg', 'https://other.example.com/image.jpg'),  # No change
        ]
        
        for original, expected in test_cases:
            result = config.rewrite_url(original)
            assert result == expected, f"Expected {expected}, got {result} for {original}"
    
    def test_complex_regex_rewrite(self):
        """Test complex regex patterns in rewrite rules."""
        config = Configuration()
        config.config['rewrite'] = [
            {
                'from': r'https://([^.]+)\.example\.com/([^?]+)(\?.*)?',
                'to': r'https://\1.newdomain.com/\2'
            }
        ]
        
        # Test URLs
        test_cases = [
            ('https://old.example.com/image.jpg', 'https://old.newdomain.com/image.jpg'),
            ('https://tracking.example.com/pixel.gif?utm_source=test', 'https://tracking.newdomain.com/pixel.gif'),
            ('https://other.com/image.jpg', 'https://other.com/image.jpg'),  # No change
        ]
        
        for original, expected in test_cases:
            result = config.rewrite_url(original)
            assert result == expected, f"Expected {expected}, got {result} for {original}"
    
    def test_multiple_rewrite_rules(self):
        """Test that multiple rewrite rules are applied in order."""
        config = Configuration()
        config.config['rewrite'] = [
            {
                'from': r'https://old\.example\.com/(.+)',
                'to': r'https://new.example.com/\1'
            },
            {
                'from': r'https://new\.example\.com/(.+)',
                'to': r'https://final.example.com/\1'
            }
        ]
        
        # Test that only the first matching rule is applied
        original = 'https://old.example.com/image.jpg'
        expected = 'https://new.example.com/image.jpg'  # Only first rule applied
        result = config.rewrite_url(original)
        assert result == expected, f"Expected {expected}, got {result}"
    
    def test_rewrite_rules_with_special_characters(self):
        """Test rewrite rules with special regex characters."""
        config = Configuration()
        config.config['rewrite'] = [
            {
                'from': r'https://example\.com/([^/]+)/([^?]+)',
                'to': r'https://new.example.com/\2/\1'
            }
        ]
        
        # Test URL with special characters
        original = 'https://example.com/folder/image.jpg'
        expected = 'https://new.example.com/image.jpg/folder'
        result = config.rewrite_url(original)
        assert result == expected, f"Expected {expected}, got {result}"
    
    def test_rewrite_rules_no_match(self):
        """Test that URLs not matching any rewrite rules are unchanged."""
        config = Configuration()
        config.config['rewrite'] = [
            {
                'from': r'https://old\.example\.com/(.+)',
                'to': r'https://new.example.com/\1'
            }
        ]
        
        # Test URLs that shouldn't be rewritten
        test_urls = [
            'https://other.example.com/image.jpg',
            'https://new.example.com/image.jpg',
            'http://old.example.com/image.jpg',  # Different protocol
            'https://old.example.org/image.jpg',  # Different domain
        ]
        
        for url in test_urls:
            result = config.rewrite_url(url)
            assert result == url, f"URL should not be changed: {url} -> {result}"
    
    def test_rewrite_rules_invalid_regex(self):
        """Test that invalid regex patterns are handled gracefully."""
        config = Configuration()
        config.config['rewrite'] = [
            {
                'from': 'https://old.example.com/(.*',  # Invalid regex - missing closing parenthesis
                'to': 'https://new.example.com/$1'
            }
        ]
        
        # Should handle invalid regex gracefully
        original = 'https://old.example.com/image.jpg'
        # Should return original URL when regex is invalid
        result = config.rewrite_url(original)
        assert result == original, f"Should return original URL for invalid regex: {result}"


class TestRewriteRulesIntegration(TestRewriteRules):
    """Integration tests for rewrite rules with actual email processing."""
    
    def test_rewrite_rules_in_email_processing(self):
        """Test that rewrite rules are applied during email processing."""
        # Create test email
        email_content = """From: sender@example.com
To: recipient@test.com
Subject: Test Email
Content-Type: text/html; charset=utf-8

<html>
<body>
<img src="https://old.example.com/image1.jpg" alt="Image 1">
<img src="https://old.example.com/image2.png" alt="Image 2">
<img src="https://new.example.com/logo.png" alt="Logo">
</body>
</html>
"""
        
        email_path = self.create_test_email_file(email_content)
        
        # Configuration with rewrite rules
        config_data = {
            'email': {
                'rewrite': [
                {
                    'from': r'https://old\.example\.com/(.+)',
                    'to': r'https://new.example.com/\1'
                }
                ]
            }
        }
        
        try:
            # Process email
            msg = self.process_email_with_config(email_path, config_data)
            
            # Extract image URLs
            images = self.extract_images_from_email(msg)
            
            # Verify rewrite rules were applied
            assert 'https://new.example.com/image1.jpg' in images
            assert 'https://new.example.com/image2.png' in images
            assert 'https://new.example.com/logo.png' in images  # This was already correct
            
            # Verify original URLs are not present
            assert 'https://old.example.com/image1.jpg' not in images
            assert 'https://old.example.com/image2.png' not in images
        finally:
            os.unlink(email_path)
    
    def test_rewrite_rules_with_tracking_detection(self):
        """Test that rewrite rules work alongside tracking detection."""
        # Create test email with tracking pixel
        email_content = """From: sender@example.com
To: recipient@test.com
Subject: Test Email
Content-Type: text/html; charset=utf-8

<html>
<body>
<img src="https://tracking.example.com/pixel.gif" width="1" height="1" alt="">
<img src="https://old.example.com/logo.png" alt="Logo">
</body>
</html>
"""
        
        email_path = self.create_test_email_file(email_content)
        
        # Configuration with rewrite rules and blacklist
        config_data = {
            'email': {
                'rewrite': [
                {
                    'from': r'https://old\.example\.com/(.+)',
                    'to': r'https://new.example.com/\1'
                }
                ],
                'blacklist': [
                    'https://tracking.example.com/.*'
                ]
            }
        }
        
        try:
            # Process email
            msg = self.process_email_with_config(email_path, config_data)
            
            # Extract image URLs
            images = self.extract_images_from_email(msg)
            
            # Verify rewrite rule was applied to non-tracking image
            assert 'https://new.example.com/logo.png' in images
            
            # Verify tracking pixel was replaced (should be a blank tracker)
            tracking_images = [img for img in images if 'tracking.example.com' not in img]
            assert len(tracking_images) == 2  # One rewritten, one replaced with blank tracker
        finally:
            os.unlink(email_path)
    
    def test_rewrite_rules_with_whitelist(self):
        """Test that rewrite rules work with whitelisted URLs."""
        # Create test email
        email_content = """From: sender@example.com
To: recipient@test.com
Subject: Test Email
Content-Type: text/html; charset=utf-8

<html>
<body>
<img src="https://old.example.com/image1.jpg" alt="Image 1">
<img src="https://trusted.example.com/logo.png" alt="Trusted Logo">
</body>
</html>
"""
        
        email_path = self.create_test_email_file(email_content)
        
        # Configuration with rewrite rules and whitelist
        config_data = {
            'email': {
                'rewrite': [
                {
                    'from': r'https://old\.example\.com/(.+)',
                    'to': r'https://new.example.com/\1'
                }
                ],
                'whitelist': [
                    'https://trusted.example.com/.*'
                ]
            }
        }
        
        try:
            # Process email
            msg = self.process_email_with_config(email_path, config_data)
            
            # Extract image URLs
            images = self.extract_images_from_email(msg)
            
            # Verify rewrite rule was applied to non-whitelisted image
            assert 'https://new.example.com/image1.jpg' in images
            
            # Verify whitelisted image was not rewritten
            assert 'https://trusted.example.com/logo.png' in images
        finally:
            os.unlink(email_path)
    
    def test_rewrite_rules_multiple_patterns(self):
        """Test multiple rewrite patterns in the same email."""
        # Create test email
        email_content = """From: sender@example.com
To: recipient@test.com
Subject: Test Email
Content-Type: text/html; charset=utf-8

<html>
<body>
<img src="https://old.example.com/image1.jpg" alt="Image 1">
<img src="https://tracking.example.com/pixel.gif" alt="Tracking">
<img src="https://cdn.example.com/asset.png" alt="Asset">
</body>
</html>
"""
        
        email_path = self.create_test_email_file(email_content)
        
        # Configuration with multiple rewrite rules
        config_data = {
            'email': {
                'rewrite': [
                {
                    'from': r'https://old\.example\.com/(.+)',
                    'to': r'https://new.example.com/\1'
                },
                {
                    'from': r'https://tracking\.example\.com/(.+)',
                    'to': r'https://clean.example.com/\1'
                },
                {
                    'from': r'https://cdn\.example\.com/(.+)',
                    'to': r'https://static.example.com/\1'
                }
                ]
            }
        }
        
        try:
            # Process email
            msg = self.process_email_with_config(email_path, config_data)
            
            # Extract image URLs
            images = self.extract_images_from_email(msg)
            
            # Verify rewrite rules were applied
            assert 'https://new.example.com/image1.jpg' in images
            assert 'https://static.example.com/asset.png' in images
            
            # Verify tracking pixel was replaced with blank tracker (not rewritten)
            tracking_images = [img for img in images if 'tracking.example.com' not in img and 'clean.example.com' not in img]
            assert len(tracking_images) == 3  # Two rewritten + one blank tracker
            
            # Verify original URLs are not present
            assert 'https://old.example.com/image1.jpg' not in images
            assert 'https://tracking.example.com/pixel.gif' not in images
            assert 'https://cdn.example.com/asset.png' not in images
        finally:
            os.unlink(email_path)


class TestRewriteRulesEdgeCases(TestRewriteRules):
    """Test edge cases and error conditions for rewrite rules."""
    
    def test_rewrite_rules_empty_url(self):
        """Test rewrite rules with empty URL."""
        config = Configuration()
        config.config['rewrite'] = [
            {
                'from': r'https://old\.example\.com/(.+)',
                'to': r'https://new.example.com/\1'
            }
        ]
        
        # Test empty URL
        result = config.rewrite_url('')
        assert result == ''
    
    def test_rewrite_rules_none_url(self):
        """Test rewrite rules with None URL."""
        config = Configuration()
        config.config['rewrite'] = [
            {
                'from': r'https://old\.example\.com/(.+)',
                'to': r'https://new.example.com/\1'
            }
        ]
        
        # Test None URL
        result = config.rewrite_url(None)
        assert result is None
    
    def test_rewrite_rules_malformed_rule(self):
        """Test rewrite rules with malformed rule structure."""
        config = Configuration()
        config.config['rewrite'] = [
            {
                'from': r'https://old\.example\.com/(.+)',
                'to': r'https://new.example.com/\1'
            },
            {
                'invalid_field': 'some_value'
            },
            {
                'from': r'https://another\.example\.com/(.+)',
                'to': r'https://replacement.example.com/\1'
            }
        ]
        
        # Should handle malformed rules gracefully
        test_url = 'https://old.example.com/image.jpg'
        result = config.rewrite_url(test_url)
        assert result == 'https://new.example.com/image.jpg'
        
        test_url2 = 'https://another.example.com/image.jpg'
        result2 = config.rewrite_url(test_url2)
        assert result2 == 'https://replacement.example.com/image.jpg'
    
    def test_rewrite_rules_case_sensitivity(self):
        """Test that rewrite rules are case sensitive by default."""
        config = Configuration()
        config.config['rewrite'] = [
            {
                'from': r'https://old\.example\.com/(.+)',
                'to': r'https://new.example.com/\1'
            }
        ]
        
        # Test case sensitivity
        test_cases = [
            ('https://OLD.example.com/image.jpg', 'https://OLD.example.com/image.jpg'),  # No change
            ('https://Old.example.com/image.jpg', 'https://Old.example.com/image.jpg'),  # No change
            ('https://old.example.com/image.jpg', 'https://new.example.com/image.jpg'),  # Changed
        ]
        
        for original, expected in test_cases:
            result = config.rewrite_url(original)
            assert result == expected, f"Expected {expected}, got {result} for {original}"
    
    def test_rewrite_rules_case_insensitive(self):
        """Test rewrite rules with case insensitive matching."""
        config = Configuration()
        config.config['rewrite'] = [
            {
                'from': r'(?i)https://old\.example\.com/(.+)',  # Case insensitive flag
                'to': r'https://new.example.com/\1'
            }
        ]
        
        # Test case insensitive matching
        test_cases = [
            ('https://OLD.example.com/image.jpg', 'https://new.example.com/image.jpg'),
            ('https://Old.example.com/image.jpg', 'https://new.example.com/image.jpg'),
            ('https://old.example.com/image.jpg', 'https://new.example.com/image.jpg'),
        ]
        
        for original, expected in test_cases:
            result = config.rewrite_url(original)
            assert result == expected, f"Expected {expected}, got {result} for {original}"


class TestRewriteRulesPerformance(TestRewriteRules):
    """Test performance aspects of rewrite rules."""
    
    def test_rewrite_rules_large_number(self):
        """Test performance with a large number of rewrite rules."""
        config = Configuration()
        
        # Create many rewrite rules
        config.config['rewrite'] = []
        for i in range(100):
            config.config['rewrite'].append({
                'from': rf'https://old{i}\.example\.com/(.+)',
                'to': rf'https://new{i}.example.com/\1'
            })
        
        # Test performance
        import time
        start_time = time.time()
        
        test_url = 'https://old50.example.com/image.jpg'
        result = config.rewrite_url(test_url)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should complete in reasonable time (less than 1 second)
        assert processing_time < 1.0, f"Rewrite processing took too long: {processing_time} seconds"
        assert result == 'https://new50.example.com/image.jpg'
    
    def test_rewrite_rules_complex_regex(self):
        """Test performance with complex regex patterns."""
        config = Configuration()
        config.config['rewrite'] = [
            {
                'from': r'https://([^.]+)\.([^.]+)\.example\.com/([^?]+)(\?([^=]+)=([^&]*)(&([^=]+)=([^&]*))*)?',
                'to': r'https://\1.newdomain.com/\3'
            }
        ]
        
        # Test with complex URL
        complex_url = 'https://sub.domain.example.com/path/to/file.jpg?param1=value1&param2=value2&param3=value3'
        expected = 'https://sub.newdomain.com/path/to/file.jpg'
        
        import time
        start_time = time.time()
        result = config.rewrite_url(complex_url)
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should complete in reasonable time
        assert processing_time < 0.1, f"Complex regex processing took too long: {processing_time} seconds"
        assert result == expected


if __name__ == '__main__':
    pytest.main([__file__]) 