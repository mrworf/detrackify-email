#!/usr/bin/env python3
"""Test blacklist functionality."""

import os
import tempfile
import yaml
import unittest
from unittest.mock import patch, MagicMock

# Import the modules to test
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detrackify_email import Configuration
from detrackify_guard import GuardConfig, GuardServer

class TestBlacklist(unittest.TestCase):
    """Test blacklist functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.whitelist_file = os.path.join(self.temp_dir, 'test_whitelist.yml')
        self.blacklist_file = os.path.join(self.temp_dir, 'test_blacklist.yml')
        
        # Create a test whitelist file
        test_whitelist = {
            'whitelist': [
                'https://trusted.example.com/logo.png',
                'https://cdn.example.org/.*'
            ]
        }
        with open(self.whitelist_file, 'w') as f:
            yaml.dump(test_whitelist, f)
        
        # Create a test blacklist file
        test_blacklist = {
            'blacklist': [
                {'sender': '^spam@malicious\\.com$'},
                {'sender': '^test.*@example\\.org$'},
                {'url': '^https://malicious\\.com/.*'},
                {'url': '^https://.*\\.phishing\\.net/.*'},
                {'url': '^https://tracking\\.example\\.com/.*'}
            ]
        }
        with open(self.blacklist_file, 'w') as f:
            yaml.dump(test_blacklist, f)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_detrackify_email_blacklist_loading(self):
        """Test that detrackify_email.py loads blacklist and whitelist correctly."""
        config = Configuration()
        config.set(Configuration.CFG_WHITELIST_FILE, self.whitelist_file)
        config.set(Configuration.CFG_BLACKLIST_FILE, self.blacklist_file)
        config.load_whitelist_from_file()
        config.load_blacklist_from_file()
        
        # Test whitelist loading
        self.assertTrue(config.is_whitelisted('https://trusted.example.com/logo.png'))
        self.assertTrue(config.is_whitelisted('https://cdn.example.org/some/path'))
        
        # Test blacklist loading
        self.assertTrue(config.is_sender_blacklisted('spam@malicious.com'))
        self.assertTrue(config.is_sender_blacklisted('test123@example.org'))
        self.assertTrue(config.is_blacklisted('https://malicious.com/some/path'))
        self.assertTrue(config.is_blacklisted('https://sub.phishing.net/evil'))
        self.assertTrue(config.is_blacklisted('https://tracking.example.com/pixel.gif'))
        
        # Test non-matching cases
        self.assertFalse(config.is_sender_blacklisted('good@example.com'))
        self.assertFalse(config.is_blacklisted('https://good.example.com/safe'))

    def test_detrackify_guard_blacklist_loading(self):
        """Test that detrackify_guard.py loads blacklist correctly."""
        guard_config = GuardConfig(
            salt='test-salt',
            blacklist_file=self.blacklist_file
        )
        
        server = GuardServer(guard_config)
        
        # Test URL blacklist checking
        self.assertTrue(server.blocklist.is_url_blacklisted('https://malicious.com/evil'))
        self.assertTrue(server.blocklist.is_url_blacklisted('https://sub.phishing.net/bad'))
        self.assertTrue(server.blocklist.is_url_blacklisted('https://tracking.example.com/pixel.gif'))
        
        # Test non-matching cases
        self.assertFalse(server.blocklist.is_url_blacklisted('https://good.example.com/safe'))

    def test_blacklist_file_not_found(self):
        """Test handling of missing blacklist file."""
        config = Configuration()
        config.set(Configuration.CFG_BLACKLIST_FILE, '/nonexistent/file.yml')
        
        # Should not raise an exception
        config.load_blacklist_from_file()
        
        # Should not match anything
        self.assertFalse(config.is_blacklisted('https://any.url'))
        self.assertFalse(config.is_sender_blacklisted('any@email.com'))

    def test_invalid_blacklist_format(self):
        """Test handling of invalid blacklist format."""
        # Create invalid blacklist file
        invalid_blacklist_file = os.path.join(self.temp_dir, 'invalid_blacklist.yml')
        with open(invalid_blacklist_file, 'w') as f:
            f.write('invalid: yaml: content: [')
        
        config = Configuration()
        config.set(Configuration.CFG_BLACKLIST_FILE, invalid_blacklist_file)
        
        # Should not raise an exception
        config.load_blacklist_from_file()
        
        # Should not match anything
        self.assertFalse(config.is_blacklisted('https://any.url'))

if __name__ == '__main__':
    unittest.main() 