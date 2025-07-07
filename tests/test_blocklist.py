#!/usr/bin/env python3
"""Test blocklist functionality."""

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


class TestBlocklist(unittest.TestCase):
    """Test blocklist functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.blocklist_file = os.path.join(self.temp_dir, 'test_blocklist.yml')
        
        # Create a test blocklist file
        test_blocklist = {
            'whitelist': [
                'https://trusted.example.com/logo.png',
                'https://cdn.example.org/.*'
            ],
            'blacklisted': [
                {'sender': '^spam@malicious\\.com$'},
                {'sender': '^test.*@example\\.org$'},
                {'url': '^https://malicious\\.com/.*'},
                {'url': '^https://.*\\.phishing\\.net/.*'},
                {'url': '^https://tracking\\.example\\.com/.*'}
            ]
        }
        
        with open(self.blocklist_file, 'w') as f:
            yaml.dump(test_blocklist, f)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_detrackify_email_blocklist_loading(self):
        """Test that detrackify_email.py loads blocklist correctly."""
        config = Configuration()
        config.set(Configuration.CFG_BLOCKLIST_FILE, self.blocklist_file)
        config.load_blocklist_from_file()
        
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

    def test_detrackify_guard_blocklist_loading(self):
        """Test that detrackify_guard.py loads blocklist correctly."""
        guard_config = GuardConfig(
            salt='test-salt',
            blocklist_file=self.blocklist_file
        )
        
        server = GuardServer(guard_config)
        
        # Test URL blacklist checking
        self.assertTrue(server.blocklist.is_url_blacklisted('https://malicious.com/evil'))
        self.assertTrue(server.blocklist.is_url_blacklisted('https://sub.phishing.net/bad'))
        self.assertTrue(server.blocklist.is_url_blacklisted('https://tracking.example.com/pixel.gif'))
        
        # Test non-matching cases
        self.assertFalse(server.blocklist.is_url_blacklisted('https://good.example.com/safe'))

    def test_blocklist_file_not_found(self):
        """Test handling of missing blocklist file."""
        config = Configuration()
        config.set(Configuration.CFG_BLOCKLIST_FILE, '/nonexistent/file.yml')
        
        # Should not raise an exception
        config.load_blocklist_from_file()
        
        # Should not match anything
        self.assertFalse(config.is_blacklisted('https://any.url'))
        self.assertFalse(config.is_sender_blacklisted('any@email.com'))

    def test_invalid_blocklist_format(self):
        """Test handling of invalid blocklist format."""
        # Create invalid blocklist file
        invalid_blocklist_file = os.path.join(self.temp_dir, 'invalid_blocklist.yml')
        with open(invalid_blocklist_file, 'w') as f:
            f.write('invalid: yaml: content: [')
        
        config = Configuration()
        config.set(Configuration.CFG_BLOCKLIST_FILE, invalid_blocklist_file)
        
        # Should not raise an exception
        config.load_blocklist_from_file()
        
        # Should not match anything
        self.assertFalse(config.is_blacklisted('https://any.url'))


if __name__ == '__main__':
    unittest.main() 