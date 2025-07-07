#!/usr/bin/env python3
"""Unit tests for domain aliases functionality in detrackify_guard.py."""

import os
import sys
import tempfile
import unittest
import yaml

# Add the parent directory to the path so we can import detrackify_guard
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from guard.config import GuardConfig
from detrackify_guard import GuardServer


class TestGuardDomainAliases(unittest.TestCase):
    """Test the domain aliases functionality in the guard server."""

    def test_guard_load_domain_aliases_from_file(self):
        """Test that guard server loads domain aliases from file."""
        # Create a test domain aliases file
        aliases_data = {
            'instacart.com': ['instacartemail.com'],
            'example.org': ['example-email.org', 'example-news.org'],
            'simple.org': 'simple-email.org'
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as aliases_file:
            yaml.dump(aliases_data, aliases_file)
            aliases_path = aliases_file.name
        
        try:
            # Create guard config with the aliases file
            config = GuardConfig(
                salt='test-salt',
                domain_aliases_file=aliases_path
            )
            
            # Create guard server
            server = GuardServer(config)
            
            # Test that aliases are loaded correctly
            self.assertTrue(server.domain_aliases.are_aliases('instacart.com', 'instacartemail.com'))
            self.assertTrue(server.domain_aliases.are_aliases('example.org', 'example-email.org'))
            self.assertTrue(server.domain_aliases.are_aliases('simple.org', 'simple-email.org'))
            
            # Test cross-group (should fail)
            self.assertFalse(server.domain_aliases.are_aliases('instacart.com', 'example.org'))
            
            # Test subdomain relationships
            self.assertTrue(server.domain_aliases.are_aliases('subdomain.example.org', 'example-email.org'))
            self.assertTrue(server.domain_aliases.are_aliases('example-email.org', 'subdomain.example.org'))
        finally:
            os.unlink(aliases_path)

    def test_guard_missing_aliases_file(self):
        """Test that guard server handles missing aliases file gracefully."""
        config = GuardConfig(
            salt='test-salt',
            domain_aliases_file='/nonexistent/aliases.yml'
        )
        
        # Should not raise an exception
        server = GuardServer(config)
        
        # Should have empty aliases
        self.assertEqual(server.domain_aliases.aliases, {})
        
        # Should not match any domains
        self.assertFalse(server.domain_aliases.are_aliases('example.com', 'other.com'))

    def test_guard_invalid_aliases_file(self):
        """Test that guard server handles invalid aliases file gracefully."""
        # Create an invalid YAML file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as aliases_file:
            aliases_file.write("invalid: yaml: content: [")
            aliases_path = aliases_file.name
        
        try:
            config = GuardConfig(
                salt='test-salt',
                domain_aliases_file=aliases_path
            )
            
            # Should not raise an exception
            server = GuardServer(config)
            
            # Should have empty aliases
            self.assertEqual(server.domain_aliases.aliases, {})
        finally:
            os.unlink(aliases_path)

    def test_guard_complex_alias_scenarios(self):
        """Test complex real-world alias scenarios in guard server."""
        aliases_data = {
            'instacart.com': ['instacartemail.com', 'instacart-email.com'],
            'amazon.com': ['amazon-email.com', 'amazon-news.com', 'amazon-support.com'],
            'google.com': 'google-email.com',
            'microsoft.com': ['outlook.com', 'hotmail.com', 'live.com']
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as aliases_file:
            yaml.dump(aliases_data, aliases_file)
            aliases_path = aliases_file.name
        
        try:
            config = GuardConfig(
                salt='test-salt',
                domain_aliases_file=aliases_path
            )
            
            server = GuardServer(config)
            
            # Test Instacart aliases
            self.assertTrue(server.domain_aliases.are_aliases('instacart.com', 'instacartemail.com'))
            self.assertTrue(server.domain_aliases.are_aliases('instacart.com', 'instacart-email.com'))
            self.assertTrue(server.domain_aliases.are_aliases('instacartemail.com', 'instacart-email.com'))
            
            # Test Amazon aliases
            self.assertTrue(server.domain_aliases.are_aliases('amazon.com', 'amazon-email.com'))
            self.assertTrue(server.domain_aliases.are_aliases('amazon-email.com', 'amazon-news.com'))
            self.assertTrue(server.domain_aliases.are_aliases('amazon-support.com', 'amazon-news.com'))
            
            # Test Google single alias
            self.assertTrue(server.domain_aliases.are_aliases('google.com', 'google-email.com'))
            
            # Test Microsoft multiple aliases
            self.assertTrue(server.domain_aliases.are_aliases('microsoft.com', 'outlook.com'))
            self.assertTrue(server.domain_aliases.are_aliases('outlook.com', 'hotmail.com'))
            self.assertTrue(server.domain_aliases.are_aliases('live.com', 'hotmail.com'))
            
            # Test cross-company (should fail)
            self.assertFalse(server.domain_aliases.are_aliases('instacart.com', 'amazon.com'))
            self.assertFalse(server.domain_aliases.are_aliases('google.com', 'microsoft.com'))
        finally:
            os.unlink(aliases_path)


if __name__ == '__main__':
    unittest.main() 