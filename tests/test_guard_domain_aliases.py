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


    def test_parent_domain_matching(self):
        """Test that domains sharing the same parent domain are correctly identified as aliases."""
        # Create guard config without aliases file to test pure parent domain logic
        config = GuardConfig(
            salt='test-salt',
            domain_aliases_file=None
        )
        
        server = GuardServer(config)
        
        # Test cases where domains should match (same parent domain)
        positive_cases = [
            # Talkspace case that was broken
            ('team.talkspace.com', 'try.talkspace.com'),
            ('mail.talkspace.com', 'support.talkspace.com'),
            
            # Google domains
            ('mail.google.com', 'drive.google.com'),
            ('docs.google.com', 'calendar.google.com'),
            ('www.google.com', 'api.google.com'),
            
            # Microsoft domains
            ('outlook.live.com', 'onedrive.live.com'),
            ('mail.microsoft.com', 'support.microsoft.com'),
            
            # Example domains
            ('www.example.com', 'api.example.com'),
            ('mail.example.org', 'support.example.org'),
            ('sub1.example.net', 'sub2.example.net'),
            
            # Single-level domains (should match themselves)
            ('example.com', 'example.com'),
            ('google.com', 'google.com'),
            
            # Subdomain relationships (should still work)
            ('sub.example.com', 'example.com'),
            ('example.com', 'sub.example.com'),
            ('deep.sub.example.com', 'sub.example.com'),
        ]
        
        for domain1, domain2 in positive_cases:
            with self.subTest(domain1=domain1, domain2=domain2):
                self.assertTrue(
                    server.domain_aliases.are_aliases(domain1, domain2),
                    f"Expected {domain1} and {domain2} to match"
                )
    
    def test_parent_domain_matching_negative(self):
        """Test that domains with different parent domains are correctly identified as non-aliases."""
        # Create guard config without aliases file to test pure parent domain logic
        config = GuardConfig(
            salt='test-salt',
            domain_aliases_file=None
        )
        
        server = GuardServer(config)
        
        # Test cases where domains should NOT match (different parent domains)
        negative_cases = [
            # Different companies
            ('team.talkspace.com', 'mail.google.com'),
            ('example.com', 'other.com'),
            ('google.com', 'microsoft.com'),
            
            # Different TLDs
            ('example.com', 'example.org'),
            ('google.com', 'google.net'),
            ('talkspace.com', 'talkspace.org'),
            
            # Different second-level domains
            ('team.talkspace.com', 'team.otherspace.com'),
            ('mail.google.com', 'mail.gmail.com'),
            ('www.example.com', 'www.example2.com'),
            
            # Edge cases
            ('example.com', 'sub.example.com'),  # This should match due to subdomain logic
            ('sub.example.com', 'example.com'),  # This should match due to subdomain logic
            ('example.com', 'deep.sub.example.com'),  # This should match due to subdomain logic
            
            # Invalid domains
            ('', 'example.com'),
            ('example.com', ''),
            ('', ''),
            (None, 'example.com'),
            ('example.com', None),
        ]
        
        for domain1, domain2 in negative_cases:
            with self.subTest(domain1=domain1, domain2=domain2):
                # Skip the edge cases that should actually match due to subdomain logic
                if (domain1 == 'example.com' and domain2 == 'sub.example.com') or \
                   (domain1 == 'sub.example.com' and domain2 == 'example.com') or \
                   (domain1 == 'example.com' and domain2 == 'deep.sub.example.com'):
                    self.assertTrue(
                        server.domain_aliases.are_aliases(domain1, domain2),
                        f"Expected {domain1} and {domain2} to match due to subdomain relationship"
                    )
                else:
                    self.assertFalse(
                        server.domain_aliases.are_aliases(domain1, domain2),
                        f"Expected {domain1} and {domain2} NOT to match"
                    )
    
    def test_parent_domain_matching_edge_cases(self):
        """Test edge cases for parent domain matching."""
        config = GuardConfig(
            salt='test-salt',
            domain_aliases_file=None
        )
        
        server = GuardServer(config)
        
        # Test domains with different numbers of levels (should match due to subdomain logic)
        self.assertTrue(server.domain_aliases.are_aliases('example.com', 'sub.example.com'))
        self.assertTrue(server.domain_aliases.are_aliases('sub.example.com', 'example.com'))
        
        # Test domains with very long subdomains
        self.assertTrue(server.domain_aliases.are_aliases('very.deep.sub.example.com', 'another.deep.sub.example.com'))
        
        # Test case sensitivity
        self.assertTrue(server.domain_aliases.are_aliases('TEAM.TALKSPACE.COM', 'try.talkspace.com'))
        self.assertTrue(server.domain_aliases.are_aliases('team.talkspace.com', 'TRY.TALKSPACE.COM'))
        
        # Test domains with extra whitespace
        self.assertTrue(server.domain_aliases.are_aliases(' team.talkspace.com ', 'try.talkspace.com'))
        self.assertTrue(server.domain_aliases.are_aliases('team.talkspace.com', ' try.talkspace.com '))
    
    def test_parent_domain_matching_with_aliases(self):
        """Test that parent domain matching works correctly with configured aliases."""
        aliases_data = {
            'talkspace.com': ['talkspace-email.com'],
            'google.com': ['google-email.com']
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
            
            # Test that parent domain matching still works
            self.assertTrue(server.domain_aliases.are_aliases('team.talkspace.com', 'try.talkspace.com'))
            self.assertTrue(server.domain_aliases.are_aliases('mail.google.com', 'drive.google.com'))
            
            # Test that configured aliases still work
            self.assertTrue(server.domain_aliases.are_aliases('talkspace.com', 'talkspace-email.com'))
            self.assertTrue(server.domain_aliases.are_aliases('google.com', 'google-email.com'))
            
            # Test that subdomains of aliases work
            self.assertTrue(server.domain_aliases.are_aliases('team.talkspace.com', 'talkspace-email.com'))
            self.assertTrue(server.domain_aliases.are_aliases('mail.google.com', 'google-email.com'))
            
            # Test that cross-company still fails
            self.assertFalse(server.domain_aliases.are_aliases('talkspace.com', 'google.com'))
        finally:
            os.unlink(aliases_path)


if __name__ == '__main__':
    unittest.main() 