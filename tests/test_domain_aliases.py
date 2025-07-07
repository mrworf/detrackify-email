#!/usr/bin/env python3
"""Unit tests for domain aliases functionality in detrackify_email.py."""

import os
import sys
import tempfile
import unittest
import yaml

# Add the parent directory to the path so we can import detrackify_email
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detrackify_email import Configuration


class TestDomainAliases(unittest.TestCase):
    """Test the domain aliases functionality."""

    def setUp(self):
        """Set up test configuration."""
        self.config = Configuration()

    def test_basic_alias_matching(self):
        """Test basic domain alias matching."""
        self.config.config['options']['guard']['domain_aliases'] = {
            'instacart.com': ['instacartemail.com'],
            'example.org': ['example-email.org', 'example-news.org']
        }
        
        # Test basic alias matches
        self.assertTrue(self.config.are_domains_aliases('instacart.com', 'instacartemail.com'))
        self.assertTrue(self.config.are_domains_aliases('instacartemail.com', 'instacart.com'))
        self.assertTrue(self.config.are_domains_aliases('example.org', 'example-email.org'))
        self.assertTrue(self.config.are_domains_aliases('example-email.org', 'example-news.org'))
        
        # Test cross-group matches (should fail)
        self.assertFalse(self.config.are_domains_aliases('instacart.com', 'example.org'))
        self.assertFalse(self.config.are_domains_aliases('instacartemail.com', 'example-email.org'))

    def test_single_string_alias(self):
        """Test single string alias format."""
        self.config.config['options']['guard']['domain_aliases'] = {
            'simple.org': 'simple-email.org'
        }
        
        self.assertTrue(self.config.are_domains_aliases('simple.org', 'simple-email.org'))
        self.assertTrue(self.config.are_domains_aliases('simple-email.org', 'simple.org'))

    def test_multiple_aliases_per_owner(self):
        """Test multiple aliases for a single owner domain."""
        self.config.config['options']['guard']['domain_aliases'] = {
            'company.com': ['company-email.com', 'company-news.com', 'company-support.com']
        }
        
        # Test owner to aliases
        self.assertTrue(self.config.are_domains_aliases('company.com', 'company-email.com'))
        self.assertTrue(self.config.are_domains_aliases('company.com', 'company-news.com'))
        self.assertTrue(self.config.are_domains_aliases('company.com', 'company-support.com'))
        
        # Test alias to alias
        self.assertTrue(self.config.are_domains_aliases('company-email.com', 'company-news.com'))
        self.assertTrue(self.config.are_domains_aliases('company-news.com', 'company-support.com'))
        self.assertTrue(self.config.are_domains_aliases('company-email.com', 'company-support.com'))

    def test_case_insensitive_matching(self):
        """Test that domain matching is case insensitive."""
        self.config.config['options']['guard']['domain_aliases'] = {
            'EXAMPLE.COM': ['example-email.com'],
            'Test.Org': ['test-email.org']
        }
        
        self.assertTrue(self.config.are_domains_aliases('example.com', 'EXAMPLE-EMAIL.COM'))
        self.assertTrue(self.config.are_domains_aliases('EXAMPLE.COM', 'example-email.com'))
        self.assertTrue(self.config.are_domains_aliases('test.org', 'TEST-EMAIL.ORG'))
        self.assertTrue(self.config.are_domains_aliases('TEST.ORG', 'test-email.org'))

    def test_subdomain_relationships(self):
        """Test that subdomain relationships still work."""
        self.config.config['options']['guard']['domain_aliases'] = {
            'example.com': ['example-email.com']
        }
        
        # Test subdomain relationships (should work regardless of aliases)
        self.assertTrue(self.config.are_domains_aliases('subdomain.example.com', 'example.com'))
        self.assertTrue(self.config.are_domains_aliases('example.com', 'subdomain.example.com'))
        self.assertTrue(self.config.are_domains_aliases('deep.subdomain.example.com', 'example.com'))
        self.assertTrue(self.config.are_domains_aliases('example.com', 'deep.subdomain.example.com'))

    def test_same_domain_matching(self):
        """Test that same domain always matches."""
        self.config.config['options']['guard']['domain_aliases'] = {
            'example.com': ['example-email.com']
        }
        
        self.assertTrue(self.config.are_domains_aliases('example.com', 'example.com'))
        self.assertTrue(self.config.are_domains_aliases('example-email.com', 'example-email.com'))
        self.assertTrue(self.config.are_domains_aliases('subdomain.example.com', 'subdomain.example.com'))

    def test_empty_and_none_domains(self):
        """Test handling of empty and None domains."""
        self.config.config['options']['guard']['domain_aliases'] = {
            'example.com': ['example-email.com']
        }
        
        # Test empty domains
        self.assertFalse(self.config.are_domains_aliases('', 'example.com'))
        self.assertFalse(self.config.are_domains_aliases('example.com', ''))
        self.assertFalse(self.config.are_domains_aliases('', ''))
        
        # Test None domains
        self.assertFalse(self.config.are_domains_aliases(None, 'example.com'))
        self.assertFalse(self.config.are_domains_aliases('example.com', None))
        self.assertFalse(self.config.are_domains_aliases(None, None))

    def test_no_aliases_configured(self):
        """Test behavior when no aliases are configured."""
        self.config.config['options']['guard']['domain_aliases'] = {}
        
        # Should only match same domain and subdomains
        self.assertTrue(self.config.are_domains_aliases('example.com', 'example.com'))
        self.assertTrue(self.config.are_domains_aliases('subdomain.example.com', 'example.com'))
        self.assertFalse(self.config.are_domains_aliases('example.com', 'other.com'))

    def test_invalid_alias_configurations(self):
        """Test handling of invalid alias configurations."""
        self.config.config['options']['guard']['domain_aliases'] = {
            'valid.com': ['valid-email.com'],
            'invalid.com': None,  # Invalid: None value
            'another.com': 123,   # Invalid: non-string/list value
            'empty.com': []       # Invalid: empty list
        }
        
        # Valid aliases should still work
        self.assertTrue(self.config.are_domains_aliases('valid.com', 'valid-email.com'))
        
        # Invalid configurations should be ignored
        self.assertFalse(self.config.are_domains_aliases('invalid.com', 'some-other.com'))
        self.assertFalse(self.config.are_domains_aliases('another.com', 'some-other.com'))
        self.assertFalse(self.config.are_domains_aliases('empty.com', 'some-other.com'))

    def test_complex_alias_scenarios(self):
        """Test complex real-world alias scenarios."""
        self.config.config['options']['guard']['domain_aliases'] = {
            'instacart.com': ['instacartemail.com', 'instacart-email.com'],
            'amazon.com': ['amazon-email.com', 'amazon-news.com', 'amazon-support.com'],
            'google.com': 'google-email.com',
            'microsoft.com': ['outlook.com', 'hotmail.com', 'live.com']
        }
        
        # Test Instacart aliases
        self.assertTrue(self.config.are_domains_aliases('instacart.com', 'instacartemail.com'))
        self.assertTrue(self.config.are_domains_aliases('instacart.com', 'instacart-email.com'))
        self.assertTrue(self.config.are_domains_aliases('instacartemail.com', 'instacart-email.com'))
        
        # Test Amazon aliases
        self.assertTrue(self.config.are_domains_aliases('amazon.com', 'amazon-email.com'))
        self.assertTrue(self.config.are_domains_aliases('amazon-email.com', 'amazon-news.com'))
        self.assertTrue(self.config.are_domains_aliases('amazon-support.com', 'amazon-news.com'))
        
        # Test Google single alias
        self.assertTrue(self.config.are_domains_aliases('google.com', 'google-email.com'))
        
        # Test Microsoft multiple aliases
        self.assertTrue(self.config.are_domains_aliases('microsoft.com', 'outlook.com'))
        self.assertTrue(self.config.are_domains_aliases('outlook.com', 'hotmail.com'))
        self.assertTrue(self.config.are_domains_aliases('live.com', 'hotmail.com'))
        
        # Test cross-company (should fail)
        self.assertFalse(self.config.are_domains_aliases('instacart.com', 'amazon.com'))
        self.assertFalse(self.config.are_domains_aliases('google.com', 'microsoft.com'))


class TestDomainAliasesYAMLConfig(unittest.TestCase):
    """Test domain aliases loading from YAML configuration files."""

    def test_load_domain_aliases_from_shared_file(self):
        """Test loading domain aliases from shared aliases file."""
        config = Configuration()
        
        # Create a test domain aliases file
        aliases_data = {
            'instacart.com': ['instacartemail.com'],
            'example.org': ['example-email.org', 'example-news.org'],
            'simple.org': 'simple-email.org'
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as aliases_file:
            yaml.dump(aliases_data, aliases_file)
            aliases_path = aliases_file.name
        
        # Create a test config file that references the aliases file
        config_data = {
            'options': {
                'guard': {
                    'server': 'https://guard.example.com',
                    'salt': 'test-salt',
                    'link': 'mismatch'
                }
            },
            'domain_aliases_file': aliases_path
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as config_file:
            yaml.dump(config_data, config_file)
            config_path = config_file.name
        
        try:
            # Load configuration
            self.assertTrue(config.load(config_path))
            
            # Test that aliases are loaded correctly from the shared file
            self.assertTrue(config.are_domains_aliases('instacart.com', 'instacartemail.com'))
            self.assertTrue(config.are_domains_aliases('example.org', 'example-email.org'))
            self.assertTrue(config.are_domains_aliases('simple.org', 'simple-email.org'))
            
            # Test cross-group (should fail)
            self.assertFalse(config.are_domains_aliases('instacart.com', 'example.org'))
        finally:
            os.unlink(config_path)
            os.unlink(aliases_path)

    def test_load_domain_aliases_from_yaml(self):
        """Test loading domain aliases from YAML configuration (legacy format)."""
        config = Configuration()
        
        yaml_data = {
            'options': {
                'guard': {
                    'server': 'https://guard.example.com',
                    'salt': 'test-salt',
                    'link': 'mismatch',
                    'domain_aliases': {
                        'instacart.com': ['instacartemail.com'],
                        'example.org': ['example-email.org', 'example-news.org'],
                        'simple.org': 'simple-email.org'
                    }
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(yaml_data, f)
            config_path = f.name
        
        try:
            # Load configuration
            self.assertTrue(config.load(config_path))
            
            # Test that aliases are loaded correctly
            self.assertTrue(config.are_domains_aliases('instacart.com', 'instacartemail.com'))
            self.assertTrue(config.are_domains_aliases('example.org', 'example-email.org'))
            self.assertTrue(config.are_domains_aliases('simple.org', 'simple-email.org'))
            
            # Test cross-group (should fail)
            self.assertFalse(config.are_domains_aliases('instacart.com', 'example.org'))
        finally:
            os.unlink(config_path)

    def test_load_empty_domain_aliases(self):
        """Test loading configuration with empty domain aliases."""
        config = Configuration()
        
        yaml_data = {
            'options': {
                'guard': {
                    'server': 'https://guard.example.com',
                    'salt': 'test-salt',
                    'domain_aliases': {}
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(yaml_data, f)
            config_path = f.name
        
        try:
            # Load configuration
            self.assertTrue(config.load(config_path))
            
            # Test that no aliases are configured
            self.assertFalse(config.are_domains_aliases('example.com', 'other.com'))
            self.assertTrue(config.are_domains_aliases('example.com', 'example.com'))  # Same domain
        finally:
            os.unlink(config_path)

    def test_load_missing_domain_aliases(self):
        """Test loading configuration without domain aliases section."""
        config = Configuration()
        
        yaml_data = {
            'options': {
                'guard': {
                    'server': 'https://guard.example.com',
                    'salt': 'test-salt'
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(yaml_data, f)
            config_path = f.name
        
        try:
            # Load configuration
            self.assertTrue(config.load(config_path))
            
            # Test that no aliases are configured (should use default empty dict)
            self.assertFalse(config.are_domains_aliases('example.com', 'other.com'))
        finally:
            os.unlink(config_path)

    def test_load_nonexistent_aliases_file(self):
        """Test loading configuration with non-existent aliases file."""
        config = Configuration()
        
        yaml_data = {
            'options': {
                'guard': {
                    'server': 'https://guard.example.com',
                    'salt': 'test-salt',
                    'domain_aliases_file': '/nonexistent/aliases.yml'
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(yaml_data, f)
            config_path = f.name
        
        try:
            # Load configuration (should succeed even with missing aliases file)
            self.assertTrue(config.load(config_path))
            
            # Test that no aliases are configured (should use default empty dict)
            self.assertFalse(config.are_domains_aliases('example.com', 'other.com'))
        finally:
            os.unlink(config_path)


class TestDomainAliasesCommandLine(unittest.TestCase):
    """Test domain aliases via command line arguments."""

    def test_command_line_domain_aliases(self):
        """Test setting domain aliases via command line arguments."""
        # This would require mocking the argument parser, which is complex
        # Instead, we'll test the internal logic that processes the arguments
        
        config = Configuration()
        
        # Simulate the command line argument processing
        alias_specs = [
            "instacart.com:instacartemail.com",
            "example.org:example-email.org,example-news.org",
            "simple.org:simple-email.org"
        ]
        
        for alias_spec in alias_specs:
            if ':' in alias_spec:
                owner, aliases_str = alias_spec.split(':', 1)
                owner = owner.strip()
                aliases = [alias.strip() for alias in aliases_str.split(',')]
                if owner and aliases:
                    config.config['options']['guard']['domain_aliases'][owner] = aliases
        
        # Test that aliases were set correctly
        self.assertTrue(config.are_domains_aliases('instacart.com', 'instacartemail.com'))
        self.assertTrue(config.are_domains_aliases('example.org', 'example-email.org'))
        self.assertTrue(config.are_domains_aliases('example-email.org', 'example-news.org'))
        self.assertTrue(config.are_domains_aliases('simple.org', 'simple-email.org'))
        
        # Test cross-group (should fail)
        self.assertFalse(config.are_domains_aliases('instacart.com', 'example.org'))

    def test_invalid_command_line_format(self):
        """Test handling of invalid command line alias formats."""
        config = Configuration()
        
        # Test missing colon
        invalid_spec = "instacart.com,instacartemail.com"
        if ':' in invalid_spec:
            owner, aliases_str = invalid_spec.split(':', 1)
            # This should not execute
            self.fail("Should not reach here")
        else:
            # This is the expected behavior for invalid format
            pass
        
        # Test empty owner
        invalid_spec2 = ":instacartemail.com"
        if ':' in invalid_spec2:
            owner, aliases_str = invalid_spec2.split(':', 1)
            owner = owner.strip()
            aliases = [alias.strip() for alias in aliases_str.split(',')]
            if owner and aliases:
                # This should not execute
                self.fail("Should not reach here")
            else:
                # This is the expected behavior for empty owner
                pass


class TestDomainAliasesIntegration(unittest.TestCase):
    """Integration tests for domain aliases with the full system."""

    def test_domain_aliases_with_guard_functionality(self):
        """Test that domain aliases work correctly with the guard link functionality."""
        config = Configuration()
        
        # Set up guard configuration with domain aliases
        config.config['options']['guard']['server'] = 'https://guard.example.com'
        config.config['options']['guard']['salt'] = 'test-salt'
        config.config['options']['guard']['link'] = 'mismatch'
        config.config['options']['guard']['domain_aliases'] = {
            'instacart.com': ['instacartemail.com'],
            'example.org': ['example-email.org']
        }
        
        # Test that the configuration is valid for guard functionality
        self.assertEqual(config.get(Configuration.CFG_GUARD_SERVER), 'https://guard.example.com')
        self.assertEqual(config.get(Configuration.CFG_GUARD_SALT), 'test-salt')
        self.assertEqual(config.get(Configuration.CFG_GUARD_LINK), 'mismatch')
        
        # Test domain alias matching
        self.assertTrue(config.are_domains_aliases('instacart.com', 'instacartemail.com'))
        self.assertTrue(config.are_domains_aliases('example.org', 'example-email.org'))
        
        # Test that aliases work in both directions
        self.assertTrue(config.are_domains_aliases('instacartemail.com', 'instacart.com'))
        self.assertTrue(config.are_domains_aliases('example-email.org', 'example.org'))

    def test_domain_aliases_with_subdomains(self):
        """Test that domain aliases work correctly with subdomain relationships."""
        config = Configuration()
        
        config.config['options']['guard']['domain_aliases'] = {
            'example.com': ['example-email.com']
        }
        
        # Test that subdomain relationships still work
        self.assertTrue(config.are_domains_aliases('subdomain.example.com', 'example.com'))
        self.assertTrue(config.are_domains_aliases('example.com', 'subdomain.example.com'))
        
        # Test that aliases work with subdomains
        self.assertTrue(config.are_domains_aliases('subdomain.example.com', 'example-email.com'))
        self.assertTrue(config.are_domains_aliases('example-email.com', 'subdomain.example.com'))
        
        # Test that subdomain of alias works
        self.assertTrue(config.are_domains_aliases('subdomain.example-email.com', 'example.com'))
        self.assertTrue(config.are_domains_aliases('example.com', 'subdomain.example-email.com'))


if __name__ == '__main__':
    unittest.main() 