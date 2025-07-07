#!/usr/bin/env python3
"""Unit tests for the YAML configuration system in detrackify_guard.py."""

import os
import sys
import tempfile
import unittest
import yaml

# Add the parent directory to the path so we can import detrackify_guard
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from guard.config import GuardConfig


class TestLoadConfigFromYaml(unittest.TestCase):
    """Test the GuardConfig.from_yaml method."""

    def test_load_valid_config(self):
        """Test loading a valid YAML configuration."""
        config_data = {
            'guardsalt': 'test-salt-123',
            'listen_ip': '0.0.0.0',
            'listen_port': 8080,
            'timeout': 3,
            'privacy': True,
            'resolve': 'head',
            'strip_param_prefix': ['utm_', 'fbclid']
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            config = GuardConfig.from_yaml(config_path)
            self.assertEqual(config.salt, 'test-salt-123')
            self.assertEqual(config.listen_ip, '0.0.0.0')
            self.assertEqual(config.listen_port, 8080)
            self.assertEqual(config.timeout, 3)
            self.assertTrue(config.privacy)
            self.assertEqual(config.resolve, 'head')
            self.assertEqual(config.strip_param_prefixes, ['utm_', 'fbclid'])
        finally:
            os.unlink(config_path)

    def test_load_invalid_yaml(self):
        """Test loading invalid YAML raises an exception."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("invalid: yaml: content: [")
            config_path = f.name
        
        try:
            with self.assertRaises(yaml.YAMLError):
                GuardConfig.from_yaml(config_path)
        finally:
            os.unlink(config_path)

    def test_load_missing_file(self):
        """Test loading a non-existent file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            GuardConfig.from_yaml('/nonexistent/file.yml')

    def test_load_empty_file(self):
        """Test loading an empty YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("")
            config_path = f.name
        
        try:
            with self.assertRaises(ValueError):
                GuardConfig.from_yaml(config_path)
        finally:
            os.unlink(config_path)

    def test_load_non_dict_yaml(self):
        """Test loading YAML that doesn't contain a dictionary."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("- item1\n- item2")
            config_path = f.name
        
        try:
            with self.assertRaises(ValueError):
                GuardConfig.from_yaml(config_path)
        finally:
            os.unlink(config_path)

    def test_load_complex_config(self):
        """Test loading a complex configuration with all options."""
        config_data = {
            'guardsalt': 'complex-salt-456',
            'listen_ip': '127.0.0.1',
            'listen_port': 9090,
            'template_dir': 'custom_templates',
            'resources_dir': 'custom_resources',
            'timeout': 10,
            'privacy': False,
            'resolve': 'get',
            'resolve_cache_file': '/var/cache/resolve.json',
            'resolve_cache_days': 60,
            'resolve_cache_max': 8192,
            'strip_param_prefix': ['utm_', 'fbclid', 'gclid', 'msclkid'],
            'user_agent': 'Custom User Agent String'
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            config = GuardConfig.from_yaml(config_path)
            self.assertEqual(config.salt, 'complex-salt-456')
            self.assertEqual(config.listen_ip, '127.0.0.1')
            self.assertEqual(config.listen_port, 9090)
            self.assertEqual(config.template_dir, 'custom_templates')
            self.assertEqual(config.resource_dir, 'custom_resources')
            self.assertEqual(config.timeout, 10)
            self.assertFalse(config.privacy)
            self.assertEqual(config.resolve, 'get')
            self.assertEqual(config.cache_file, '/var/cache/resolve.json')
            self.assertEqual(config.cache_days, 60)
            self.assertEqual(config.cache_max, 8192)
            self.assertEqual(config.strip_param_prefixes, ['utm_', 'fbclid', 'gclid', 'msclkid'])
            self.assertEqual(config.user_agent, 'Custom User Agent String')
        finally:
            os.unlink(config_path)


class TestGuardConfig(unittest.TestCase):
    """Test the GuardConfig dataclass."""

    def test_guard_config_defaults(self):
        """Test GuardConfig with default values."""
        config = GuardConfig(salt='test-salt')
        
        self.assertEqual(config.salt, 'test-salt')
        self.assertEqual(config.timeout, 5)
        self.assertEqual(config.template_dir, 'templates')
        self.assertEqual(config.resource_dir, 'resources')
        self.assertFalse(config.privacy)
        self.assertIsNone(config.resolve)
        self.assertIsNone(config.cache_file)
        self.assertEqual(config.cache_days, 30)
        self.assertEqual(config.cache_max, 4096)
        self.assertEqual(config.strip_param_prefixes, [])
        self.assertIsNone(config.force_language)

    def test_guard_config_custom_values(self):
        """Test GuardConfig with custom values."""
        config = GuardConfig(
            salt='custom-salt',
            timeout=10,
            template_dir='custom_templates',
            resource_dir='custom_resources',
            privacy=True,
            resolve='head',
            cache_file='/tmp/cache.json',
            cache_days=60,
            cache_max=8192,
            strip_param_prefixes=['utm_', 'fbclid'],
            user_agent='Custom Agent',
            force_language='de'
        )
        
        self.assertEqual(config.salt, 'custom-salt')
        self.assertEqual(config.timeout, 10)
        self.assertEqual(config.template_dir, 'custom_templates')
        self.assertEqual(config.resource_dir, 'custom_resources')
        self.assertTrue(config.privacy)
        self.assertEqual(config.resolve, 'head')
        self.assertEqual(config.cache_file, '/tmp/cache.json')
        self.assertEqual(config.cache_days, 60)
        self.assertEqual(config.cache_max, 8192)
        self.assertEqual(config.strip_param_prefixes, ['utm_', 'fbclid'])
        self.assertEqual(config.user_agent, 'Custom Agent')
        self.assertEqual(config.force_language, 'de')


class TestConfigEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""

    def test_strip_param_prefix_list_handling(self):
        """Test that strip_param_prefix is handled correctly as a list."""
        config_data = {
            'guardsalt': 'test-salt',
            'strip_param_prefix': ['utm_', 'fbclid', 'gclid']
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            config = GuardConfig.from_yaml(config_path)
            self.assertEqual(config.strip_param_prefixes, ['utm_', 'fbclid', 'gclid'])
        finally:
            os.unlink(config_path)

    def test_boolean_values_in_yaml(self):
        """Test that boolean values are loaded correctly from YAML."""
        config_data = {
            'guardsalt': 'test-salt',
            'privacy': True
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            config = GuardConfig.from_yaml(config_path)
            self.assertTrue(config.privacy)
        finally:
            os.unlink(config_path)


if __name__ == '__main__':
    unittest.main() 