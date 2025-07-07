#!/usr/bin/env python3
"""Unit tests for the YAML configuration system in detrackify_guard.py."""

import os
import sys
import tempfile
import unittest
import yaml

# Add the parent directory to the path so we can import detrackify_guard
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detrackify_guard import load_config_from_yaml, GuardConfig


class TestLoadConfigFromYaml(unittest.TestCase):
    """Test the load_config_from_yaml function."""

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
            loaded_config = load_config_from_yaml(config_path)
            self.assertEqual(loaded_config, config_data)
        finally:
            os.unlink(config_path)

    def test_load_invalid_yaml(self):
        """Test loading invalid YAML raises an exception."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("invalid: yaml: content: [")
            config_path = f.name
        
        try:
            with self.assertRaises(yaml.YAMLError):
                load_config_from_yaml(config_path)
        finally:
            os.unlink(config_path)

    def test_load_missing_file(self):
        """Test loading a non-existent file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            load_config_from_yaml('/nonexistent/file.yml')

    def test_load_empty_file(self):
        """Test loading an empty YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("")
            config_path = f.name
        
        try:
            with self.assertRaises(ValueError):
                load_config_from_yaml(config_path)
        finally:
            os.unlink(config_path)

    def test_load_non_dict_yaml(self):
        """Test loading YAML that doesn't contain a dictionary."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("- item1\n- item2")
            config_path = f.name
        
        try:
            with self.assertRaises(ValueError):
                load_config_from_yaml(config_path)
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
            loaded_config = load_config_from_yaml(config_path)
            self.assertEqual(loaded_config, config_data)
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
            loaded_config = load_config_from_yaml(config_path)
            self.assertEqual(loaded_config['strip_param_prefix'], ['utm_', 'fbclid', 'gclid'])
        finally:
            os.unlink(config_path)

    def test_boolean_values_in_yaml(self):
        """Test that boolean values are loaded correctly from YAML."""
        config_data = {
            'guardsalt': 'test-salt',
            'privacy': True,
            'debug': False
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            loaded_config = load_config_from_yaml(config_path)
            self.assertTrue(loaded_config['privacy'])
            self.assertFalse(loaded_config['debug'])
        finally:
            os.unlink(config_path)


if __name__ == '__main__':
    unittest.main() 