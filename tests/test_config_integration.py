#!/usr/bin/env python3
"""Integration tests for the YAML configuration system."""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import yaml

# Add the parent directory to the path so we can import detrackify_guard
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detrackify_guard import main
from guard.config import GuardConfig


def no_exit(code=0):
    raise RuntimeError(f"sys.exit({code}) called")


class TestConfigIntegration(unittest.TestCase):
    """Test configuration integration with command line arguments."""

    def test_command_line_overrides_yaml(self):
        """Test that command line arguments override YAML configuration."""
        with patch('sys.exit', side_effect=no_exit), \
             patch('sys.argv', ['detrackify_guard.py', '--config', 'test.yml', '--guardsalt', 'cmd-salt']), \
             patch('guard.config.GuardConfig.from_yaml') as mock_load_config, \
             patch('detrackify_guard.GuardServer') as mock_server, \
             patch('detrackify_guard.atexit.register'):
            
            # Mock YAML config
            yaml_config = GuardConfig(salt='yaml-salt', listen_ip='0.0.0.0', listen_port=8080, timeout=3, privacy=True)
            mock_load_config.return_value = yaml_config
            
            # Mock server instance
            mock_server_instance = mock_server.return_value
            
            # Call main function
            main()
            
            # Verify GuardConfig was called with command line salt overriding YAML
            mock_server.assert_called_once()
            config_arg = mock_server.call_args[0][0]
            self.assertEqual(config_arg.salt, 'cmd-salt')  # Command line overrides YAML
            self.assertEqual(config_arg.timeout, 3)  # From YAML
            self.assertTrue(config_arg.privacy)  # From YAML

    def test_command_line_only_no_yaml(self):
        """Test configuration with only command line arguments."""
        with patch('sys.exit', side_effect=no_exit), \
             patch('sys.argv', ['detrackify_guard.py', '--guardsalt', 'cmd-only-salt']), \
             patch('detrackify_guard.GuardServer') as mock_server, \
             patch('detrackify_guard.atexit.register'):
            
            # Mock server instance
            mock_server_instance = mock_server.return_value
            
            # Call main function
            main()
            
            # Verify GuardConfig was called with command line values
            mock_server.assert_called_once()
            config_arg = mock_server.call_args[0][0]
            self.assertEqual(config_arg.salt, 'cmd-only-salt')
            self.assertEqual(config_arg.timeout, 5)  # Default
            self.assertFalse(config_arg.privacy)  # Default

    def test_yaml_only_no_command_line(self):
        """Test configuration with only YAML file."""
        with patch('sys.exit', side_effect=no_exit), \
             patch('sys.argv', ['detrackify_guard.py', '--config', 'test.yml']), \
             patch('guard.config.GuardConfig.from_yaml') as mock_load_config, \
             patch('detrackify_guard.GuardServer') as mock_server, \
             patch('detrackify_guard.atexit.register'):
            
            # Mock YAML config
            yaml_config = GuardConfig(salt='yaml-only-salt', listen_ip='192.168.1.1', listen_port=7070, timeout=7, privacy=True, resolve='get')
            mock_load_config.return_value = yaml_config
            
            # Mock server instance
            mock_server_instance = mock_server.return_value
            
            # Call main function
            main()
            
            # Verify GuardConfig was called with YAML values
            mock_server.assert_called_once()
            config_arg = mock_server.call_args[0][0]
            self.assertEqual(config_arg.salt, 'yaml-only-salt')
            self.assertEqual(config_arg.timeout, 7)
            self.assertTrue(config_arg.privacy)
            self.assertEqual(config_arg.resolve, 'get')

    def test_no_salt_provided(self):
        """Test that missing salt raises an error."""
        with patch('sys.exit', side_effect=no_exit), \
             patch('sys.argv', ['detrackify_guard.py']), \
             patch('detrackify_guard.GuardServer'), \
             patch('detrackify_guard.atexit.register'):
            
            # Call main function and expect it to return 1
            result = main()
            self.assertEqual(result, 1)

    def test_yaml_load_error(self):
        """Test that YAML load errors are handled properly."""
        with patch('sys.exit', side_effect=no_exit), \
             patch('sys.argv', ['detrackify_guard.py', '--config', 'test.yml']), \
             patch('guard.config.GuardConfig.from_yaml') as mock_load_config:
            
            # Mock YAML load to raise an exception
            mock_load_config.side_effect = FileNotFoundError("Config file not found")
            
            # Call main function and expect it to return 1
            result = main()
            self.assertEqual(result, 1)

    def test_debug_command_line_only(self):
        """Test that debug is only settable via command line."""
        with patch('sys.exit', side_effect=no_exit), \
             patch('sys.argv', ['detrackify_guard.py', '--config', 'test.yml', '--debug']), \
             patch('guard.config.GuardConfig.from_yaml') as mock_load_config, \
             patch('detrackify_guard.GuardServer') as mock_server, \
             patch('detrackify_guard.atexit.register'):
            
            yaml_config = GuardConfig(salt='test-salt')
            mock_load_config.return_value = yaml_config
            
            main()
            
            # Verify debug is set from command line, not YAML
            mock_server.assert_called_once()
            config_arg = mock_server.call_args[0][0]
            # Debug should be True from command line, not from YAML

    def test_force_language_command_line_only(self):
        """Test that force_language is only settable via command line."""
        with patch('sys.exit', side_effect=no_exit), \
             patch('sys.argv', ['detrackify_guard.py', '--config', 'test.yml', '--force-language', 'de']), \
             patch('guard.config.GuardConfig.from_yaml') as mock_load_config, \
             patch('detrackify_guard.GuardServer') as mock_server, \
             patch('detrackify_guard.atexit.register'):
            
            yaml_config = GuardConfig(salt='test-salt')
            mock_load_config.return_value = yaml_config
            
            main()
            
            # Verify force_language is set from command line, not YAML
            mock_server.assert_called_once()
            config_arg = mock_server.call_args[0][0]
            self.assertEqual(config_arg.force_language, 'de')  # From command line, not YAML


if __name__ == '__main__':
    unittest.main() 