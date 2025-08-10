#!/usr/bin/env python3
"""Test script for YAML configuration loading."""

import sys
import os
import tempfile
import yaml
import pytest

# Add the current directory to the path so we can import detrackify_guard
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guard.config import GuardConfig


def test_yaml_config():
    """
    Test loading a valid YAML configuration file with various data types.
    
    Expected outcome: All configuration values should be parsed correctly from
    YAML format, maintaining proper data types (strings, integers, booleans, lists)
    and demonstrating successful YAML-to-Python conversion.
    """
    
    # Test configuration
    test_config = {
        'common': {
            'salt': 'test-salt-123',
            'strip_param_prefix': ['utm_', 'fbclid']
        },
        'guard_server': {
            'listen_ip': '0.0.0.0',
            'listen_port': 8080,
            'timeout': 3,
            'privacy': True,
            'resolve': 'head'
        }
    }
    
    # Create temporary YAML file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(test_config, f)
        config_path = f.name
    
    try:
        # Test loading configuration
        config = GuardConfig.from_yaml(config_path)
        
        # Verify all values are loaded correctly
        assert config.salt == 'test-salt-123'
        assert config.listen_ip == '0.0.0.0'
        assert config.listen_port == 8080
        assert config.timeout == 3
        assert config.privacy is True
        assert config.resolve == 'head'
        assert config.strip_param_prefixes == ['utm_', 'fbclid']
        
        print("✅ YAML configuration loading test passed!")
        
    except Exception as e:
        print(f"❌ YAML configuration loading test failed: {e}")
        raise
    finally:
        # Clean up temporary file
        os.unlink(config_path)


def test_invalid_yaml():
    """
    Test handling of syntactically invalid YAML content.
    
    Expected outcome: Function should raise yaml.YAMLError when attempting
    to parse malformed YAML syntax, providing clear error indication rather
    than silent failure or incorrect parsing.
    """
    
    # Create temporary file with invalid YAML
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write("invalid: yaml: content: [")
        config_path = f.name
    
    try:
        # Test loading invalid configuration
        try:
            GuardConfig.from_yaml(config_path)
            assert False, "Invalid YAML test failed - should have raised an exception"
        except yaml.YAMLError:
            print("✅ Invalid YAML handling test passed!")
        
    finally:
        # Clean up temporary file
        os.unlink(config_path)


def test_missing_file():
    """
    Test handling of non-existent configuration file paths.
    
    Expected outcome: Function should raise FileNotFoundError when attempting
    to load a configuration file that doesn't exist, providing clear error
    indication for missing configuration files.
    """
    
    try:
        GuardConfig.from_yaml('/nonexistent/file.yml')
        assert False, "Missing file test failed - should have raised an exception"
    except FileNotFoundError:
        print("✅ Missing file handling test passed!")


if __name__ == '__main__':
    print("Testing YAML configuration functionality...")
    
    tests = [
        test_yaml_config,
        test_invalid_yaml,
        test_missing_file
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed: {e}")
    
    print(f"\nTest results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        sys.exit(0)
    else:
        print("💥 Some tests failed!")
        sys.exit(1) 