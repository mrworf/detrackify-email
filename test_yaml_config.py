#!/usr/bin/env python3
"""Test script for YAML configuration loading."""

import sys
import os
import tempfile
import yaml

# Add the current directory to the path so we can import detrackify_guard
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detrackify_guard import load_config_from_yaml


def test_yaml_config():
    """Test YAML configuration loading."""
    
    # Test configuration
    test_config = {
        'guardsalt': 'test-salt-123',
        'listen_ip': '0.0.0.0',
        'listen_port': 8080,
        'timeout': 3,
        'privacy': True,
        'resolve': 'head',
        'strip_param_prefix': ['utm_', 'fbclid'],
        'debug': True
    }
    
    # Create temporary YAML file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(test_config, f)
        config_path = f.name
    
    try:
        # Test loading configuration
        loaded_config = load_config_from_yaml(config_path)
        
        # Verify all values are loaded correctly
        assert loaded_config['guardsalt'] == 'test-salt-123'
        assert loaded_config['listen_ip'] == '0.0.0.0'
        assert loaded_config['listen_port'] == 8080
        assert loaded_config['timeout'] == 3
        assert loaded_config['privacy'] is True
        assert loaded_config['resolve'] == 'head'
        assert loaded_config['strip_param_prefix'] == ['utm_', 'fbclid']
        assert loaded_config['debug'] is True
        
        print("✅ YAML configuration loading test passed!")
        return True
        
    except Exception as e:
        print(f"❌ YAML configuration loading test failed: {e}")
        return False
    finally:
        # Clean up temporary file
        os.unlink(config_path)


def test_invalid_yaml():
    """Test handling of invalid YAML."""
    
    # Create temporary file with invalid YAML
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write("invalid: yaml: content: [")
        config_path = f.name
    
    try:
        # Test loading invalid configuration
        try:
            load_config_from_yaml(config_path)
            print("❌ Invalid YAML test failed - should have raised an exception")
            return False
        except yaml.YAMLError:
            print("✅ Invalid YAML handling test passed!")
            return True
        
    finally:
        # Clean up temporary file
        os.unlink(config_path)


def test_missing_file():
    """Test handling of missing configuration file."""
    
    try:
        load_config_from_yaml('/nonexistent/file.yml')
        print("❌ Missing file test failed - should have raised an exception")
        return False
    except FileNotFoundError:
        print("✅ Missing file handling test passed!")
        return True


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
        if test():
            passed += 1
    
    print(f"\nTest results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        sys.exit(0)
    else:
        print("💥 Some tests failed!")
        sys.exit(1) 