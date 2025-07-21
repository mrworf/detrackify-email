#!/usr/bin/env python3
"""Test script for unified YAML configuration loading."""

import sys
import os
import tempfile
import yaml
import pytest

# Add the current directory to the path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detrackify_email.configuration import Configuration
from guard.config import GuardConfig


def test_unified_config_email_section():
    """
    Test loading email configuration from unified YAML file.
    
    Expected outcome: Email configuration should correctly extract settings from
    the 'email' section while also loading shared settings from root level.
    """
    
    # Test unified configuration with new flattened structure
    test_config = {
        'domain_aliases_file': 'shared_aliases.yml',
        'blacklist_file': 'shared_blacklist.yml',
        'email': {
            'verbose': True,
            'guard': {
                'server': 'http://localhost:9090',
                'salt': 'test-salt-123'
            },
            'cache_file': 'email_cache.yml'
        },
        'guard': {
            'salt': 'guard-salt-456',
            'listen_port': 8080
        }
    }
    
    # Create temporary YAML file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(test_config, f)
        config_path = f.name
    
    try:
        # Test loading email configuration
        config = Configuration()
        success = config.load_from_yaml(config_path)
        
        assert success is True
        assert config.get('domain_aliases_file') == 'shared_aliases.yml'
        assert config.get('blacklist_file') == 'shared_blacklist.yml'
        assert config.get('cache_file') == 'email_cache.yml'
        assert config.get('guard.server') == 'http://localhost:9090'
        assert config.get('guard.salt') == 'test-salt-123'
        assert config.get('verbose') is True
        
        print("✅ Unified email configuration loading test passed!")
        
    except Exception as e:
        print(f"❌ Unified email configuration loading test failed: {e}")
        raise
    finally:
        # Clean up temporary file
        os.unlink(config_path)


def test_unified_config_guard_section():
    """
    Test loading guard configuration from unified YAML file.
    
    Expected outcome: Guard configuration should correctly extract settings from
    the 'guard' section while also loading shared settings from root level.
    """
    
    # Test unified configuration
    test_config = {
        'salt': 'shared-salt-123',
        'domain_aliases_file': 'shared_aliases.yml',
        'blacklist_file': 'shared_blacklist.yml',
        'email': {
            'guard': {
                'server': 'http://localhost:9090',
                'salt': 'email-salt-123'
            }
        },
        'guard': {
            'listen_ip': '0.0.0.0',
            'listen_port': 8080,
            'timeout': 3,
            'privacy': True
        }
    }
    
    # Create temporary YAML file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(test_config, f)
        config_path = f.name
    
    try:
        # Test loading guard configuration
        config = GuardConfig.from_yaml(config_path)
        
        # Verify guard section settings
        assert config.salt == 'shared-salt-123'  # Should use shared salt
        assert config.listen_ip == '0.0.0.0'
        assert config.listen_port == 8080
        assert config.timeout == 3
        assert config.privacy is True
        
        # Verify shared settings
        assert config.domain_aliases_file == 'shared_aliases.yml'
        assert config.blacklist_file == 'shared_blacklist.yml'
        
        print("✅ Unified guard configuration loading test passed!")
        
    except Exception as e:
        print(f"❌ Unified guard configuration loading test failed: {e}")
        raise
    finally:
        # Clean up temporary file
        os.unlink(config_path)


def test_unified_config_precedence():
    """
    Test that application-specific sections take precedence over shared settings.
    
    Expected outcome: Settings in email/guard sections should override
    corresponding settings in the shared section.
    """
    
    # Test configuration with conflicting settings
    test_config = {
        'salt': 'shared-salt-123',
        'domain_aliases_file': 'shared_aliases.yml',
        'blacklist_file': 'shared_blacklist.yml',
        'email': {
            'domain_aliases_file': 'email_aliases.yml',
            'guard': {
                'server': 'http://localhost:9090',
                'salt': 'email-salt-123'
            }
        },
        'guard': {
            'salt': 'guard-salt-456',
            'blacklist_file': 'guard_blacklist.yml',
            'listen_ip': '0.0.0.0',
            'listen_port': 8080
        }
    }
    
    # Create temporary YAML file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(test_config, f)
        config_path = f.name
    
    try:
        # Test email configuration precedence
        email_config = Configuration()
        email_success = email_config.load_from_yaml(config_path)
        
        assert email_success is True
        # Email should use its own domain_aliases_file, not shared
        assert email_config.get('domain_aliases_file') == 'email_aliases.yml'
        # Email should use shared blacklist_file since not overridden
        assert email_config.get('blacklist_file') == 'shared_blacklist.yml'
        # Email should use its own guard salt, not shared
        assert email_config.get('guard.salt') == 'email-salt-123'
        
        # Test guard configuration precedence
        guard_config = GuardConfig.from_yaml(config_path)
        
        # Guard should use its own salt, not shared
        assert guard_config.salt == 'guard-salt-456'
        # Guard should use its own blacklist_file, not shared
        assert guard_config.blacklist_file == 'guard_blacklist.yml'
        # Guard should use shared domain_aliases_file since not overridden
        assert guard_config.domain_aliases_file == 'shared_aliases.yml'
        
        print("✅ Unified configuration precedence test passed!")
        
    except Exception as e:
        print(f"❌ Unified configuration precedence test failed: {e}")
        raise
    finally:
        # Clean up temporary file
        os.unlink(config_path)


def test_unified_config_minimal():
    """
    Test loading configuration with minimal settings.
    
    Expected outcome: Both applications should work with minimal configuration
    and use appropriate defaults.
    """
    
    # Test minimal unified configuration
    test_config = {
        'salt': 'test-salt-123',
        'email': {
            'guard': {
                'server': 'http://localhost:9090',
                'link': 'mismatch'
            }
        },
        'guard': {
            'listen_ip': '127.0.0.1',
            'listen_port': 9090
        }
    }
    
    # Create temporary YAML file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(test_config, f)
        config_path = f.name
    
    try:
        # Test email configuration with minimal settings
        email_config = Configuration()
        email_success = email_config.load_from_yaml(config_path)
        
        assert email_success is True
        assert email_config.get('guard.server') == 'http://localhost:9090'
        assert email_config.get('guard.salt') == 'test-salt-123'  # Should use shared salt
        
        # Test guard configuration with minimal settings
        guard_config = GuardConfig.from_yaml(config_path)
        
        assert guard_config.salt == 'test-salt-123'  # Should use shared salt
        # Should use defaults for other settings
        assert guard_config.listen_ip == '127.0.0.1'
        assert guard_config.listen_port == 9090
        assert guard_config.timeout == 5
        
        print("✅ Unified configuration minimal test passed!")
        
    except Exception as e:
        print(f"❌ Unified configuration minimal test failed: {e}")
        raise
    finally:
        # Clean up temporary file
        os.unlink(config_path)


def test_shared_salt_functionality():
    """
    Test that shared salt is properly used by both applications.
    
    Expected outcome: Both email and guard should use the shared salt when
    no application-specific salt is provided.
    """
    
    # Test configuration with only shared salt
    test_config = {
        'salt': 'shared-salt-456',
        'domain_aliases_file': 'shared_aliases.yml',
        'email': {
            'guard': {
                'server': 'http://localhost:9090',
                'link': 'mismatch'
            }
        },
        'guard': {
            'listen_ip': '127.0.0.1',
            'listen_port': 9090
        }
    }
    
    # Create temporary YAML file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(test_config, f)
        config_path = f.name
    
    try:
        # Test email configuration uses shared salt
        email_config = Configuration()
        email_success = email_config.load_from_yaml(config_path)
        
        assert email_success is True
        assert email_config.get('guard.salt') == 'shared-salt-456'
        
        # Test guard configuration uses shared salt
        guard_config = GuardConfig.from_yaml(config_path)
        
        assert guard_config.salt == 'shared-salt-456'
        
        print("✅ Shared salt functionality test passed!")
        
    except Exception as e:
        print(f"❌ Shared salt functionality test failed: {e}")
        raise
    finally:
        # Clean up temporary file
        os.unlink(config_path)


if __name__ == '__main__':
    # Run all tests
    test_unified_config_email_section()
    test_unified_config_guard_section()
    test_unified_config_precedence()
    test_unified_config_minimal()
    test_shared_salt_functionality()
    print("\n🎉 All unified configuration tests passed!") 