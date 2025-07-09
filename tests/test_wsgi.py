#!/usr/bin/env python3
"""Test WSGI setup and configuration loading."""

import os
import pytest
from unittest.mock import patch


class TestWSGISetup:
    """Test WSGI application setup and configuration."""

    def test_wsgi_import_without_env(self):
        """Test that WSGI app can be imported without environment variables."""
        # Clear any existing GUARD_SALT
        if 'GUARD_SALT' in os.environ:
            del os.environ['GUARD_SALT']
        
        try:
            from wsgi import app
            # Should be None when GUARD_SALT is not set
            assert app is None
        except Exception as e:
            pytest.fail(f"Failed to import WSGI app: {e}")

    def test_config_from_env(self):
        """Test that configuration can be loaded from environment variables."""
        # Set test environment variables
        test_env = {
            'GUARD_SALT': 'test-salt-123',
            'TIMEOUT': '10',
            'PRIVACY': 'true',
            'RESOLVE': 'head',
            'STRIP_PARAM_PREFIX': 'utm_source,utm_medium',
            'USER_AGENT': 'Test User Agent',
        }
        
        with patch.dict(os.environ, test_env):
            from guard.config import GuardConfig
            config = GuardConfig.from_env()
            
            assert config.salt == 'test-salt-123'
            assert config.timeout == 10
            assert config.privacy is True
            assert config.resolve == 'head'
            assert 'utm_source' in config.strip_param_prefixes
            assert 'utm_medium' in config.strip_param_prefixes
            assert config.user_agent == 'Test User Agent'

    def test_app_creation_with_env(self):
        """Test that Flask app can be created with proper environment variables."""
        test_env = {
            'GUARD_SALT': 'test-salt-123',
            'TIMEOUT': '5',
            'LISTEN_IP': '127.0.0.1',
            'LISTEN_PORT': '9090',
        }
        
        with patch.dict(os.environ, test_env):
            from wsgi import create_app
            app = create_app()
            
            assert app is not None
            # Verify it's a Flask app
            assert hasattr(app, 'route')
            assert hasattr(app, 'add_url_rule')

    def test_app_creation_without_salt(self):
        """Test that app creation fails without GUARD_SALT."""
        # Clear any existing GUARD_SALT
        if 'GUARD_SALT' in os.environ:
            del os.environ['GUARD_SALT']
        
        from wsgi import create_app
        with pytest.raises(ValueError, match="Guard salt is required"):
            create_app()

    def test_wsgi_app_with_env(self):
        """Test that WSGI app is created when GUARD_SALT is set."""
        test_env = {
            'GUARD_SALT': 'test-salt-123',
            'TIMEOUT': '5',
        }
        
        with patch.dict(os.environ, test_env):
            # Re-import to get the app with environment set
            import importlib
            import wsgi
            importlib.reload(wsgi)
            
            assert wsgi.app is not None
            assert hasattr(wsgi.app, 'route')

    def test_environment_variable_parsing(self):
        """Test parsing of various environment variable types."""
        test_env = {
            'GUARD_SALT': 'test-salt',
            'TIMEOUT': '15',
            'PRIVACY': 'false',
            'RESOLVE_CACHE_DAYS': '60',
            'RESOLVE_CACHE_MAX': '8192',
            'DENY_ON_WARNINGS': 'ssl_certificate,connection_error',
        }
        
        with patch.dict(os.environ, test_env):
            from guard.config import GuardConfig
            config = GuardConfig.from_env()
            
            assert config.timeout == 15
            assert config.privacy is False
            assert config.cache_days == 60
            assert config.cache_max == 8192
            assert 'ssl_certificate' in config.deny_on_warnings
            assert 'connection_error' in config.deny_on_warnings

    def test_boolean_environment_variables(self):
        """Test boolean environment variable parsing."""
        test_cases = [
            ('true', True),
            ('1', True),
            ('yes', True),
            ('on', True),
            ('false', False),
            ('0', False),
            ('no', False),
            ('off', False),
            ('', False),
        ]
        
        for value, expected in test_cases:
            test_env = {
                'GUARD_SALT': 'test-salt',
                'PRIVACY': value,
            }
            
            with patch.dict(os.environ, test_env):
                from guard.config import GuardConfig
                config = GuardConfig.from_env()
                assert config.privacy is expected, f"Failed for value: {value}"

    def test_list_environment_variables(self):
        """Test list environment variable parsing."""
        test_cases = [
            ('utm_source,utm_medium', ['utm_source', 'utm_medium']),
            ('utm_source, utm_medium', ['utm_source', 'utm_medium']),
            ('utm_source', ['utm_source']),
            ('', []),
        ]
        
        for value, expected in test_cases:
            test_env = {
                'GUARD_SALT': 'test-salt',
                'STRIP_PARAM_PREFIX': value,
            }
            
            with patch.dict(os.environ, test_env):
                from guard.config import GuardConfig
                config = GuardConfig.from_env()
                assert config.strip_param_prefixes == expected, f"Failed for value: {value}" 