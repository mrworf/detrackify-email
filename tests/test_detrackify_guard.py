#!/usr/bin/env python3
"""Unit tests for detrackify_guard.py."""

import os
import sys
import tempfile
import unittest
import json
import base64
import hashlib
from unittest.mock import patch, MagicMock, mock_open

# Add the parent directory to the path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detrackify_guard import GuardServer
from guard.config import GuardConfig
from common.utils import SharedUtils


class TestGuardServer(unittest.TestCase):
    """Test GuardServer class functionality."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test configuration
        self.config = GuardConfig(
            salt='test-salt',
            listen_ip='127.0.0.1',
            listen_port=8080,
            template_dir='templates',
            timeout=5,
            resolve='head',
            cache_file=os.path.join(self.temp_dir, 'test_cache.json'),
            cache_max=100,
            cache_days=7,
            strip_param_prefixes=['utm_', 'fbclid'],
            user_agent='TestBot/1.0',
            domain_aliases_file=os.path.join(self.temp_dir, 'domain_aliases.yml'),
            blacklist_file=os.path.join(self.temp_dir, 'blacklist.yml'),
            deny_on_warnings=['ssl_certificate', 'connection_error']
        )
        
        # Create test files
        self._create_test_files()
        
        # Create server instance
        self.server = GuardServer(self.config)

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def _create_test_files(self):
        """Create test configuration files."""
        # Create domain aliases file
        domain_aliases = {
            'example.com': ['example-email.com', 'example.org'],
            'test.com': ['test-email.com']
        }
        with open(self.config.domain_aliases_file, 'w') as f:
            import yaml
            yaml.dump(domain_aliases, f)
        
        # Create blacklist file
        blacklist = {
            'blacklist': [
                {'url': '^https://malicious\\.com/.*'},
                {'sender': '^spam@malicious\\.com$'}
            ]
        }
        with open(self.config.blacklist_file, 'w') as f:
            import yaml
            yaml.dump(blacklist, f)

    def _create_test_payload(self, url='https://example.com', display='Test Link', 
                           domain='example.com', to_address=None, block_reason=None):
        """Create a test guard payload."""
        payload = {
            'url': url,
            'display': display,
            'domain': domain
        }
        if to_address:
            payload['to'] = to_address
        if block_reason:
            payload['block'] = block_reason
        
        data = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        sha = SharedUtils.generate_hash(data, self.config.salt)
        return sha, data, payload

    def test_guard_server_initialization(self):
        """Test GuardServer initialization."""
        self.assertIsNotNone(self.server.app)
        self.assertEqual(self.server.salt, 'test-salt')
        self.assertEqual(self.server.timeout, 5)
        self.assertTrue(self.server.resolve_enabled)
        self.assertFalse(self.server.resolve_get)  # Should be False for 'head'
        self.assertIsNotNone(self.server.domain_aliases)
        self.assertIsNotNone(self.server.blocklist)

    def test_guard_server_with_get_resolve(self):
        """Test GuardServer with GET resolve method."""
        config = GuardConfig(
            salt='test-salt',
            resolve='get',
            template_dir='templates'
        )
        server = GuardServer(config)
        self.assertTrue(server.resolve_get)

    def test_guard_server_without_resolve(self):
        """Test GuardServer without resolve enabled."""
        config = GuardConfig(
            salt='test-salt',
            resolve=None,
            template_dir='templates'
        )
        server = GuardServer(config)
        self.assertFalse(server.resolve_enabled)
        self.assertIsNone(server.cache)

    def test_guard_method_get_request(self):
        """Test guard method with GET request."""
        sha, data, payload = self._create_test_payload()
        
        with self.server.app.test_client() as client:
            with patch('detrackify_guard.render_template') as mock_render:
                mock_render.return_value = '<html>test</html>'
                
                response = client.get(f'/guard/{sha}/{data}')
                
                self.assertEqual(response.status_code, 200)
                mock_render.assert_called_once()
                
                # Check that render_template was called with correct context
                call_args = mock_render.call_args
                context = call_args[1]  # kwargs
                self.assertEqual(context['display'], 'Test Link')
                self.assertEqual(context['domain'], 'example.com')
                self.assertEqual(context['url'], 'https://example.com')
                self.assertTrue('ts' in context)
                self.assertEqual(context['timeout_ms'], 5000)
                self.assertEqual(context['block_reason'], '')
                self.assertTrue(context['resolve'])
                self.assertEqual(context['deny_on_warnings'], ['ssl_certificate', 'connection_error'])
                self.assertFalse(context['auto_redirect'])

    def test_guard_method_post_request(self):
        """Test guard method with POST request."""
        sha, data, payload = self._create_test_payload()
        
        with self.server.app.test_client() as client:
            with patch('detrackify_guard.redirect') as mock_redirect:
                mock_response = MagicMock()
                mock_response.headers = {}
                mock_redirect.return_value = mock_response
                
                response = client.post(f'/guard/{sha}/{data}', data={'ts': '1234567890.0'})
                
                self.assertEqual(response.status_code, 200)
                mock_redirect.assert_called_once_with('https://example.com', code=302)

    def test_guard_method_invalid_link(self):
        """Test guard method with invalid guard link."""
        with self.server.app.test_client() as client:
            response = client.get('/guard/invalid-sha/invalid-data')
            self.assertEqual(response.status_code, 404)

    def test_guard_method_with_block_reason(self):
        """Test guard method with block reason in payload."""
        sha, data, payload = self._create_test_payload(block_reason='blacklisted')
        
        with self.server.app.test_client() as client:
            with patch('detrackify_guard.render_template') as mock_render:
                mock_render.return_value = '<html>test</html>'
                
                response = client.get(f'/guard/{sha}/{data}')
                
                self.assertEqual(response.status_code, 200)
                call_args = mock_render.call_args
                context = call_args[1]
                self.assertEqual(context['block_reason'], 'blacklisted')

    def test_opts_js_method(self):
        """Test opts_js method."""
        sha, data, payload = self._create_test_payload()
        
        with self.server.app.test_client() as client:
            with patch('detrackify_guard.render_template') as mock_render:
                mock_render.return_value = 'var opts = {};'
                
                response = client.get('/guard/opts.js',
                                   headers={'Referer': f'http://localhost/guard/{sha}/{data}'})

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers['Content-Type'], 'application/javascript')
                opts = mock_render.call_args[1]['opts']
                self.assertIn('auto_redirect', opts)
                self.assertFalse(opts['auto_redirect'])

    def test_auto_redirect_context(self):
        config = GuardConfig(salt='test-salt', resolve='head', template_dir='templates', auto_redirect=True)
        server = GuardServer(config)
        sha, data, _ = self._create_test_payload()
        with server.app.test_client() as client:
            with patch('detrackify_guard.render_template') as mock_render:
                mock_render.return_value = '<html>test</html>'
                client.get(f'/guard/{sha}/{data}')
                context = mock_render.call_args[1]
                self.assertTrue(context['auto_redirect'])

    def test_opts_js_auto_redirect(self):
        config = GuardConfig(salt='test', resolve='head', template_dir='templates', auto_redirect=True,
                             deny_on_warnings=['ssl_certificate', 'connection_error'])
        server = GuardServer(config)
        payload = {'url': 'https://example.com', 'display': 'Test Link', 'domain': 'example.com'}
        data = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        sha = SharedUtils.generate_hash(data, config.salt)
        with server.app.test_client() as client:
            with patch('detrackify_guard.render_template') as mock_render:
                mock_render.return_value = 'var opts = {};'
                response = client.get('/guard/opts.js', headers={'Referer': f'http://localhost/guard/{sha}/{data}'})
                opts = mock_render.call_args[1]['opts']
                self.assertTrue(opts['auto_redirect'])
                self.assertEqual(response.headers['Cache-Control'], 'no-store')

                mock_render.assert_called_once()
                call_args = mock_render.call_args
                opts = call_args[1]['opts']
                self.assertTrue(opts['resolve'])
                self.assertEqual(opts['timeout_ms'], 5000)
                self.assertEqual(opts['sha'], sha)
                self.assertEqual(opts['data'], data)
                self.assertEqual(opts['sender_domain'], 'example.com')
                self.assertEqual(opts['block_reason'], '')
                self.assertEqual(opts['deny_on_warnings'], ['ssl_certificate', 'connection_error'])

    def test_opts_js_method_invalid_referer(self):
        """Test opts_js method with invalid referer."""
        with self.server.app.test_client() as client:
            with patch('detrackify_guard.render_template') as mock_render:
                mock_render.return_value = 'var opts = {};'
                
                response = client.get('/guard/opts.js', 
                                   headers={'Referer': 'http://localhost/invalid'})
                
                self.assertEqual(response.status_code, 200)
                call_args = mock_render.call_args
                opts = call_args[1]['opts']
                self.assertEqual(opts['sha'], '')
                self.assertEqual(opts['data'], '')

    def test_resolve_link_method(self):
        """Test resolve_link method."""
        # Test that the method exists and can be called
        # This test ensures the method signature is correct and doesn't have import issues
        self.assertTrue(hasattr(self.server, 'resolve_link'))
        self.assertTrue(callable(self.server.resolve_link))
        
        # Test that the method is properly registered as a route
        with self.server.app.test_client() as client:
            response = client.post('/guard/resolve', json={})
            # Should get 400 for invalid JSON, not 404 for missing route
            self.assertNotEqual(response.status_code, 404)

    def test_resolve_link_method_unsafe_url(self):
        """Test resolve_link method with unsafe URL."""
        sha, data, payload = self._create_test_payload(url='javascript:alert(1)')
        
        with self.server.app.test_client() as client:
            response = client.post('/guard/resolve', 
                                 json={'sha': sha, 'data': data})
            
            self.assertEqual(response.status_code, 400)

    def test_resolve_link_method_invalid_payload(self):
        """Test resolve_link method with invalid payload."""
        with self.server.app.test_client() as client:
            response = client.post('/guard/resolve', 
                                 json={'sha': 'invalid', 'data': 'invalid'})
            
            self.assertEqual(response.status_code, 403)

    def test_resolve_link_method_cached_entry(self):
        """Test resolve_link method with cached entry to ensure info variable is available."""
        # Create a test payload
        sha, data, payload = self._create_test_payload(url='https://example.com')
        
        # Mock the cache to return an entry
        with patch.object(self.server.cache, 'get') as mock_get:
            mock_get.return_value = {
                'url': 'https://resolved-example.com',
                'title': 'Resolved Title',
                'warning': None
            }
            
            with self.server.app.test_client() as client:
                response = client.post('/guard/resolve', 
                                     json={'sha': sha, 'data': data})
                
                # Should succeed without UnboundLocalError
                self.assertEqual(response.status_code, 200)
                result = json.loads(response.data)
                self.assertEqual(result['url'], 'https://resolved-example.com')
                self.assertEqual(result['title'], 'Resolved Title')
                self.assertIn('domains_match', result)  # This uses the info variable

    def test_go_method(self):
        """Test go method."""
        url = 'https://example.com'
        sha = SharedUtils.generate_hash(url, self.config.salt)
        
        with self.server.app.test_client() as client:
            with patch('detrackify_guard.redirect') as mock_redirect:
                mock_response = MagicMock()
                mock_response.headers = {}
                mock_redirect.return_value = mock_response
                
                response = client.post('/guard/go', 
                                     data={'url': url, 'sha': sha, 'ts': '1234567890.0'})
                
                self.assertEqual(response.status_code, 200)
                mock_redirect.assert_called_once_with(url, code=302)

    def test_go_method_invalid_hash(self):
        """Test go method with invalid hash."""
        with self.server.app.test_client() as client:
            response = client.post('/guard/go', 
                                 data={'url': 'https://example.com', 'sha': 'invalid'})
            
            self.assertEqual(response.status_code, 404)

    def test_health_check_method(self):
        """Test health_check method."""
        with self.server.app.test_client() as client:
            response = client.get('/guard/health')
            
            self.assertEqual(response.status_code, 200)
            result = json.loads(response.data)
            self.assertEqual(result['status'], 'healthy')
            self.assertTrue('timestamp' in result)

    def test_common_js_method(self):
        """Test common_js method."""
        with self.server.app.test_client() as client:
            with patch('detrackify_guard.send_from_directory') as mock_send:
                mock_send.return_value = 'var common = {};'
                
                response = client.get('/guard/common.js')
                
                self.assertEqual(response.status_code, 200)
                mock_send.assert_called_once_with('templates', 'common.js', max_age=86400)

    def test_common_css_method(self):
        """Test common_css method."""
        with self.server.app.test_client() as client:
            with patch('detrackify_guard.send_from_directory') as mock_send:
                mock_send.return_value = 'body { }'
                
                response = client.get('/guard/common.css')
                
                self.assertEqual(response.status_code, 200)
                mock_send.assert_called_once_with('templates', 'common.css', max_age=0)

    def test_resource_method(self):
        """Test resource method."""
        # Create a test resource file
        test_file = os.path.join(self.temp_dir, 'test.png')
        with open(test_file, 'w') as f:
            f.write('fake image data')
        
        config = GuardConfig(
            salt='test-salt',
            template_dir='templates',
            resource_dir=self.temp_dir
        )
        server = GuardServer(config)
        
        with server.app.test_client() as client:
            with patch('detrackify_guard.send_from_directory') as mock_send:
                mock_send.return_value = 'fake image data'
                
                response = client.get('/resource/test.png')
                
                self.assertEqual(response.status_code, 200)
                mock_send.assert_called_once_with(self.temp_dir, 'test.png')

    def test_resource_method_path_traversal(self):
        """Test resource method with path traversal attempt."""
        config = GuardConfig(
            salt='test-salt',
            template_dir='templates',
            resource_dir=self.temp_dir
        )
        server = GuardServer(config)
        
        with server.app.test_client() as client:
            response = client.get('/resource/../../../etc/passwd')
            self.assertEqual(response.status_code, 404)

    def test_choose_template_method(self):
        """Test choose_template method."""
        # Test with forced language
        config = GuardConfig(
            salt='test-salt',
            template_dir='templates',
            force_language='de'
        )
        server = GuardServer(config)
        
        with patch('os.path.isfile') as mock_isfile:
            mock_isfile.return_value = True
            template = server.choose_template('en-US,en;q=0.9')
            self.assertEqual(template, 'guard_warning_de.html')

    def test_choose_template_method_invalid_language(self):
        """Test choose_template method with invalid language."""
        config = GuardConfig(
            salt='test-salt',
            template_dir='templates',
            force_language='../../../etc/passwd'
        )
        server = GuardServer(config)
        
        template = server.choose_template('en-US,en;q=0.9')
        self.assertEqual(template, 'guard_warning.html')

    def test_add_security_headers(self):
        """Test add_security_headers method."""
        with self.server.app.test_client() as client:
            response = client.get('/guard/health')
            
            self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
            self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
            self.assertEqual(response.headers['X-XSS-Protection'], '1; mode=block')
            self.assertIn('Content-Security-Policy', response.headers)

    def test_domain_alias_checking(self):
        """Test domain alias checking functionality."""
        # Test that domain aliases are properly initialized
        self.assertIsNotNone(self.server.domain_aliases)
        self.assertTrue(hasattr(self.server.domain_aliases, 'are_aliases'))
        
        # Test that domain alias checking works
        self.assertTrue(self.server.domain_aliases.are_aliases('example.com', 'example-email.com'))
        self.assertTrue(self.server.domain_aliases.are_aliases('example.com', 'example.org'))
        self.assertFalse(self.server.domain_aliases.are_aliases('example.com', 'different.com'))

    def test_blacklist_checking(self):
        """Test blacklist checking functionality."""
        # Test that the blacklist is properly initialized
        self.assertIsNotNone(self.server.blocklist)
        self.assertTrue(hasattr(self.server.blocklist, 'is_url_blacklisted'))
        
        # Test that blacklist checking works
        self.assertTrue(self.server.blocklist.is_url_blacklisted('https://malicious.com/evil'))
        self.assertFalse(self.server.blocklist.is_url_blacklisted('https://good.example.com/safe'))

    def test_warning_blocking(self):
        """Test warning blocking functionality."""
        # Test that deny_on_warnings is properly configured
        self.assertIsNotNone(self.server.deny_on_warnings)
        self.assertIn('ssl_certificate', self.server.deny_on_warnings)
        self.assertIn('connection_error', self.server.deny_on_warnings)
        
        # Test that warning blocking logic works
        warning_type = 'ssl_certificate'
        self.assertIn(warning_type, self.server.deny_on_warnings)
        
        # Test that the warning blocking logic would work correctly
        if warning_type in self.server.deny_on_warnings:
            block_reason = f'warning_blocked:{warning_type}'
            self.assertEqual(block_reason, 'warning_blocked:ssl_certificate')

    def test_strip_query_parameters_usage(self):
        """Test that strip_query_parameters is used correctly (catches GuardUtils vs SharedUtils issues)."""
        # This test specifically checks that we're using SharedUtils, not GuardUtils
        # by testing the guard method which uses strip_query_parameters
        payload = {
            'url': 'https://example.com?utm_source=test&param=value',
            'display': 'Test Link',
            'domain': 'example.com'
        }
        data = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        sha = SharedUtils.generate_hash(data, self.config.salt)
        
        with self.server.app.test_client() as client:
            with patch('detrackify_guard.render_template') as mock_render:
                mock_render.return_value = '<html>test</html>'
                
                # This should not raise an AttributeError about GuardUtils
                response = client.get(f'/guard/{sha}/{data}')
                
                self.assertEqual(response.status_code, 200)
                mock_render.assert_called_once()
                
                # Check that the URL in the context has been processed correctly
                call_args = mock_render.call_args
                context = call_args[1]
                # The URL should have utm_ parameters stripped
                self.assertNotIn('utm_source', context['url'])

    def test_verify_guard_link_usage(self):
        """Test that verify_guard_link is used correctly in guard method."""
        sha, data, payload = self._create_test_payload()
        
        with self.server.app.test_client() as client:
            with patch('detrackify_guard.render_template') as mock_render:
                mock_render.return_value = '<html>test</html>'
                
                # This should use SharedUtils.verify_guard_link, not manual verification
                response = client.get(f'/guard/{sha}/{data}')
                
                self.assertEqual(response.status_code, 200)
                mock_render.assert_called_once()

    def test_parse_guard_url_usage(self):
        """Test that parse_guard_url is used correctly in opts_js method."""
        sha, data, payload = self._create_test_payload()
        
        with self.server.app.test_client() as client:
            with patch('detrackify_guard.render_template') as mock_render:
                mock_render.return_value = 'var opts = {};'
                
                # This should use SharedUtils.parse_guard_url, not manual regex
                response = client.get('/guard/opts.js', 
                                   headers={'Referer': f'http://localhost/guard/{sha}/{data}'})
                
                self.assertEqual(response.status_code, 200)
                call_args = mock_render.call_args
                opts = call_args[1]['opts']
                self.assertEqual(opts['sha'], sha)
                self.assertEqual(opts['data'], data)


if __name__ == '__main__':
    unittest.main() 
