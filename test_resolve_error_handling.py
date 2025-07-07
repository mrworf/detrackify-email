#!/usr/bin/env python3
"""Test resolve error handling."""

import unittest
from unittest.mock import Mock, patch, MagicMock
import requests
from detrackify_guard import GuardServer
from guard.config import GuardConfig


class TestResolveErrorHandling(unittest.TestCase):
    """Test that resolve errors are handled gracefully."""

    def setUp(self):
        """Set up test configuration."""
        config = GuardConfig(salt='test-salt')
        config.resolve = 'head'
        config.timeout = 10
        config.user_agent = 'Test User Agent'
        config.template_dir = 'templates'
        config.resource_dir = 'resources'
        config.privacy = True
        config.domain_aliases_file = None
        config.blocklist_file = None
        config.cache_file = None
        config.cache_max = 100
        config.cache_days = 30
        config.strip_param_prefixes = []
        config.debug = False
        config.force_language = None
        
        self.server = GuardServer(config)

    @patch('requests.Session')
    def test_ssl_error_handling(self, mock_session):
        """Test that SSL errors are handled gracefully."""
        # Mock the session to raise an SSL error
        mock_session_instance = Mock()
        mock_session_instance.head.side_effect = requests.exceptions.SSLError(
            "SSL certificate verification failed"
        )
        mock_session.return_value = mock_session_instance
        
        # Mock the request context
        with patch('detrackify_guard.request') as mock_request:
            mock_request.get_json.return_value = {
                'sha': 'test-sha',
                'data': 'dGVzdC1kYXRh'  # base64 encoded 'test-data'
            }
            
            # Mock the hash verification
            with patch.object(self.server, 'salt', 'test-salt'):
                with patch('guard.utils.GuardUtils.verify_hash', return_value=True):
                    with patch('guard.utils.GuardUtils.decode_base64_payload') as mock_decode:
                        mock_decode.return_value = {
                            'url': 'https://subscriberhelp.granicus.com/?utm_medium=email'
                        }
                        
                        # Mock the cache
                        with patch.object(self.server, 'cache', None):
                            # Mock the blocklist
                            with patch.object(self.server, 'blocklist') as mock_blocklist:
                                mock_blocklist.is_url_blacklisted.return_value = False
                                
                                # Call the resolve method
                                with patch('detrackify_guard.jsonify') as mock_jsonify:
                                    mock_jsonify.return_value = Mock()
                                    response = self.server.resolve_link()
                                    
                                    # Verify that the response is successful (200)
                                    self.assertIsNotNone(response)
                                    
                                    # Verify that the original URL was returned
                                    mock_jsonify.assert_called_once()
                                    call_args = mock_jsonify.call_args[0][0]
                                    self.assertEqual(
                                        call_args['url'], 
                                        'https://subscriberhelp.granicus.com/?utm_medium=email'
                                    )
                                    self.assertIn('warning', call_args)
                                    self.assertEqual(
                                        call_args['warning'], 
                                        'SSL certificate verification failed'
                                    )

    @patch('requests.Session')
    def test_connection_error_handling(self, mock_session):
        """Test that connection errors are handled gracefully."""
        # Mock the session to raise a connection error
        mock_session_instance = Mock()
        mock_session_instance.head.side_effect = requests.exceptions.ConnectionError(
            "Connection failed"
        )
        mock_session.return_value = mock_session_instance
        
        # Mock the request context
        with patch('detrackify_guard.request') as mock_request:
            mock_request.get_json.return_value = {
                'sha': 'test-sha',
                'data': 'dGVzdC1kYXRh'  # base64 encoded 'test-data'
            }
            
            # Mock the hash verification
            with patch.object(self.server, 'salt', 'test-salt'):
                with patch('guard.utils.GuardUtils.verify_hash', return_value=True):
                    with patch('guard.utils.GuardUtils.decode_base64_payload') as mock_decode:
                        mock_decode.return_value = {
                            'url': 'https://example.com/test'
                        }
                        
                        # Mock the cache
                        with patch.object(self.server, 'cache', None):
                            # Mock the blocklist
                            with patch.object(self.server, 'blocklist') as mock_blocklist:
                                mock_blocklist.is_url_blacklisted.return_value = False
                                
                                # Call the resolve method
                                with patch('detrackify_guard.jsonify') as mock_jsonify:
                                    mock_jsonify.return_value = Mock()
                                    response = self.server.resolve_link()
                                    
                                    # Verify that the response is successful (200)
                                    self.assertIsNotNone(response)
                                    
                                    # Verify that the original URL was returned
                                    mock_jsonify.assert_called_once()
                                    call_args = mock_jsonify.call_args[0][0]
                                    self.assertEqual(call_args['url'], 'https://example.com/test')
                                    self.assertIn('warning', call_args)
                                    self.assertEqual(call_args['warning'], 'Connection error')

    @patch('requests.Session')
    def test_timeout_error_handling(self, mock_session):
        """Test that timeout errors are handled gracefully."""
        # Mock the session to raise a timeout error
        mock_session_instance = Mock()
        mock_session_instance.head.side_effect = requests.exceptions.Timeout(
            "Request timed out"
        )
        mock_session.return_value = mock_session_instance
        
        # Mock the request context
        with patch('detrackify_guard.request') as mock_request:
            mock_request.get_json.return_value = {
                'sha': 'test-sha',
                'data': 'dGVzdC1kYXRh'  # base64 encoded 'test-data'
            }
            
            # Mock the hash verification
            with patch.object(self.server, 'salt', 'test-salt'):
                with patch('guard.utils.GuardUtils.verify_hash', return_value=True):
                    with patch('guard.utils.GuardUtils.decode_base64_payload') as mock_decode:
                        mock_decode.return_value = {
                            'url': 'https://slow-site.com/test'
                        }
                        
                        # Mock the cache
                        with patch.object(self.server, 'cache', None):
                            # Mock the blocklist
                            with patch.object(self.server, 'blocklist') as mock_blocklist:
                                mock_blocklist.is_url_blacklisted.return_value = False
                                
                                # Call the resolve method
                                with patch('detrackify_guard.jsonify') as mock_jsonify:
                                    mock_jsonify.return_value = Mock()
                                    response = self.server.resolve_link()
                                    
                                    # Verify that the response is successful (200)
                                    self.assertIsNotNone(response)
                                    
                                    # Verify that the original URL was returned
                                    mock_jsonify.assert_called_once()
                                    call_args = mock_jsonify.call_args[0][0]
                                    self.assertEqual(call_args['url'], 'https://slow-site.com/test')
                                    self.assertIn('warning', call_args)
                                    self.assertEqual(call_args['warning'], 'Connection timeout')


if __name__ == '__main__':
    unittest.main() 