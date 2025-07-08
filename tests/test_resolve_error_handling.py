#!/usr/bin/env python3
"""Test resolve error handling."""

import unittest
from unittest.mock import Mock, patch, MagicMock
import requests
import json
import base64
import hashlib
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
        config.blacklist_file = None
        config.cache_file = None
        config.cache_max = 100
        config.cache_days = 30
        config.strip_param_prefixes = []
        config.debug = False
        config.force_language = None
        
        self.server = GuardServer(config)
        self.app = self.server.app
        self.client = self.app.test_client()

    def create_test_payload(self, url):
        """Create a test payload with the given URL."""
        payload_data = {
            'url': url
        }
        data = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode()
        sha = hashlib.sha256((data + 'test-salt').encode()).hexdigest()
        return {
            'sha': sha,
            'data': data
        }

    @patch('requests.Session')
    def test_ssl_error_handling(self, mock_session):
        """Test that SSL errors are handled gracefully."""
        # Mock the session to raise an SSL error
        mock_session_instance = Mock()
        mock_session_instance.head.side_effect = requests.exceptions.SSLError(
            "SSL certificate verification failed"
        )
        mock_session.return_value = mock_session_instance
        
        # Create test payload
        payload = self.create_test_payload('https://subscriberhelp.granicus.com/?utm_medium=email')
        
        # Make the request using Flask test client
        with self.app.app_context():
            response = self.client.post('/guard/resolve', 
                                      json=payload,
                                      content_type='application/json')
        
        # Verify that the response is successful (200)
        self.assertEqual(response.status_code, 200)
        
        # Parse the response
        response_data = json.loads(response.data)
        self.assertEqual(
            response_data['url'], 
            'https://subscriberhelp.granicus.com/?utm_medium=email'
        )
        self.assertIn('warning', response_data)
        self.assertEqual(
            response_data['warning'], 
            'ssl_certificate:This website has security certificate issues and could not be reached'
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
        
        # Create test payload
        payload = self.create_test_payload('https://example.com/test')
        
        # Make the request using Flask test client
        with self.app.app_context():
            response = self.client.post('/guard/resolve', 
                                      json=payload,
                                      content_type='application/json')
        
        # Verify that the response is successful (200)
        self.assertEqual(response.status_code, 200)
        
        # Parse the response
        response_data = json.loads(response.data)
        self.assertEqual(response_data['url'], 'https://example.com/test')
        self.assertIn('warning', response_data)
        self.assertEqual(response_data['warning'], 'connection_error:Connection error')

    @patch('requests.Session')
    def test_timeout_error_handling(self, mock_session):
        """Test that timeout errors are handled gracefully."""
        # Mock the session to raise a timeout error
        mock_session_instance = Mock()
        mock_session_instance.head.side_effect = requests.exceptions.Timeout(
            "Request timed out"
        )
        mock_session.return_value = mock_session_instance
        
        # Create test payload
        payload = self.create_test_payload('https://slow-site.com/test')
        
        # Make the request using Flask test client
        with self.app.app_context():
            response = self.client.post('/guard/resolve', 
                                      json=payload,
                                      content_type='application/json')
        
        # Verify that the response is successful (200)
        self.assertEqual(response.status_code, 200)
        
        # Parse the response
        response_data = json.loads(response.data)
        self.assertEqual(response_data['url'], 'https://slow-site.com/test')
        self.assertIn('warning', response_data)
        self.assertEqual(response_data['warning'], 'connection_timeout:Connection timeout')


if __name__ == '__main__':
    unittest.main() 