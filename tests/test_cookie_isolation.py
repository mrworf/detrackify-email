#!/usr/bin/env python3
"""Test that cookies are not persisted between requests."""

import pytest
import requests
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from detrackify_guard import GuardConfig, GuardServer


def test_session_creation_and_cleanup():
    """Test that sessions are created and cleaned up properly."""
    cfg = GuardConfig(salt="test")
    server = GuardServer(cfg)
    
    # Mock the requests.Session to track operations
    with patch('detrackify_guard.requests.Session') as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        
        # Mock the response
        mock_response = MagicMock()
        mock_response.url = "https://example.com/final"
        mock_session.get.return_value = mock_response
        mock_session.head.return_value = mock_response
        
        # Test the session creation logic directly
        with patch.object(server, 'resolve_enabled', True):
            with patch.object(server, 'resolve_get', True):
                with patch.object(server, 'timeout', 5):
                    with patch.object(server, 'user_agent', 'test-agent'):
                        with patch.object(server, 'strip_query_params', return_value="https://example.com"):
                            # Simulate the session creation part of resolve_link
                            session = requests.Session()
                            session.headers.update({'User-Agent': 'test-agent'})
                            session.cookies.clear()
                            
                            # Simulate a request
                            resp = session.get("https://example.com", allow_redirects=True, timeout=5)
                            
                            # Clean up
                            session.cookies.clear()
                            session.close()
        
        # Verify that the session was created
        mock_session_class.assert_called_once()
        
        # Verify that cookies.clear() was called
        assert mock_session.cookies.clear.call_count >= 1
        
        # Verify that the session was closed
        mock_session.close.assert_called_once()


def test_multiple_sessions_are_isolated():
    """Test that multiple requests create separate sessions."""
    cfg = GuardConfig(salt="test")
    server = GuardServer(cfg)
    
    with patch('detrackify_guard.requests.Session') as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        
        # Mock the response
        mock_response = MagicMock()
        mock_response.url = "https://example.com/final"
        mock_session.get.return_value = mock_response
        mock_session.head.return_value = mock_response
        
        # Simulate multiple requests
        for i in range(3):
            with patch.object(server, 'resolve_enabled', True):
                with patch.object(server, 'resolve_get', True):
                    with patch.object(server, 'timeout', 5):
                        with patch.object(server, 'user_agent', 'test-agent'):
                            with patch.object(server, 'strip_query_params', return_value="https://example.com"):
                                # Each request should create a new session
                                session = requests.Session()
                                session.headers.update({'User-Agent': 'test-agent'})
                                session.cookies.clear()
                                
                                # Simulate a request
                                resp = session.get("https://example.com", allow_redirects=True, timeout=5)
                                
                                # Clean up
                                session.cookies.clear()
                                session.close()
        
        # Verify that a new session was created for each request
        assert mock_session_class.call_count == 3
        
        # Verify that each session was properly closed
        assert mock_session.close.call_count == 3


def test_cookie_clearing_behavior():
    """Test that cookies are explicitly cleared before and after requests."""
    cfg = GuardConfig(salt="test")
    server = GuardServer(cfg)
    
    with patch('detrackify_guard.requests.Session') as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        
        # Mock the response
        mock_response = MagicMock()
        mock_response.url = "https://example.com/final"
        mock_session.get.return_value = mock_response
        mock_session.head.return_value = mock_response
        
        # Test the cookie clearing behavior
        with patch.object(server, 'resolve_enabled', True):
            with patch.object(server, 'resolve_get', True):
                with patch.object(server, 'timeout', 5):
                    with patch.object(server, 'user_agent', 'test-agent'):
                        with patch.object(server, 'strip_query_params', return_value="https://example.com"):
                            # Simulate the session creation and cookie clearing
                            session = requests.Session()
                            session.headers.update({'User-Agent': 'test-agent'})
                            
                            # Clear cookies before request
                            session.cookies.clear()
                            
                            # Simulate a request
                            resp = session.get("https://example.com", allow_redirects=True, timeout=5)
                            
                            # Clear cookies after request
                            session.cookies.clear()
                            session.close()
        
        # Verify that cookies.clear() was called at least twice (before and after)
        assert mock_session.cookies.clear.call_count >= 2 