#!/usr/bin/env python3
"""
Test that phishing state elements are properly populated in the guard warning template.
"""

import jinja2
import re
import pytest


def test_phishing_state_elements_populated():
    """
    Test that phishing state elements are properly populated with sender and link information.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    # Test data for a phishing scenario
    test_context = {
        'url': 'https://fake-microsoft.com/login',
        'display': 'Microsoft Security Alert',
        'domain': 'example.com',
        'sender_domain': 'example.com',
        'block_reason': 'phishy',
        'resolve': True,
        'ts': 0,
        'sender_email': 'security@fake-microsoft.com',
        'sender_display': 'Microsoft Security Team',
        'timeout_ms': 2000,
        'deny_on_warnings': [],
        'auto_redirect': False,
    }
    
    # Render the template
    html = template.render(**test_context)
    
    # Check that the phishing state elements exist
    assert 'id="phishing-sender-display"' in html
    assert 'id="phishing-sender-email"' in html
    assert 'id="phishing-link-domain"' in html
    
    # Check that the template data is correctly passed to JavaScript
    assert 'sender_email: \'security@fake-microsoft.com\'' in html
    assert 'sender_display: \'Microsoft Security Team\'' in html
    assert 'block_reason: \'phishy\'' in html
    assert 'url: \'https://fake-microsoft.com/login\'' in html
    
    # Check that the phishing state is properly structured
    assert 'This link may be a phishing attempt' in html
    assert "The sender's name" in html
    assert "doesn't match the email address" in html
    assert "or the link destination" in html


def test_phishing_state_non_resolve_mode():
    """
    Test that phishing state works correctly in non-resolve mode.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    # Test data for non-resolve phishing scenario
    test_context = {
        'url': 'https://fake-paypal.com/verify',
        'display': 'PayPal Account Verification',
        'domain': 'example.com',
        'sender_domain': 'example.com',
        'block_reason': 'phishy',
        'resolve': False,  # Non-resolve mode
        'ts': 0,
        'sender_email': 'service@fake-paypal.com',
        'sender_display': 'PayPal Customer Service',
        'timeout_ms': 2000,
        'deny_on_warnings': [],
        'auto_redirect': False,
    }
    
    # Render the template
    html = template.render(**test_context)
    
    # Check that the non-resolve phishing state elements exist
    assert 'id="non-resolve-phishing-sender-display"' in html
    assert 'id="non-resolve-phishing-sender-email"' in html
    assert 'id="non-resolve-phishing-link-domain"' in html
    
    # Check that the template data is correctly passed to JavaScript
    assert 'sender_email: \'service@fake-paypal.com\'' in html
    assert 'sender_display: \'PayPal Customer Service\'' in html
    assert 'block_reason: \'phishy\'' in html
    assert 'url: \'https://fake-paypal.com/verify\'' in html


def test_phishing_state_with_empty_sender_display():
    """
    Test that phishing state handles empty sender display gracefully.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    # Test data with empty sender display
    test_context = {
        'url': 'https://suspicious-site.com/login',
        'display': 'Account Login',
        'domain': 'example.com',
        'sender_domain': 'example.com',
        'block_reason': 'phishy',
        'resolve': True,
        'ts': 0,
        'sender_email': 'noreply@suspicious-site.com',
        'sender_display': '',  # Empty sender display
        'timeout_ms': 2000,
        'deny_on_warnings': [],
        'auto_redirect': False,
    }
    
    # Render the template
    html = template.render(**test_context)
    
    # Check that the phishing state elements still exist
    assert 'id="phishing-sender-display"' in html
    assert 'id="phishing-sender-email"' in html
    assert 'id="phishing-link-domain"' in html
    
    # Check that empty sender display is handled correctly
    assert 'sender_display: \'\'' in html  # Empty string in JavaScript


def test_phishing_state_with_special_characters():
    """
    Test that phishing state handles special characters in sender information correctly.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    # Test data with special characters
    test_context = {
        'url': 'https://fake-bank.com/secure',
        'display': 'Bank Security Alert',
        'domain': 'example.com',
        'sender_domain': 'example.com',
        'block_reason': 'phishy',
        'resolve': True,
        'ts': 0,
        'sender_email': 'security@fake-bank.com',
        'sender_display': 'Bank & Trust Security Team',  # Special characters
        'timeout_ms': 2000,
        'deny_on_warnings': [],
        'auto_redirect': False,
    }
    
    # Render the template
    html = template.render(**test_context)
    
    # Check that the phishing state elements exist
    assert 'id="phishing-sender-display"' in html
    assert 'id="phishing-sender-email"' in html
    assert 'id="phishing-link-domain"' in html
    
    # Check that special characters are properly handled in JavaScript
    assert 'sender_display: \'Bank & Trust Security Team\'' in html  # Raw characters in JavaScript


def test_phishing_state_javascript_initialization():
    """
    Test that the JavaScript initialization properly sets up phishing detection.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    test_context = {
        'url': 'https://phishing-test.com/login',
        'display': 'Test Login',
        'domain': 'example.com',
        'sender_domain': 'example.com',
        'block_reason': 'phishy',
        'resolve': True,
        'ts': 0,
        'sender_email': 'test@phishing-test.com',
        'sender_display': 'Test Security',
        'timeout_ms': 2000,
        'deny_on_warnings': [],
        'auto_redirect': False,
    }
    
    # Render the template
    html = template.render(**test_context)
    
    # Check that the JavaScript initialization is properly set up
    assert 'window.templateData = templateData;' in html
    assert 'initializeGuard(window.guardOpts, JS_STRINGS, WARNING_DEFINITIONS, templateData);' in html
    
    # Check that the template data is properly structured
    assert 'const templateData = {' in html
    assert 'url:' in html
    assert 'sender_email:' in html
    assert 'sender_display:' in html
    assert 'block_reason:' in html
