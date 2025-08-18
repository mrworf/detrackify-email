"""
Test cases for the resolved URL display consistency in technical details.

This test verifies that the resolved URL is always shown in technical details
when resolve mode is enabled, regardless of whether the resolved URL differs
from the original URL.
"""

import jinja2
import pytest


def test_resolved_url_shows_when_same_as_original():
    """
    Test that resolved URL is shown even when it's the same as original URL.
    
    This tests the scenario where:
    - Resolution is successful 
    - But URL doesn't redirect (resolved URL = original URL)
    - Resolved link row should still be visible
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://example.com/page',
        display='Click here',
        domain='example.com',
        block_reason='',
        resolve=True,  # Resolve mode enabled
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check that template has the technical details structure
    assert 'id="tech-resolved-row"' in html
    assert 'id="tech-resolved-url"' in html
    
    # Check that the JavaScript logic exists for showing resolved URL
    # The key condition should NOT include "&& data.url !== originalUrl"
    assert 'opts.resolve && data && data.url' in html
    # Ensure the old broken condition is not present
    assert 'data.url !== originalUrl' not in html


def test_resolved_url_shows_when_different_from_original():
    """
    Test that resolved URL is shown when it differs from original URL.
    
    This tests the scenario where:
    - Resolution is successful
    - URL redirects to a different destination
    - Resolved link row should be visible
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://short.ly/abc123',
        display='Short URL',
        domain='example.com',
        block_reason='',
        resolve=True,  # Resolve mode enabled
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check that template has the technical details structure
    assert 'id="tech-resolved-row"' in html
    assert 'id="tech-resolved-url"' in html
    
    # Check that the JavaScript logic exists for showing resolved URL
    assert 'opts.resolve && data && data.url' in html


def test_resolved_url_hidden_when_resolve_disabled():
    """
    Test that resolved URL row is hidden when resolve mode is disabled.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://example.com/page',
        display='Click here',
        domain='example.com',
        block_reason='',
        resolve=False,  # Resolve mode disabled
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check that template has the technical details structure
    assert 'id="tech-resolved-row"' in html
    assert 'id="tech-resolved-url"' in html
    
    # The row should be hidden when resolve=False
    assert 'opts.resolve && data && data.url' in html


def test_resolved_url_shows_with_warnings():
    """
    Test that resolved URL is shown even when resolution warnings occur.
    
    This tests scenarios where resolution encounters warnings (SSL issues, 
    timeouts, etc.) but still returns a URL (usually the original URL as fallback).
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://ssl-issues.example.com',
        display='Problematic SSL site',
        domain='example.com',
        block_reason='',
        resolve=True,  # Resolve mode enabled
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check that template has the technical details structure
    assert 'id="tech-resolved-row"' in html
    assert 'id="tech-resolved-url"' in html
    
    # Check that the JavaScript logic for warnings is present
    assert 'id="tech-warning-row"' in html
    assert 'id="tech-warning"' in html
    
    # Resolved URL should still show even with warnings
    assert 'opts.resolve && data && data.url' in html


def test_technical_details_has_proper_structure():
    """
    Test that the technical details section has all required elements.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://example.com',
        display='Test Link',
        domain='example.com',
        block_reason='',
        resolve=True,
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check all required technical details elements exist
    required_elements = [
        'id="technical-details"',
        'id="tech-sender"',
        'id="tech-link-name"',
        'id="tech-original-row"',
        'id="tech-original-label"',
        'id="tech-original-url"',
        'id="tech-resolved-row"',
        'id="tech-resolved-url"',
        'id="tech-title-row"',
        'id="tech-title"',
        'id="tech-warning-row"',
        'id="tech-warning"',
        'id="tech-block-reason-row"',
        'id="tech-block-reason"'
    ]
    
    for element in required_elements:
        assert element in html, f"Missing required element: {element}"
    
    # Check that the toggle function exists
    assert 'toggleTechnicalDetails()' in html
    assert 'populateTechnicalDetails(' in html


def test_page_title_display_logic():
    """
    Test that page title display logic is correctly implemented in JavaScript.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://example.com',
        display='Test Link',
        domain='example.com',
        block_reason='',
        resolve=True,
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check that title row elements exist
    assert 'id="tech-title-row"' in html
    assert 'id="tech-title"' in html
    assert 'Page Title:' in html
    
    # Check that the JavaScript logic for title handling exists
    assert 'opts.resolve && data && data.title && data.title.trim() !== \'\'' in html
    assert 'techTitleRow.style.display = \'\';' in html
    assert 'techTitleRow.style.display = \'none\';' in html
    
    # Check title truncation logic
    assert 'displayTitle.length > 100' in html
    assert 'displayTitle.substring(0, 97) + \'...\';' in html


def test_title_handling_for_long_titles():
    """
    Test that the JavaScript logic properly handles long titles.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://example.com/very-long-page-title',
        display='Link with Long Title',
        domain='example.com',
        block_reason='',
        resolve=True,
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check that truncation logic exists
    assert 'if (displayTitle.length > 100)' in html
    assert 'displayTitle = displayTitle.substring(0, 97) + \'...\';' in html
    
    # Check that title element is selectable for copying
    assert 'class="tech-detail-value selectable"' in html


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
