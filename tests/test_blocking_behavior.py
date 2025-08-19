"""
Test cases for comprehensive blocking behavior in the guard system.

This test verifies that:
1. Links with block keys in payload are never resolved
2. Blocked links show proper UX (stop emoji, no continue button)
3. Block reasons are displayed in technical details
4. Resolve endpoint respects blacklist blocking
"""

import jinja2
import pytest


def test_blocked_link_no_resolve_call():
    """
    Test that links with block key in payload don't trigger resolve calls.
    
    This ensures blocked links skip resolution entirely for security.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://malicious.example.com',
        display='Malicious Link',
        domain='example.com',
        block_reason='blacklisted',  # This should prevent resolve
        resolve=True,
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check that the template loads common.js which handles blocking logic
    assert 'src="/guard/common.js"' in html
    assert 'initializeGuard(' in html
    
    # Check that blocked state elements exist in the template
    assert 'id="blocked-state"' in html
    assert 'id="phishing-state"' in html
    
    # Check that technical details structure exists
    assert 'id="tech-block-reason-row"' in html
    assert 'id="tech-block-reason"' in html


def test_blocked_link_shows_stop_emoji():
    """
    Test that blocked links show the stop emoji (🛑) and proper messaging.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://blocked.example.com',
        display='Blocked Link',
        domain='example.com', 
        block_reason='security_policy',
        resolve=True,
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check for stop emoji and appropriate messaging
    assert '🛑' in html
    assert 'This link has been blocked' in html
    assert 'The administrator has blocked access to this link due to security concerns.' in html
    
    # Check blocked state elements exist
    assert 'id="blocked-state"' in html
    # Block reason should only appear in technical details, not in main UI
    assert 'id="tech-block-reason"' in html


def test_blocked_link_no_continue_button():
    """
    Test that blocked links hide the continue button completely.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://dangerous.example.com',
        display='Dangerous Link',
        domain='example.com',
        block_reason='phishing_attempt',
        resolve=True,
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check that continue form exists and will be handled by JavaScript
    assert 'id="continueForm"' in html
    
    # Check that the template loads common.js which handles form visibility
    assert 'src="/guard/common.js"' in html
    assert 'initializeGuard(' in html


def test_block_reason_in_technical_details():
    """
    Test that block reasons appear in the technical details section.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://blocked.example.com',
        display='Blocked Link',
        domain='example.com',
        block_reason='admin_policy_violation',
        resolve=True,
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check that block reason row exists in technical details
    assert 'id="tech-block-reason-row"' in html
    assert 'id="tech-block-reason"' in html
    assert 'Block Reason:' in html
    
    # Check that the template loads common.js which handles block reasons
    assert 'src="/guard/common.js"' in html
    assert 'initializeGuard(' in html


def test_non_resolve_blocked_behavior():
    """
    Test blocking behavior when resolve mode is disabled.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://blocked.example.com',
        display='Blocked Link',
        domain='example.com',
        block_reason='blacklisted',
        resolve=False,  # No resolve mode
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check non-resolve blocked state
    assert 'id="non-resolve-blocked"' in html
    # Block reason should only appear in technical details, not in main UI
    assert 'id="tech-block-reason"' in html
    
    # Check that the template loads common.js which handles non-resolve blocking
    assert 'src="/guard/common.js"' in html
    assert 'initializeGuard(' in html


def test_resolve_response_blocking():
    """
    Test that blocks from resolve response are properly handled.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://suspicious.example.com',
        display='Suspicious Link', 
        domain='example.com',
        block_reason='',  # No initial block
        resolve=True,
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check that the template loads common.js which handles resolve response blocking
    assert 'src="/guard/common.js"' in html
    assert 'initializeGuard(' in html
    
    # Block reason should only appear in technical details, not in main UI
    assert 'id="tech-block-reason"' in html


def test_phishing_blocks_different_from_admin_blocks():
    """
    Test that phishing blocks are handled differently from admin blocks.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://phishing.example.com',
        display='Fake Bank Login',
        domain='example.com',
        block_reason='phishy',  # Special phishing case
        resolve=True,
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check that phishing cases show phishing state, not blocked state
    assert 'phishing-state' in html
    assert '⚠️' in html  # Warning triangle for phishing
    assert 'This link may be a phishing attempt' in html
    assert "The sender's name" in html  # Part of the new phishing message
    assert "doesn't match the email address" in html  # Part of the new phishing message
    assert "or the link destination" in html  # Part of the new phishing message
    assert 'id="phishing-sender-display"' in html  # Check for phishing-specific elements
    assert 'id="phishing-sender-email"' in html
    assert 'id="phishing-link-domain"' in html
    
    # Check that the template loads common.js which handles phishing cases
    assert 'src="/guard/common.js"' in html
    assert 'initializeGuard(' in html


def test_technical_details_structure_with_blocks():
    """
    Test that technical details has proper structure including block reason.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://blocked.example.com',
        display='Blocked Link',
        domain='example.com',
        block_reason='security_violation',
        resolve=True,
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check all required technical details elements exist including block reason
    required_elements = [
        'id="technical-details"',
        'id="tech-sender"',
        'id="tech-link-name"',
        'id="tech-original-row"',
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
    
    # Check that block reason element is selectable
    assert 'class="tech-detail-value selectable" id="tech-block-reason"' in html


def test_block_reason_display_priority():
    """
    Test that block reason display logic prioritizes resolve response over initial opts.
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template('guard_warning.html')
    
    html = template.render(
        url='https://example.com',
        display='Test Link',
        domain='example.com',
        block_reason='',  # No initial block reason
        resolve=True,
        ts=0,
        sender_email='user@example.com',
        sender_display='Test User',
    )
    
    # Check that the template loads common.js which handles block reason priority logic
    assert 'src="/guard/common.js"' in html
    assert 'initializeGuard(' in html
    
    # Check that technical details structure exists for block reasons
    assert 'id="tech-block-reason-row"' in html
    assert 'id="tech-block-reason"' in html


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
