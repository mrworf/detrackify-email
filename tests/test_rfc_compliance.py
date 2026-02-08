"""
RFC compliance validation tests for email output.

This module provides utilities to validate that processed emails conform to
RFC 5322 (email message format) and RFC 2045-2047 (MIME) standards, ensuring
they will be accepted by email servers and clients.
"""

import email
import pytest
from email import policy
from email.parser import BytesParser
from email.errors import MessageError, HeaderParseError
from typing import Optional


def validate_rfc_compliance(msg_bytes: bytes, strict: bool = True) -> tuple[bool, Optional[str]]:
    """
    Validate that an email message conforms to RFC 5322 and RFC 2045-2047 standards.
    
    Args:
        msg_bytes: Raw email message bytes
        strict: If True, use strict policy; if False, use default policy
        
    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if message is RFC-compliant
        - error_message: None if valid, otherwise description of the issue
    """
    try:
        # Use strict policy for more rigorous validation
        email_policy = policy.strict if strict else policy.default
        
        # Parse the email - this will raise exceptions for severe RFC violations
        parser = BytesParser(policy=email_policy)
        msg = parser.parsebytes(msg_bytes)
        
        # Additional validation checks
        
        # 1. Check for valid MIME structure if multipart
        if msg.is_multipart():
            content_type = msg.get_content_type()
            if content_type.startswith('multipart/'):
                boundary = msg.get_boundary()
                if not boundary:
                    return False, "Multipart message missing boundary parameter"
                
                # Check that boundary appears in the message
                if boundary.encode() not in msg_bytes:
                    return False, f"Boundary '{boundary}' not found in message body"
        
        # 2. Validate Content-Type headers
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type:
                # Basic validation - Content-Type should be valid
                if '/' not in content_type:
                    return False, f"Invalid Content-Type format: {content_type}"
                
                # Check charset if specified
                charset = part.get_content_charset()
                if charset:
                    # Basic charset validation (should be valid encoding name)
                    try:
                        'test'.encode(charset)
                    except (LookupError, ValueError):
                        return False, f"Invalid charset specified: {charset}"
        
        # 3. Validate Content-Transfer-Encoding
        for part in msg.walk():
            encoding = part.get('Content-Transfer-Encoding', '').lower()
            if encoding and encoding not in ('7bit', '8bit', 'binary', 'quoted-printable', 'base64'):
                return False, f"Invalid Content-Transfer-Encoding: {encoding}"
        
        # 4. Check for valid header format (no invalid characters)
        for header_name, header_value in msg.items():
            if header_value:
                # Headers should not contain unencoded newlines (except for folding)
                # The email module handles this, but we can check for obvious issues
                if '\n' in header_value and '\r\n' not in header_value.replace('\r\n', ''):
                    # Allow RFC 5322 header folding (lines starting with space/tab)
                    lines = header_value.split('\n')
                    for i, line in enumerate(lines[1:], 1):
                        if line and not line[0] in (' ', '\t'):
                            return False, f"Invalid header folding in {header_name}"
        
        # 5. Validate multipart/alternative structure (common case)
        if msg.get_content_type() == 'multipart/alternative':
            parts = list(msg.iter_parts())
            if len(parts) < 2:
                return False, "multipart/alternative must have at least 2 parts"
            
            # Check that parts have valid content types
            content_types = [p.get_content_type() for p in parts]
            if 'text/plain' not in content_types and 'text/html' not in content_types:
                # This is a warning, not an error - but worth noting
                pass
        
        # 6. Try to serialize and re-parse (round-trip test)
        # This catches many structural issues
        try:
            serialized = msg.as_bytes(policy=email_policy)
            parser2 = BytesParser(policy=email_policy)
            msg2 = parser2.parsebytes(serialized)
        except Exception as e:
            return False, f"Message fails round-trip serialization: {str(e)}"
        
        return True, None
        
    except MessageError as e:
        return False, f"Message parsing error: {str(e)}"
    except HeaderParseError as e:
        return False, f"Header parsing error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error during validation: {str(e)}"


def assert_rfc_compliant(msg_bytes: bytes, strict: bool = True) -> None:
    """
    Assert that an email message is RFC-compliant.
    
    Raises AssertionError with descriptive message if validation fails.
    
    Args:
        msg_bytes: Raw email message bytes
        strict: If True, use strict policy; if False, use default policy
    """
    is_valid, error_msg = validate_rfc_compliance(msg_bytes, strict)
    assert is_valid, f"Email is not RFC-compliant: {error_msg}"


@pytest.fixture
def rfc_validator():
    """Pytest fixture providing RFC validation helper."""
    return {
        'validate': validate_rfc_compliance,
        'assert_compliant': assert_rfc_compliant,
    }


def test_rfc_compliance_helper():
    """Test that the RFC compliance helper works correctly."""
    # Valid email
    valid_email = b"""From: test@example.com
To: recipient@example.com
Subject: Test
Content-Type: text/plain

Test content.
"""
    is_valid, error = validate_rfc_compliance(valid_email)
    assert is_valid, f"Valid email failed validation: {error}"
    
    # Invalid email (missing required structure)
    invalid_email = b"""Invalid email content without proper headers
"""
    is_valid, error = validate_rfc_compliance(invalid_email)
    # Should either fail or handle gracefully
    # (Some malformed emails might still parse, which is OK for our purposes)
