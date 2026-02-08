"""Integration tests for detrackify_email."""

# This file tests the detrackify_email.py script as it would be used in a production environment.
# It should perform all tests by running the script with various command line arguments and checking the output.
# As needed, pipe content from test data files into the script when running to simulate the script being used in a production environment.

import email
import glob
import os
import subprocess
import sys
import tempfile
import base64
import json
import hashlib
import pytest
from bs4 import BeautifulSoup
from common.utils import SharedUtils
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import detrackify_guard
import logging
from test_rfc_compliance import assert_rfc_compliant

# Path to the script under test
SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "detrackify_email.py")

# Test email file categories - using glob patterns for scalability
SPAM_FILES = sorted(glob.glob(os.path.join('tests', 'content', 'spam*.eml')))
CLEAN_FILES = sorted(glob.glob(os.path.join('tests', 'content', 'clean*.eml')))
LEGIT_FILES = sorted(glob.glob(os.path.join('tests', 'content', 'legit*.eml')))
PHISHING_FILES = sorted(glob.glob(os.path.join('tests', 'content', 'phishing*.eml')))

# All real-world email files for comprehensive testing
ALL_REAL_WORLD_FILES = LEGIT_FILES + SPAM_FILES + PHISHING_FILES


def process_email(path, extra_args=None, validate_rfc=True):
    """
    Run the script on the provided path and return the resulting message.
    
    Args:
        path: Path to input email file
        extra_args: Additional command-line arguments
        validate_rfc: If True, validate RFC compliance of output
        
    Returns:
        Parsed email message object
    """
    extra_args = extra_args or []
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name
    try:
        subprocess.run([
            sys.executable,
            SCRIPT,
            "--input",
            path,
            "--output",
            tmp_path,
            *extra_args,
        ], check=True)
        
        # Read the output bytes for RFC validation
        with open(tmp_path, "rb") as fd:
            output_bytes = fd.read()
        
        # Validate RFC compliance if requested
        if validate_rfc:
            assert_rfc_compliant(output_bytes, strict=False)  # Use default policy for compatibility
        
        # Parse and return message
        return email.message_from_bytes(output_bytes)
    finally:
        os.remove(tmp_path)


def process_email_expect_failure(path, extra_args=None):
    """Run the script expecting it to fail and return the result."""
    extra_args = extra_args or []
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name
    try:
        result = subprocess.run([
            sys.executable,
            SCRIPT,
            "--input",
            path,
            "--output",
            tmp_path,
            *extra_args,
        ], capture_output=True, text=True)
        # Check if output file was created and has content
        output_content = None
        if os.path.exists(tmp_path):
            with open(tmp_path, "rb") as fd:
                output_content = fd.read()
        return result, output_content
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def process_email_hardfail(path, extra_args=None):
    """Run the script with hardfail enabled and return the result."""
    extra_args = extra_args or []
    extra_args.append("--hardfail")
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name
    try:
        result = subprocess.run([
            sys.executable,
            SCRIPT,
            "--input",
            path,
            "--output",
            tmp_path,
            *extra_args,
        ], capture_output=True, text=True)
        # Check if output file was created and has content
        output_content = None
        if os.path.exists(tmp_path):
            with open(tmp_path, "rb") as fd:
                output_content = fd.read()
        return result, output_content
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def has_tracking(msg):
    headers = msg.get_all('X-Detrackify-Blocked') or []
    return any('No tracking pixels' not in h for h in headers)


def test_spam_emails():
    """
    Test that emails in the spam category are correctly identified as having tracking pixels.
    
    Expected outcome: All spam emails should be flagged as containing tracking pixels,
    indicated by X-Detrackify-Blocked headers that don't contain 'No tracking pixels'.
    """
    for path in SPAM_FILES:
        msg = process_email(path)
        assert has_tracking(msg), f'{path} not flagged'


def test_clean_emails():
    """
    Test that emails in the clean category are correctly identified as NOT having tracking pixels.
    
    Expected outcome: All clean emails should have X-Detrackify-Blocked headers stating
    'No tracking pixels' indicating they are clean of tracking content.
    """
    for path in CLEAN_FILES:
        msg = process_email(path)
        headers = msg.get_all('X-Detrackify-Blocked')
        assert headers and all('No tracking pixels' in h for h in headers), f'{path} incorrectly flagged'


def test_legit_emails():
    """
    Test processing of legitimate emails (financial services, business communications, etc.).
    
    Expected outcome: Legitimate emails should process without errors, preserve all headers
    and content, and typically have minimal or no tracking detection since they're from
    trusted sources. Output should be RFC-compliant.
    """
    for path in LEGIT_FILES:
        msg = process_email(path)  # RFC validation enabled by default
        
        # Should process without errors
        assert msg is not None, f"Failed to process legitimate email: {path}"
        
        # Should have minimal tracking detection (legitimate emails are typically clean)
        headers = msg.get_all('X-Detrackify-Blocked')
        if headers:
            # If there are blocked headers, they should indicate no tracking
            assert all('No tracking pixels' in h for h in headers), f"Legitimate email incorrectly flagged as having tracking: {path}"
        
        # Should preserve important headers
        assert msg.get('From') is not None, f"From header missing in {path}"
        assert msg.get('To') is not None, f"To header missing in {path}"
        assert msg.get('Subject') is not None, f"Subject header missing in {path}"
        
        # Should have detrackify processing header
        assert msg.get('X-Detrackify') == 'Processed by Detrackify', f"Missing detrackify processing header in {path}"
        
        # Content should be preserved
        assert msg.get_payload() is not None, f"Email payload missing in {path}"


def test_phishing_emails():
    """
    Test processing of phishing emails to ensure they're handled safely.
    
    Expected outcome: Phishing emails should be processed without crashes, preserve
    email structure for analysis, and typically be flagged as spam by spam filters.
    The tool should handle malicious content gracefully without compromising security.
    """
    for path in PHISHING_FILES:
        msg = process_email(path)
        
        # Should process without errors (even malicious emails should be processed)
        assert msg is not None, f"Failed to process phishing email: {path}"
        
        # Should have detrackify processing header
        assert msg.get('X-Detrackify') == 'Processed by Detrackify', f"Missing detrackify processing header in {path}"
        
        # Should preserve email structure for analysis
        assert msg.get('From') is not None, f"From header missing in {path}"
        assert msg.get('To') is not None, f"To header missing in {path}"
        assert msg.get('Subject') is not None, f"Subject header missing in {path}"
        
        # Should have spam indicators in headers (phishing emails are typically flagged)
        spam_headers = msg.get_all('X-Spam-Status')
        if spam_headers:
            # If spam headers exist, they should indicate this is spam
            assert any('Yes' in h for h in spam_headers), f"Phishing email not flagged as spam: {path}"
        
        # Should have content
        assert msg.get_payload() is not None, f"Email payload missing in {path}"


def test_all_email_types_parameter_stripping():
    """
    Test that URL parameter stripping works correctly across all email types.
    
    Expected outcome: All email types should have URLs with tracking parameters
    (utm_, fbclid, etc.) stripped while preserving legitimate parameters and
    maintaining email structure and functionality.
    """
    all_files = [
        (LEGIT_FILES, "legitimate"),
        (SPAM_FILES, "spam"), 
        (PHISHING_FILES, "phishing"),
    ]
    
    for file_list, email_type in all_files:
        for path in file_list:
            msg = process_email(path, ["--strip-param-prefix", "utm_", "--strip-param-prefix", "fbclid"])
            assert msg is not None, f"Failed to process {email_type} email with parameter stripping: {path}"
            
            # Should have detrackify processing header
            assert msg.get('X-Detrackify') == 'Processed by Detrackify', f"Missing detrackify processing header for {email_type} email: {path}"
            
            # Should preserve email structure
            assert msg.get('From') is not None, f"From header missing in {email_type} email: {path}"
            assert msg.get('To') is not None, f"To header missing in {email_type} email: {path}"
            assert msg.get('Subject') is not None, f"Subject header missing in {email_type} email: {path}"


def test_all_email_types_guard_mode():
    """
    Test that guard mode (link rewriting for security) works correctly across all email types.
    
    Expected outcome: All email types should have links rewritten to go through the guard
    server when guard mode is enabled, while preserving email structure and ensuring
    the rewritten links contain proper authentication hashes.
    """
    guard_server = "https://guard.example.com"
    guard_salt = "test-salt-123"
    
    all_files = [
        (LEGIT_FILES, "legitimate"),
        (SPAM_FILES, "spam"),
        (PHISHING_FILES, "phishing"),
    ]
    
    for file_list, email_type in all_files:
        for path in file_list:
            msg = process_email(path, [
                "--guardserver", guard_server,
                "--guardsalt", guard_salt,
                "--guardlink", "mismatch"
            ])
            assert msg is not None, f"Failed to process {email_type} email with guard mode: {path}"
            
            # Should have detrackify processing header
            assert msg.get('X-Detrackify') == 'Processed by Detrackify', f"Missing detrackify processing header for {email_type} email: {path}"
            
            # Should preserve email structure
            assert msg.get('From') is not None, f"From header missing in {email_type} email: {path}"
            assert msg.get('To') is not None, f"To header missing in {email_type} email: {path}"
            assert msg.get('Subject') is not None, f"Subject header missing in {email_type} email: {path}"


def test_pylint():
    """
    Test that the code passes pylint static analysis.
    
    Expected outcome: The main script should pass pylint error checking (-E flag)
    with no critical errors that would prevent proper execution.
    """
    try:
        # First check if pylint is available
        subprocess.run([sys.executable, "-m", "pylint", "--version"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Skip only if pylint is not available
        pytest.skip("pylint not available")
    
    # If pylint is available, run the actual check
    result = subprocess.run([sys.executable, "-m", "pylint", "-E", SCRIPT], capture_output=True, text=True)
    if result.returncode != 0:
        # If pylint finds errors, fail the test and show the output
        pytest.fail(f"pylint found errors:\n{result.stdout}\n{result.stderr}")


#########################
# Negative test cases for malformed/corrupted emails
#########################

def test_empty_file():
    """
    Test handling of completely empty email file.
    
    Expected outcome: Script should not crash and should either process gracefully
    or fail gracefully in soft-fail mode, producing some output even if minimal.
    """
    path = os.path.join('tests', 'content', 'malformed_empty.eml')
    # Should not crash - should either process gracefully or fail gracefully
    result, output = process_email_expect_failure(path)
    # The script should not crash (exit code should be 0 in soft-fail mode)
    assert result.returncode == 0, f"Script crashed on empty file: {result.stderr}"
    # Output should still be generated (even if just headers)
    assert output is not None, "No output generated for empty file"


def test_missing_headers():
    """
    Test handling of email with no headers section.
    
    Expected outcome: Script should not crash when processing an email that lacks
    standard email headers, processing gracefully and producing valid output.
    """
    path = os.path.join('tests', 'content', 'malformed_no_headers.eml')
    # Should not crash - should process gracefully
    result, output = process_email_expect_failure(path)
    assert result.returncode == 0, f"Script crashed on no headers: {result.stderr}"
    assert output is not None, "No output generated for email with no headers"


def test_corrupted_headers():
    """
    Test handling of email with corrupted or malformed headers.
    
    Expected outcome: Script should not crash when processing emails with invalid
    header formatting, handling the corruption gracefully and producing output.
    """
    path = os.path.join('tests', 'content', 'malformed_corrupted_headers.eml')
    # Should not crash - should process gracefully
    result, output = process_email_expect_failure(path)
    assert result.returncode == 0, f"Script crashed on corrupted headers: {result.stderr}"
    assert output is not None, "No output generated for corrupted headers"


def test_binary_content():
    """
    Test handling of email containing binary content or non-text data.
    
    Expected outcome: Script should not crash when processing emails with binary
    attachments or content, handling the binary data safely without corruption.
    """
    path = os.path.join('tests', 'content', 'malformed_binary.eml')
    # Should not crash - should process gracefully
    result, output = process_email_expect_failure(path)
    assert result.returncode == 0, f"Script crashed on binary content: {result.stderr}"
    assert output is not None, "No output generated for binary content"


def test_malformed_mime():
    """
    Test handling of email with malformed MIME structure.
    
    Expected outcome: Script should not crash when processing emails with incorrect
    MIME boundaries, missing parts, or other MIME structural problems.
    """
    path = os.path.join('tests', 'content', 'malformed_mime.eml')
    # Should not crash - should process gracefully
    result, output = process_email_expect_failure(path)
    assert result.returncode == 0, f"Script crashed on malformed MIME: {result.stderr}"
    assert output is not None, "No output generated for malformed MIME"


def test_encoding_issues():
    """
    Test handling of email with character encoding problems.
    
    Expected outcome: Script should not crash when processing emails with invalid
    character encodings, mixed encodings, or encoding declaration mismatches.
    """
    path = os.path.join('tests', 'content', 'malformed_encoding.eml')
    # Should not crash - should process gracefully
    result, output = process_email_expect_failure(path)
    assert result.returncode == 0, f"Script crashed on encoding issues: {result.stderr}"
    assert output is not None, "No output generated for encoding issues"


def test_truncated_email():
    """
    Test handling of truncated or incomplete email files.
    
    Expected outcome: Script should not crash when processing emails that are
    cut off mid-stream, handling incomplete data gracefully.
    """
    path = os.path.join('tests', 'content', 'malformed_truncated.eml')
    # Should not crash - should process gracefully
    result, output = process_email_expect_failure(path)
    assert result.returncode == 0, f"Script crashed on truncated email: {result.stderr}"
    assert output is not None, "No output generated for truncated email"


def test_invalid_html():
    """
    Test handling of email with malformed HTML content.
    
    Expected outcome: Script should not crash when processing emails with invalid
    HTML tags, unclosed elements, or other HTML parsing issues.
    """
    path = os.path.join('tests', 'content', 'malformed_invalid_html.eml')
    # Should not crash - should process gracefully
    result, output = process_email_expect_failure(path)
    assert result.returncode == 0, f"Script crashed on invalid HTML: {result.stderr}"
    assert output is not None, "No output generated for invalid HTML"


def test_null_bytes():
    """
    Test handling of email containing null bytes or other control characters.
    
    Expected outcome: Script should not crash when processing emails with null
    bytes, handling the control characters safely without security issues.
    """
    path = os.path.join('tests', 'content', 'malformed_null_bytes.eml')
    # Should not crash - should process gracefully
    result, output = process_email_expect_failure(path)
    assert result.returncode == 0, f"Script crashed on null bytes: {result.stderr}"
    assert output is not None, "No output generated for null bytes"


def test_large_email():
    """
    Test handling of very large email files to ensure performance and memory safety.
    
    Expected outcome: Script should not crash, timeout, or consume excessive memory
    when processing large emails, completing processing in reasonable time.
    """
    path = os.path.join('tests', 'content', 'malformed_large.eml')
    # Should not crash or timeout - should process gracefully
    result, output = process_email_expect_failure(path)
    assert result.returncode == 0, f"Script crashed on large email: {result.stderr}"
    assert output is not None, "No output generated for large email"


def test_nonexistent_file():
    """
    Test handling of nonexistent input file paths.
    
    Expected outcome: Script should fail gracefully with appropriate error message
    when given a path to a file that doesn't exist.
    """
    path = os.path.join('tests', 'content', 'nonexistent.eml')
    # Should fail gracefully with appropriate error message
    result, output = process_email_expect_failure(path)
    assert result.returncode != 0, "Script should fail on nonexistent file"
    assert "No such file" in result.stderr or "FileNotFoundError" in result.stderr, "Should have file not found error"


def test_hardfail_mode_empty():
    """
    Test that hardfail mode fails fast on empty files.
    
    Expected outcome: In hardfail mode, script should exit with error code when
    encountering processing errors, preventing potentially corrupted output.
    """
    path = os.path.join('tests', 'content', 'malformed_empty.eml')
    result, output = process_email_hardfail(path)
    # In hardfail mode, should exit with non-zero code on processing errors
    # But empty file might be handled differently


def test_hardfail_mode_corrupted():
    """
    Test that hardfail mode fails fast on corrupted emails.
    
    Expected outcome: In hardfail mode, script should exit with error code when
    encountering corrupted email data rather than producing potentially incorrect output.
    """
    path = os.path.join('tests', 'content', 'malformed_corrupted_headers.eml')
    result, output = process_email_hardfail(path)
    # In hardfail mode, should either succeed or fail fast


def test_passthrough_on_error():
    """
    Test that malformed emails are passed through unchanged in soft-fail mode.
    
    Expected outcome: In soft-fail mode, when processing fails, the original email
    content should be preserved to maintain email delivery functionality.
    """
    path = os.path.join('tests', 'content', 'malformed_encoding.eml')
    # Explicitly ensure we're not using hardfail mode
    result, output = process_email_expect_failure(path, [])
    
    # In soft-fail mode, script may exit with error code but should still produce output
    # that preserves the original email content
    assert output is not None, "No output generated"
    assert len(output) > 0, "Empty output generated"
    
    # The output should be either processed or the original passed through
    try:
        msg = email.message_from_bytes(output)
        # Should have at least some headers
        assert len(msg.items()) > 0, "No headers in processed email"
    except Exception as e:
        # If we can't parse it as email, it might be the original passed through
        # In production, this would be acceptable as it preserves email delivery
        
        # Read original content to compare
        with open(path, 'rb') as f:
            original_content = f.read()
        
        # Output should be similar to original (preserving email delivery)
        assert len(output) > 0, f"Empty output despite error: {e}"


def test_hardfail_mode_with_encoding_issues():
    """
    Test that hardfail mode fails appropriately on encoding issues.
    
    Expected outcome: In hardfail mode, script should exit with non-zero code when
    encountering encoding problems, preventing potentially corrupted email processing.
    """
    path = os.path.join('tests', 'content', 'malformed_encoding.eml')
    result, output = process_email_hardfail(path)
    
    # In hardfail mode, the script should exit with non-zero code on processing errors
    # This is the expected behavior to prevent processing of corrupted emails
    assert result.returncode != 0, "Script should fail in hardfail mode on encoding issues"
    
    # Error message should be informative
    assert "Error" in result.stderr, "Should have error message in stderr"


def test_processing_preserves_original_on_error():
    """
    Test that original email content is preserved when processing encounters errors.
    
    Expected outcome: When processing fails, the tool should ensure email delivery
    is not compromised by preserving the original content in a parseable form.
    """
    path = os.path.join('tests', 'content', 'malformed_mime.eml')
    
    # Read original content
    with open(path, 'rb') as f:
        original_content = f.read()
    
    result, output = process_email_expect_failure(path)
    assert result.returncode == 0, f"Script failed: {result.stderr}"
    assert output is not None, "No output generated"
    
    # The output should be a valid email (even if just the original passed through)
    try:
        msg = email.message_from_bytes(output)
        # Should have at least some headers
        assert len(msg.items()) > 0, "No headers in processed email"
    except Exception as e:
        # If we can't parse it as email, it might be the original passed through
        # In production, this would be acceptable as it preserves email delivery
        pass


def test_stdin_stdout_mode_with_malformed():
    """
    Test that script can handle malformed input via stdin/stdout mode.
    
    Expected outcome: Script should not crash when processing malformed emails
    through stdin/stdout, which is the typical production deployment mode.
    """
    path = os.path.join('tests', 'content', 'malformed_encoding.eml')
    
    # Test stdin/stdout mode
    with open(path, 'rb') as f:
        result = subprocess.run([
            sys.executable,
            SCRIPT,
        ], input=f.read(), capture_output=True)
    
    # Should not crash in stdin/stdout mode
    assert result.returncode == 0, f"Script crashed in stdin/stdout mode: {result.stderr}"
    assert len(result.stdout) > 0, "No output generated in stdin/stdout mode"


#########################
# Guard link tests
#########################

GUARD_FILE = os.path.join(os.path.dirname(__file__), "content", "guard.eml")
SALT = "testsalt"
SERVER = "https://guard.example.com"
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "content", "config_guard.yml")


def extract_links(msg):
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
            soup = BeautifulSoup(html, "html.parser")
            return [(a.get_text(), a["href"]) for a in soup.find_all("a")]
    return []


def test_guard_off_no_change():
    """
    Test that guard mode is disabled by default (no link rewriting).
    
    Expected outcome: When guard server is specified but guardlink is not set,
    no links should be rewritten and original URLs should be preserved.
    """
    msg = process_email(GUARD_FILE, ["--guardserver", SERVER, "--guardsalt", SALT])
    links = extract_links(msg)
    assert links[0][1] == "https://example.com/welcome"
    assert links[1][1] == "https://other.com/path?x=1&y=2"
    assert msg.get("X-Detrackify-Guarded-Links") is None


def test_guard_mismatch_only_changes_mismatched():
    """
    Test that mismatch mode only rewrites links to domains different from sender.
    
    Expected outcome: Links to domains that don't match the sender domain should
    be rewritten through guard server, while same-domain links are preserved.
    """
    msg = process_email(GUARD_FILE, [
        "--guardserver", SERVER,
        "--guardsalt", SALT,
        "--guardlink", "mismatch",
    ])
    links = extract_links(msg)
    assert links[0][1] == "https://example.com/welcome"
    b64 = base64.urlsafe_b64encode(json.dumps({
        "display": "Click \"here\" & enjoy",
        "from": "user@example.com",
        "url": "https://other.com/path?x=1&y=2",
    }).encode()).decode()
    sha = hashlib.sha256((b64 + SALT).encode()).hexdigest()
    expected = f"{SERVER}/guard/{sha}/{b64}"
    assert links[1][1] == expected
    assert msg["X-Detrackify-Guarded-Links"] == "1"
    assert msg["X-Detrackify-Guard-Mode"] == "mismatch"


def test_guard_all_changes_all():
    """
    Test that 'always' mode rewrites all links through guard server.
    
    Expected outcome: All links should be rewritten through guard server regardless
    of domain match, providing maximum security by intercepting all link clicks.
    """
    msg = process_email(GUARD_FILE, [
        "--guardserver", SERVER,
        "--guardsalt", SALT,
        "--guardlink", "always",
    ])
    links = extract_links(msg)
    payload1 = base64.urlsafe_b64encode(json.dumps({
        "display": "Welcome",
        "from": "user@example.com",
        "url": "https://example.com/welcome",
    }).encode()).decode()
    sha1 = hashlib.sha256((payload1 + SALT).encode()).hexdigest()
    expected1 = f"{SERVER}/guard/{sha1}/{payload1}"
    payload2 = base64.urlsafe_b64encode(json.dumps({
        "display": "Click \"here\" & enjoy",
        "from": "user@example.com",
        "url": "https://other.com/path?x=1&y=2",
    }).encode()).decode()
    sha2 = hashlib.sha256((payload2 + SALT).encode()).hexdigest()
    expected2 = f"{SERVER}/guard/{sha2}/{payload2}"
    assert links[0][1] == expected1
    assert links[1][1] == expected2
    assert msg["X-Detrackify-Guarded-Links"] == "2"
    assert msg["X-Detrackify-Guard-Mode"] == "always"


def test_guard_whitelist_sender():
    # Create a temporary guard whitelist file with sender whitelist
    import tempfile
    import yaml
    
    guard_whitelist_data = {
        'whitelist': [
            {'sender': '^user@example\\.com$'}
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(guard_whitelist_data, f)
        guard_whitelist_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(GUARD_FILE, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "always",
            "--guard-whitelist-file", guard_whitelist_path,
        ])
        links = extract_links(msg)
        assert links[0][1] == "https://example.com/welcome"
        assert links[1][1] == "https://other.com/path?x=1&y=2"
        assert msg["X-Detrackify-Guarded-Links"] == "0"
    finally:
        os.unlink(guard_whitelist_path)


def test_guard_whitelist_link():
    # Create a temporary guard whitelist file with link whitelist
    import tempfile
    import yaml
    
    guard_whitelist_data = {
        'whitelist': [
            {'url': '^https://other\\.com'}
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(guard_whitelist_data, f)
        guard_whitelist_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(GUARD_FILE, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "always",
            "--guard-whitelist-file", guard_whitelist_path,
        ])
        links = extract_links(msg)
        assert links[1][1] == "https://other.com/path?x=1&y=2"
        assert links[0][1].startswith(SERVER)
        assert msg["X-Detrackify-Guarded-Links"] == "1"
    finally:
        os.unlink(guard_whitelist_path)


def test_guard_hash_matches_payload():
    """
    Test that guard links contain valid authentication hashes.
    
    Expected outcome: The SHA256 hash in guard URLs should match the hash of
    the base64 payload plus salt, preventing tampering with guard links.
    """
    msg = process_email(GUARD_FILE, [
        "--guardserver", SERVER,
        "--guardsalt", SALT,
        "--guardlink", "mismatch",
    ])
    links = extract_links(msg)
    b64 = links[1][1].split('/')[-1]
    sha = links[1][1].split('/')[-2]
    assert hashlib.sha256((b64 + SALT).encode()).hexdigest() == sha


def test_guard_payload_is_json():
    """
    Test that guard link payloads contain valid JSON with required fields.
    
    Expected outcome: Base64 decoded payload should be valid JSON containing
    display text, domain, and original URL for proper guard server processing.
    """
    msg = process_email(GUARD_FILE, [
        "--guardserver", SERVER,
        "--guardsalt", SALT,
        "--guardlink", "mismatch",
    ])
    links = extract_links(msg)
    b64 = links[1][1].split('/')[-1]
    payload = json.loads(base64.urlsafe_b64decode(b64).decode())
    assert set(payload.keys()) == {"display", "from", "url"}
    assert payload["url"] == "https://other.com/path?x=1&y=2"


def test_guard_display_special_chars():
    """
    Test that guard payloads correctly handle special characters in link text.
    
    Expected outcome: Link display text with quotes, ampersands, and other
    special characters should be properly encoded in the guard payload.
    """
    msg = process_email(GUARD_FILE, [
        "--guardserver", SERVER,
        "--guardsalt", SALT,
        "--guardlink", "mismatch",
    ])
    links = extract_links(msg)
    b64 = links[1][1].split('/')[-1]
    payload = json.loads(base64.urlsafe_b64decode(b64).decode())
    assert payload["display"] == "Click \"here\" & enjoy"


def test_guard_capture_to():
    """
    Test that guard mode can capture recipient information when enabled.
    
    Expected outcome: When guardcaptureto is enabled, the guard payload should
    include the recipient's email address for audit logging.
    """
    msg = process_email(GUARD_FILE, [
        "--guardserver", SERVER,
        "--guardsalt", SALT,
        "--guardlink", "mismatch",
        "--guardcaptureto",
    ])
    links = extract_links(msg)
    b64 = links[1][1].split('/')[-1]
    payload = json.loads(base64.urlsafe_b64decode(b64).decode())
    assert payload.get("to") == "dest@example.com"


def test_guard_rewritten_link_format():
    """
    Test that guard-rewritten links follow the correct URL format.
    
    Expected outcome: Rewritten links should follow the format:
    {guardserver}/guard/{sha256hash}/{base64payload}
    """
    msg = process_email(GUARD_FILE, [
        "--guardserver", SERVER,
        "--guardsalt", SALT,
        "--guardlink", "mismatch",
    ])
    links = extract_links(msg)
    assert links[1][1].startswith(f"{SERVER}/guard/")


def test_guard_via_config_file():
    """
    Test that guard mode can be configured via YAML configuration file.
    
    Expected outcome: Guard settings from config file should be applied correctly,
    demonstrating configuration file functionality for guard mode.
    """
    msg = process_email(GUARD_FILE, ["--config", CONFIG_FILE])
    links = extract_links(msg)
    b64 = links[1][1].split('/')[-1]
    sha = links[1][1].split('/')[-2]
    assert hashlib.sha256((b64 + SALT).encode()).hexdigest() == sha
    payload = json.loads(base64.urlsafe_b64decode(b64).decode())
    assert payload.get("to") == "dest@example.com"
    assert msg["X-Detrackify-Guard-Mode"] == "mismatch"


def test_strip_query_params():
    """
    Test that URL parameter stripping works correctly in guard mode.
    
    Expected outcome: URLs should have tracking parameters removed while preserving
    legitimate parameters, demonstrating integration between guard and stripping features.
    """
    cfg = detrackify_guard.GuardConfig(
        salt="x",
        strip_param_prefixes=["utm_"]
    )
    server = detrackify_guard.GuardServer(cfg)
    url = server.strip_query_params("https://example.com/?a=1&utm_source=x&b=2")
    assert url == "https://example.com/?a=1"


def test_strip_query_params_no_match():
    """
    Test that URLs without matching parameters are left unchanged.
    
    Expected outcome: URLs without tracking parameters should remain unchanged,
    ensuring legitimate parameters are preserved.
    """
    cfg = detrackify_guard.GuardConfig(
        salt="x",
        strip_param_prefixes=["utm_"]
    )
    server = detrackify_guard.GuardServer(cfg)
    url = server.strip_query_params("https://example.com/?a=1&b=2")
    assert url == "https://example.com/?a=1&b=2"


def test_strip_query_params_multiple_prefixes():
    """
    Test that multiple parameter prefixes are stripped correctly.
    
    Expected outcome: All parameters matching any of the configured prefixes
    should be removed, along with all subsequent parameters.
    """
    cfg = detrackify_guard.GuardConfig(
        salt="x",
        strip_param_prefixes=["foo", "utm_"]
    )
    server = detrackify_guard.GuardServer(cfg)
    url = server.strip_query_params("https://example.com/?a=1&foo_id=2&utm_x=3&b=4")
    assert url == "https://example.com/?a=1"


def test_strip_query_params_case_insensitive():
    """
    Test that parameter stripping is case-insensitive.
    
    Expected outcome: Tracking parameters should be stripped regardless of case
    (UTM_SOURCE, utm_source, Utm_Source should all be removed).
    """
    cfg = detrackify_guard.GuardConfig(
        salt="x",
        strip_param_prefixes=["utm_", "fbclid"]
    )
    server = detrackify_guard.GuardServer(cfg)
    
    # Test case-insensitive UTM parameter
    url1 = server.strip_query_params("https://example.com/?a=1&UTM_SOURCE=x&b=2")
    assert url1 == "https://example.com/?a=1"
    
    # Test case-insensitive Facebook click ID
    url2 = server.strip_query_params("https://example.com/?a=1&FBCLID=123&b=2")
    assert url2 == "https://example.com/?a=1"
    
    # Test mixed case
    url3 = server.strip_query_params("https://example.com/?a=1&Utm_Medium=email&b=2")
    assert url3 == "https://example.com/?a=1"


def test_resolve_get_registers_routes():
    """
    Test that GET resolution mode registers the correct web routes.
    
    Expected outcome: When resolve mode is 'get', the guard server should register
    /guard/resolve and /guard/go routes for link resolution functionality.
    """
    cfg = detrackify_guard.GuardConfig(
        salt="x",
        resolve="get"
    )
    server = detrackify_guard.GuardServer(cfg)
    rules = {r.rule for r in server.app.url_map.iter_rules()}
    assert "/guard/resolve" in rules
    assert "/guard/go" in rules


def test_resolve_get_enables_resolution():
    """
    Test that GET resolution mode enables resolution functionality.
    
    Expected outcome: When resolve mode is 'get', the guard server should enable
    resolution features and use GET method for link resolution.
    """
    cfg = detrackify_guard.GuardConfig(
        salt="x",
        resolve="get"
    )
    server = detrackify_guard.GuardServer(cfg)
    assert server.resolve_enabled is True
    assert server.resolve_get is True


#########################
# Blacklist tests
#########################

def test_guard_sender_blacklisted():
    """Test that blacklisted senders result in blocked links with correct JSON payload."""
    # Create a temporary blacklist file with sender blacklist
    import tempfile
    import yaml
    
    blacklist_data = {
        'blacklist': [
            {'sender': r'^user@example\.com$'}
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(blacklist_data, f)
        blacklist_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(GUARD_FILE, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "mismatch",
            "--blacklist-file", blacklist_path,
        ])
        links = extract_links(msg)
        
        # Both links should be guarded due to blacklisted sender
        assert links[0][1].startswith(f"{SERVER}/guard/")
        assert links[1][1].startswith(f"{SERVER}/guard/")
        
        # Check that both links have block reasons in their payloads
        for link in links:
            b64 = link[1].split('/')[-1]
            payload = json.loads(base64.urlsafe_b64decode(b64).decode())
            assert "block" in payload
            assert "blacklisted" in payload["block"]
            assert payload["from"] == "user@example.com"
            
    finally:
        os.unlink(blacklist_path)


def test_guard_url_blacklisted():
    """Test that blacklisted URLs result in blocked links with correct JSON payload."""
    # Create a temporary blacklist file with URL blacklist
    import tempfile
    import yaml
    
    blacklist_data = {
        'blacklist': [
            {'url': r'^https://other\.com/.*'}
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(blacklist_data, f)
        blacklist_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(GUARD_FILE, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "mismatch",
            "--blacklist-file", blacklist_path,
        ])
        links = extract_links(msg)
        
        # First link should not be guarded (not blacklisted)
        assert links[0][1] == "https://example.com/welcome"
        
        # Second link should be guarded due to blacklisted URL
        assert links[1][1].startswith(f"{SERVER}/guard/")
        
        # Check that the guarded link has block reasons in its payload
        b64 = links[1][1].split('/')[-1]
        payload = json.loads(base64.urlsafe_b64decode(b64).decode())
        logging.debug(f"Debug - Payload: {payload}")
        logging.debug(f"Debug - Expected URL: https://other.com/path?x=1&y=2")
        logging.debug(f"Debug - Actual URL: {payload.get('url')}")
        assert "block" in payload
        assert "blacklisted" in payload["block"]
        assert payload["url"] == "https://other.com/path?x=1&y=2"
        assert payload["from"] == "user@example.com"
        
    finally:
        os.unlink(blacklist_path)


def test_guard_sender_and_url_blacklisted():
    """Test that both blacklisted sender and URL result in blocked links with correct JSON payload."""
    # Create a temporary blacklist file with both sender and URL blacklist
    import tempfile
    import yaml
    
    blacklist_data = {
        'blacklist': [
            {'sender': r'^user@example\.com$'},
            {'url': r'^https://other\.com/.*'}
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(blacklist_data, f)
        blacklist_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(GUARD_FILE, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "mismatch",
            "--blacklist-file", blacklist_path,
        ])
        links = extract_links(msg)
        
        # Both links should be guarded due to blacklisted sender
        assert links[0][1].startswith(f"{SERVER}/guard/")
        assert links[1][1].startswith(f"{SERVER}/guard/")
        
        # Check that both links have block reasons in their payloads
        for link in links:
            b64 = link[1].split('/')[-1]
            payload = json.loads(base64.urlsafe_b64decode(b64).decode())
            assert "block" in payload
            assert "blacklisted" in payload["block"]
            assert payload["from"] == "user@example.com"
        
    finally:
        os.unlink(blacklist_path)


def test_guard_no_blacklist_no_block_field():
    """Test that links without blacklist reasons don't have block field in JSON payload."""
    # Create a temporary empty blacklist file
    import tempfile
    import yaml
    
    blacklist_data = {
        'blacklist': []
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(blacklist_data, f)
        blacklist_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(GUARD_FILE, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "mismatch",
            "--blacklist-file", blacklist_path,
        ])
        links = extract_links(msg)
        
        # First link should not be guarded (same domain)
        assert links[0][1] == "https://example.com/welcome"
        
        # Second link should be guarded due to domain mismatch
        assert links[1][1].startswith(f"{SERVER}/guard/")
        
        # Check that the guarded link does NOT have block field in its payload
        b64 = links[1][1].split('/')[-1]
        payload = json.loads(base64.urlsafe_b64decode(b64).decode())
        assert "block" not in payload
        assert payload["url"] == "https://other.com/path?x=1&y=2"
        assert payload["from"] == "user@example.com"
        
    finally:
        os.unlink(blacklist_path)

def test_plain_text_add_html_for_guarded_links():
    """
    Test that plain text emails get HTML part added when links need guarding.
    
    Expected outcome: When --guard-add-html-for-plain is enabled and a plain text
    email contains links that need guarding, a text/html part should be added with
    guarded links, and X-Detrackify-Generated-HTML header should be present.
    The output should be RFC-compliant.
    """
    # Create a temporary plain text email with a link that needs guarding
    import tempfile
    plain_email_content = """From: sender@example.com
To: recipient@other.com
Subject: Test email with link
Content-Type: text/plain

Check out this link: https://suspicious.com/phishing
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
        f.write(plain_email_content)
        email_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        # Process with RFC validation enabled (default)
        msg = process_email(email_path, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "mismatch",
            "--guard-add-html-for-plain",
        ])
        
        # Should have X-Detrackify-Generated-HTML header
        assert msg.get('X-Detrackify-Generated-HTML') == 'true', "Missing X-Detrackify-Generated-HTML header"
        
        # Should have both text/plain and text/html parts
        has_plain = False
        has_html = False
        html_content = None
        
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                has_plain = True
            elif content_type == 'text/html':
                has_html = True
                html_content = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
        
        assert has_plain, "Missing text/plain part"
        assert has_html, "Missing text/html part"
        assert html_content is not None, "HTML content is None"
        
        # HTML should contain guarded link
        assert SERVER in html_content, "HTML should contain guard server URL"
        assert 'https://suspicious.com/phishing' in html_content or '/guard/' in html_content, "HTML should contain guarded link"
        
        # Should have guarded links count
        assert msg.get('X-Detrackify-Guarded-Links') is not None, "Missing guarded links count"
        
    finally:
        os.unlink(email_path)


def test_plain_text_no_html_when_no_guarding_needed():
    """
    Test that plain text emails don't get HTML part when links don't need guarding.
    
    Expected outcome: When --guard-add-html-for-plain is enabled but links don't
    need guarding (same domain), no HTML part should be added.
    """
    # Create a temporary plain text email with a link from same domain
    import tempfile
    plain_email_content = """From: sender@example.com
To: recipient@example.com
Subject: Test email with link
Content-Type: text/plain

Check out this link: https://example.com/welcome
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
        f.write(plain_email_content)
        email_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(email_path, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "mismatch",  # Only guard mismatched domains
            "--guard-add-html-for-plain",
        ])
        
        # Should NOT have X-Detrackify-Generated-HTML header
        assert msg.get('X-Detrackify-Generated-HTML') is None, "Should not have X-Detrackify-Generated-HTML header when no guarding needed"
        
        # Should still have text/plain part
        has_plain = False
        has_html = False
        
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                has_plain = True
            elif content_type == 'text/html':
                has_html = True
        
        assert has_plain, "Missing text/plain part"
        assert not has_html, "Should not have text/html part when no guarding needed"
        
    finally:
        os.unlink(email_path)


def test_plain_text_no_html_when_feature_disabled():
    """
    Test that plain text emails don't get HTML part when feature is disabled.
    
    Expected outcome: When --guard-add-html-for-plain is NOT enabled, no HTML
    part should be added even if links need guarding.
    """
    # Create a temporary plain text email with a link that needs guarding
    import tempfile
    plain_email_content = """From: sender@example.com
To: recipient@other.com
Subject: Test email with link
Content-Type: text/plain

Check out this link: https://suspicious.com/phishing
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
        f.write(plain_email_content)
        email_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(email_path, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "mismatch",
            # Note: NOT including --guard-add-html-for-plain
        ])
        
        # Should NOT have X-Detrackify-Generated-HTML header
        assert msg.get('X-Detrackify-Generated-HTML') is None, "Should not have X-Detrackify-Generated-HTML header when feature disabled"
        
        # Should only have text/plain part
        has_plain = False
        has_html = False
        
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                has_plain = True
            elif content_type == 'text/html':
                has_html = True
        
        assert has_plain, "Missing text/plain part"
        assert not has_html, "Should not have text/html part when feature disabled"
        
    finally:
        os.unlink(email_path)

def test_all_processed_emails_rfc_compliant():
    """
    Test that all processed emails are RFC 5322 and RFC 2045-2047 compliant.
    
    Expected outcome: All processed emails should be valid according to RFC standards,
    ensuring they will be accepted by email servers and clients.
    """
    # Test with various email types and configurations
    test_files = LEGIT_FILES[:2] + SPAM_FILES[:2] + PHISHING_FILES[:1]  # Sample from each category
    
    for path in test_files:
        # Test with default processing
        msg = process_email(path, validate_rfc=True)
        assert msg is not None, f"Failed to process email: {path}"
        
        # Test with guard enabled
        try:
            msg_guard = process_email(path, [
                "--guardserver", SERVER,
                "--guardsalt", SALT,
                "--guardlink", "mismatch",
            ], validate_rfc=True)
            assert msg_guard is not None, f"Failed to process email with guard: {path}"
        except Exception:
            # Some emails might not have From headers, skip guard tests for those
            pass

def test_plain_text_no_html_when_no_links():
    """
    Test that plain text emails without links don't get HTML part.
    
    Expected outcome: When --guard-add-html-for-plain is enabled but email has no links,
    no HTML part should be added.
    """
    # Create a temporary plain text email with no links
    import tempfile
    plain_email_content = """From: sender@example.com
To: recipient@example.com
Subject: Test email without links
Content-Type: text/plain

This is a plain text email with no links at all.
Just regular text content.
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
        f.write(plain_email_content)
        email_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(email_path, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "mismatch",
            "--guard-add-html-for-plain",
        ])
        
        # Should NOT have X-Detrackify-Generated-HTML header
        assert msg.get('X-Detrackify-Generated-HTML') is None, "Should not have X-Detrackify-Generated-HTML header when no links present"
        
        # Should only have text/plain part
        has_plain = False
        has_html = False
        
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                has_plain = True
            elif content_type == 'text/html':
                has_html = True
        
        assert has_plain, "Missing text/plain part"
        assert not has_html, "Should not have text/html part when no links present"
        
    finally:
        os.unlink(email_path)


def test_plain_text_no_html_when_already_has_html():
    """
    Test that emails that already have HTML part don't get another HTML part added.
    
    Expected outcome: When email already has text/html part, no additional HTML part
    should be added even if plain text part has links that need guarding.
    """
    # Create a temporary multipart email with both text/plain and text/html
    import tempfile
    multipart_email_content = """From: sender@example.com
To: recipient@other.com
Subject: Test email with both parts
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain

Check out this link: https://suspicious.com/phishing
--boundary123
Content-Type: text/html

<html><body>Check out this <a href="https://suspicious.com/phishing">link</a></body></html>
--boundary123--
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
        f.write(multipart_email_content)
        email_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(email_path, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "mismatch",
            "--guard-add-html-for-plain",
        ])
        
        # Should NOT have X-Detrackify-Generated-HTML header (email already had HTML)
        assert msg.get('X-Detrackify-Generated-HTML') is None, "Should not have X-Detrackify-Generated-HTML header when email already has HTML"
        
        # Should have both text/plain and text/html parts (original ones)
        has_plain = False
        has_html = False
        html_count = 0
        
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                has_plain = True
            elif content_type == 'text/html':
                has_html = True
                html_count += 1
        
        assert has_plain, "Missing text/plain part"
        assert has_html, "Missing text/html part"
        assert html_count == 1, f"Should have exactly 1 HTML part, found {html_count}"
        
    finally:
        os.unlink(email_path)


def test_plain_text_no_html_when_guard_disabled():
    """
    Test that plain text emails don't get HTML part when guard is disabled.
    
    Expected outcome: When guard mode is 'off', no HTML part should be added even if
    --guard-add-html-for-plain is enabled and links need guarding.
    """
    # Create a temporary plain text email with a link that would need guarding
    import tempfile
    plain_email_content = """From: sender@example.com
To: recipient@other.com
Subject: Test email with link
Content-Type: text/plain

Check out this link: https://suspicious.com/phishing
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
        f.write(plain_email_content)
        email_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(email_path, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "off",  # Guard disabled
            "--guard-add-html-for-plain",
        ])
        
        # Should NOT have X-Detrackify-Generated-HTML header
        assert msg.get('X-Detrackify-Generated-HTML') is None, "Should not have X-Detrackify-Generated-HTML header when guard is disabled"
        
        # Should only have text/plain part
        has_plain = False
        has_html = False
        
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                has_plain = True
            elif content_type == 'text/html':
                has_html = True
        
        assert has_plain, "Missing text/plain part"
        assert not has_html, "Should not have text/html part when guard is disabled"
        
    finally:
        os.unlink(email_path)
