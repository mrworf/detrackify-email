"""Integration tests for detrackify_email."""

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
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import detrackify_guard

# Path to the script under test
SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "detrackify_email.py")


def process_email(path, extra_args=None):
    """Run the script on the provided path and return the resulting message."""
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
        with open(tmp_path, "rb") as fd:
            return email.message_from_bytes(fd.read())
    finally:
        os.remove(tmp_path)


def has_tracking(msg):
    headers = msg.get_all('X-Detrackify-Blocked') or []
    return any('No tracking pixels' not in h for h in headers)


SPAM_FILES = sorted(glob.glob(os.path.join('tests', 'content', 'spam*.eml')))
CLEAN_FILES = sorted(glob.glob(os.path.join('tests', 'content', 'clean*.eml')))


def test_spam_emails():
    for path in SPAM_FILES:
        msg = process_email(path)
        assert has_tracking(msg), f'{path} not flagged'


def test_clean_emails():
    for path in CLEAN_FILES:
        msg = process_email(path)
        headers = msg.get_all('X-Detrackify-Blocked')
        assert headers and all('No tracking pixels' in h for h in headers), f'{path} incorrectly flagged'


def test_pylint():
    """Ensure the code passes pylint."""
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
    msg = process_email(GUARD_FILE, ["--guardserver", SERVER, "--guardsalt", SALT])
    links = extract_links(msg)
    assert links[0][1] == "https://example.com/welcome"
    assert links[1][1] == "https://other.com/path?x=1&y=2"
    assert msg.get("X-Detrackify-Guarded-Links") is None


def test_guard_mismatch_only_changes_mismatched():
    msg = process_email(GUARD_FILE, [
        "--guardserver", SERVER,
        "--guardsalt", SALT,
        "--guardlink", "mismatch",
    ])
    links = extract_links(msg)
    assert links[0][1] == "https://example.com/welcome"
    b64 = base64.urlsafe_b64encode(json.dumps({
        "display": "Click \"here\" & enjoy",
        "domain": "example.com",
        "url": "https://other.com/path?x=1&y=2",
    }).encode()).decode()
    sha = hashlib.sha256((b64 + SALT).encode()).hexdigest()
    expected = f"{SERVER}/guard/{sha}/{b64}"
    assert links[1][1] == expected
    assert msg["X-Detrackify-Guarded-Links"] == "1"
    assert msg["X-Detrackify-Guard-Mode"] == "mismatch"


def test_guard_all_changes_all():
    msg = process_email(GUARD_FILE, [
        "--guardserver", SERVER,
        "--guardsalt", SALT,
        "--guardlink", "always",
    ])
    links = extract_links(msg)
    payload1 = base64.urlsafe_b64encode(json.dumps({
        "display": "Welcome",
        "domain": "example.com",
        "url": "https://example.com/welcome",
    }).encode()).decode()
    sha1 = hashlib.sha256((payload1 + SALT).encode()).hexdigest()
    expected1 = f"{SERVER}/guard/{sha1}/{payload1}"
    payload2 = base64.urlsafe_b64encode(json.dumps({
        "display": "Click \"here\" & enjoy",
        "domain": "example.com",
        "url": "https://other.com/path?x=1&y=2",
    }).encode()).decode()
    sha2 = hashlib.sha256((payload2 + SALT).encode()).hexdigest()
    expected2 = f"{SERVER}/guard/{sha2}/{payload2}"
    assert links[0][1] == expected1
    assert links[1][1] == expected2
    assert msg["X-Detrackify-Guarded-Links"] == "2"
    assert msg["X-Detrackify-Guard-Mode"] == "always"


def test_guard_whitelist_sender():
    msg = process_email(GUARD_FILE, [
        "--guardserver", SERVER,
        "--guardsalt", SALT,
        "--guardlink", "always",
        "--guardwhitelistsender", "^user@example\\.com$",
    ])
    links = extract_links(msg)
    assert links[0][1] == "https://example.com/welcome"
    assert links[1][1] == "https://other.com/path?x=1&y=2"
    assert msg["X-Detrackify-Guarded-Links"] == "0"


def test_guard_whitelist_link():
    msg = process_email(GUARD_FILE, [
        "--guardserver", SERVER,
        "--guardsalt", SALT,
        "--guardlink", "always",
        "--guardwhitelink", "^https://other\\.com",
    ])
    links = extract_links(msg)
    assert links[1][1] == "https://other.com/path?x=1&y=2"
    assert links[0][1].startswith(SERVER)
    assert msg["X-Detrackify-Guarded-Links"] == "1"


def test_guard_hash_matches_payload():
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
    msg = process_email(GUARD_FILE, [
        "--guardserver", SERVER,
        "--guardsalt", SALT,
        "--guardlink", "mismatch",
    ])
    links = extract_links(msg)
    b64 = links[1][1].split('/')[-1]
    payload = json.loads(base64.urlsafe_b64decode(b64).decode())
    assert set(payload.keys()) == {"display", "domain", "url"}
    assert payload["url"] == "https://other.com/path?x=1&y=2"


def test_guard_display_special_chars():
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
    msg = process_email(GUARD_FILE, [
        "--guardserver", SERVER,
        "--guardsalt", SALT,
        "--guardlink", "mismatch",
    ])
    links = extract_links(msg)
    assert links[1][1].startswith(f"{SERVER}/guard/")


def test_guard_via_config_file():
    msg = process_email(GUARD_FILE, ["--config", CONFIG_FILE])
    links = extract_links(msg)
    b64 = links[1][1].split('/')[-1]
    sha = links[1][1].split('/')[-2]
    assert hashlib.sha256((b64 + SALT).encode()).hexdigest() == sha
    payload = json.loads(base64.urlsafe_b64decode(b64).decode())
    assert payload.get("to") == "dest@example.com"
    assert msg["X-Detrackify-Guard-Mode"] == "mismatch"


def test_strip_query_params():
    from guard.utils import GuardUtils
    url = GuardUtils.strip_query_parameters("https://example.com/?a=1&utm_source=x&b=2", ["utm_"])
    assert url == "https://example.com/?a=1"


def test_strip_query_params_no_match():
    from guard.utils import GuardUtils
    url = GuardUtils.strip_query_parameters("https://example.com/?a=1&b=2", ["utm_"])
    assert url == "https://example.com/?a=1&b=2"


def test_strip_query_params_multiple_prefixes():
    from guard.utils import GuardUtils
    url = GuardUtils.strip_query_parameters("https://example.com/?a=1&foo_id=2&utm_x=3&b=4", ["foo", "utm_"])
    assert url == "https://example.com/?a=1"


def test_resolve_get_registers_routes():
    cfg = detrackify_guard.GuardConfig(
        salt="x",
        resolve="get"
    )
    server = detrackify_guard.GuardServer(cfg)
    rules = {r.rule for r in server.app.url_map.iter_rules()}
    assert "/guard/resolve" in rules
    assert "/guard/go" in rules


def test_resolve_get_enables_resolution():
    cfg = detrackify_guard.GuardConfig(
        salt="x",
        resolve="get"
    )
    server = detrackify_guard.GuardServer(cfg)
    assert server.resolve_enabled is True
    assert server.resolve_get is True


#########################
# Blocklist tests
#########################

def test_guard_sender_blacklisted():
    """Test that blacklisted senders result in blocked links with correct JSON payload."""
    # Create a temporary blocklist file with sender blacklist
    import tempfile
    import yaml
    
    blocklist_data = {
        'whitelist': [],
        'blacklisted': [
            {'sender': r'^user@example\.com$'}
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(blocklist_data, f)
        blocklist_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(GUARD_FILE, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "mismatch",
            "--blocklistfile", blocklist_path,
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
            assert payload["domain"] == "example.com"
            
    finally:
        os.unlink(blocklist_path)


def test_guard_url_blacklisted():
    """Test that blacklisted URLs result in blocked links with correct JSON payload."""
    # Create a temporary blocklist file with URL blacklist
    import tempfile
    import yaml
    
    blocklist_data = {
        'whitelist': [],
        'blacklisted': [
            {'url': r'^https://other\.com/.*'}
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(blocklist_data, f)
        blocklist_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(GUARD_FILE, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "mismatch",
            "--blocklistfile", blocklist_path,
        ])
        links = extract_links(msg)
        
        # First link should not be guarded (not blacklisted)
        assert links[0][1] == "https://example.com/welcome"
        
        # Second link should be guarded due to blacklisted URL
        assert links[1][1].startswith(f"{SERVER}/guard/")
        
        # Check that the guarded link has block reasons in its payload
        b64 = links[1][1].split('/')[-1]
        payload = json.loads(base64.urlsafe_b64decode(b64).decode())
        print(f"Debug - Payload: {payload}")
        print(f"Debug - Expected URL: https://other.com/path?x=1&y=2")
        print(f"Debug - Actual URL: {payload.get('url')}")
        assert "block" in payload
        assert "blacklisted" in payload["block"]
        assert payload["url"] == "https://other.com/path?x=1&y=2"
        assert payload["domain"] == "example.com"
        
    finally:
        os.unlink(blocklist_path)


def test_guard_sender_and_url_blacklisted():
    """Test that both blacklisted sender and URL result in blocked links with correct JSON payload."""
    # Create a temporary blocklist file with both sender and URL blacklist
    import tempfile
    import yaml
    
    blocklist_data = {
        'whitelist': [],
        'blacklisted': [
            {'sender': r'^user@example\.com$'},
            {'url': r'^https://other\.com/.*'}
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(blocklist_data, f)
        blocklist_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(GUARD_FILE, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "mismatch",
            "--blocklistfile", blocklist_path,
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
            assert payload["domain"] == "example.com"
        
    finally:
        os.unlink(blocklist_path)


def test_guard_no_blocklist_no_block_field():
    """Test that links without blocklist reasons don't have block field in JSON payload."""
    # Create a temporary empty blocklist file
    import tempfile
    import yaml
    
    blocklist_data = {
        'whitelist': [],
        'blacklisted': []
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(blocklist_data, f)
        blocklist_path = f.name
        f.flush()
        os.fsync(f.fileno())
    
    try:
        msg = process_email(GUARD_FILE, [
            "--guardserver", SERVER,
            "--guardsalt", SALT,
            "--guardlink", "mismatch",
            "--blocklistfile", blocklist_path,
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
        assert payload["domain"] == "example.com"
        
    finally:
        os.unlink(blocklist_path)
