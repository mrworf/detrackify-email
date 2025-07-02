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
from bs4 import BeautifulSoup

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
    subprocess.run(["pylint", "-E", SCRIPT], check=True)


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
    sha = hashlib.sha1((b64 + SALT).encode()).hexdigest()
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
    sha1 = hashlib.sha1((payload1 + SALT).encode()).hexdigest()
    expected1 = f"{SERVER}/guard/{sha1}/{payload1}"
    payload2 = base64.urlsafe_b64encode(json.dumps({
        "display": "Click \"here\" & enjoy",
        "domain": "example.com",
        "url": "https://other.com/path?x=1&y=2",
    }).encode()).decode()
    sha2 = hashlib.sha1((payload2 + SALT).encode()).hexdigest()
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
    assert hashlib.sha1((b64 + SALT).encode()).hexdigest() == sha


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
    assert hashlib.sha1((b64 + SALT).encode()).hexdigest() == sha
    payload = json.loads(base64.urlsafe_b64decode(b64).decode())
    assert payload.get("to") == "dest@example.com"
    assert msg["X-Detrackify-Guard-Mode"] == "mismatch"
