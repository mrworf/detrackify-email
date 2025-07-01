"""Integration tests for detrackify_email."""

import email
import glob
import os
import subprocess
import sys
import tempfile

# Path to the script under test
SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "detrackify_email.py")


def process_email(path):
    """Run the script on the provided path and return the resulting message."""
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
