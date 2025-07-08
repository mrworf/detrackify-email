#!/usr/bin/env python3
"""Simple test for blacklist functionality."""

import sys
import os
import yaml
import re

# Add the current directory to the Python path so we can import detrackify_email
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detrackify_email.configuration import Configuration

def test_blacklist():
    """Test blacklist functionality."""
    print("Testing blacklist functionality...")
    
    # Create test whitelist and blacklist YAMLs
    test_whitelist_yaml = '''
whitelist:
  - url: 'https://trusted.example.com/logo.png'
  - url: 'https://cdn.example.org/.*'
'''
    test_blacklist_yaml = '''
blacklist:
  - sender: '^spam@malicious\\.com$'
  - sender: '^test.*@example\\.org$'
  - url: '^https://malicious\\.com/.*'
  - url: '^https://.*\\.phishing\\.net/.*'
'''
    # Write to temporary files
    with open('test_whitelist.yml', 'w') as f:
        f.write(test_whitelist_yaml)
    with open('test_blacklist.yml', 'w') as f:
        f.write(test_blacklist_yaml)

    # Test configuration
    config = Configuration()
    config.set(Configuration.CFG_WHITELIST_FILE, 'test_whitelist.yml')
    config.set(Configuration.CFG_BLACKLIST_FILE, 'test_blacklist.yml')
    config.load_whitelist_from_file()
    config.load_blacklist_from_file()
    
    # Test whitelist
    print("Testing whitelist...")
    assert config.is_whitelisted('https://trusted.example.com/logo.png')
    assert config.is_whitelisted('https://cdn.example.org/some/path')
    print("✓ Whitelist working correctly")
    
    # Test sender blacklist
    print("Testing sender blacklist...")
    assert config.is_sender_blacklisted('spam@malicious.com')
    assert config.is_sender_blacklisted('test123@example.org')
    assert not config.is_sender_blacklisted('good@example.com')
    print("✓ Sender blacklist working correctly")
    
    # Test URL blacklist
    print("Testing URL blacklist...")
    assert config.is_blacklisted('https://malicious.com/evil')
    assert config.is_blacklisted('https://sub.phishing.net/bad')
    assert not config.is_blacklisted('https://good.example.com/safe')
    print("✓ URL blacklist working correctly")
    
    # Clean up
    os.remove('test_whitelist.yml')
    os.remove('test_blacklist.yml')
    
    print("All tests passed! ✓")

def test_url_blacklist_specific():
    """Test specific URL blacklist pattern that matches the test case."""
    print("Testing specific URL blacklist pattern...")
    
    test_blacklist_yaml = '''
blacklist:
  - url: '^https://other\\.com/.*'
'''
    with open('test_blacklist.yml', 'w') as f:
        f.write(test_blacklist_yaml)

    config = Configuration()
    config.set(Configuration.CFG_BLACKLIST_FILE, 'test_blacklist.yml')
    config.config['blacklist'] = []
    config.config['whitelist'] = []
    config.load_blacklist_from_file()
    
    test_url = 'https://other.com/path?x=1&y=2'
    result = config.is_blacklisted(test_url)
    print(f"URL: {test_url}")
    print(f"Blacklisted: {result}")
    print(f"Blacklist entries: {config.config.get('blacklist', [])}")
    
    for entry in config.config.get('blacklist', []):
        if isinstance(entry, dict) and 'url' in entry:
            pattern = entry['url'].replace('\\', '\\')
            print(f"Testing pattern: {repr(pattern)} against {repr(test_url)}")
            match = re.match(pattern, test_url)
            fullmatch = re.fullmatch(pattern, test_url)
            print(f"re.match result: {match}")
            print(f"re.fullmatch result: {fullmatch}")
    
    assert result, f"URL {test_url} should be blacklisted"
    print("✓ Specific URL blacklist working correctly")
    
    os.remove('test_blacklist.yml')

def test_sender_blacklist():
    """Test sender blacklist functionality."""
    print("Testing sender blacklist pattern...")
    
    # Create a temporary blacklist with sender blacklist
    blacklist_data = {
        'blacklist': [
            {'sender': '^user@example\\.com$'}
        ]
    }
    
    # Create temporary file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(blacklist_data, f)
        blacklist_path = f.name
    
    try:
        # Create configuration and clear any default blocklist/whitelist
        config = Configuration()
        config.config['blacklist'] = []
        config.config['whitelist'] = []
        config.set(Configuration.CFG_BLACKLIST_FILE, blacklist_path)
        config.load_blacklist_from_file()
        
        # Test sender blacklist detection
        test_sender = "user@example.com"
        is_blacklisted = config.is_sender_blacklisted(test_sender)
        
        print(f"Sender: {test_sender}")
        print(f"Blacklisted: {is_blacklisted}")
        print(f"Blacklist entries: {config.config.get('blacklist', [])}")
        
        # Test the regex pattern directly
        sender_found = False
        for entry in config.config.get('blacklist', []):
            if isinstance(entry, dict) and 'sender' in entry:
                pattern = entry['sender']
                print(f"Testing pattern: '{pattern}' against '{test_sender}'")
                match_result = re.match(pattern, test_sender)
                print(f"re.match result: {match_result}")
                sender_found = True
                assert match_result, f"Sender {test_sender} should match pattern {pattern}"
                break
        
        assert sender_found, "No sender blacklist entries found"
        assert is_blacklisted, f"Sender {test_sender} should be blacklisted"
        print("✓ Sender blacklist working correctly")
        
    finally:
        # Clean up temporary file
        os.unlink(blacklist_path)

if __name__ == '__main__':
    # Only run the specific test for clarity
    test_url_blacklist_specific()
    
    # Test sender blacklist
    test_sender_blacklist() 