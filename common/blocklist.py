"""
Common blocklist/whitelist functionality for detrackify.
"""

import logging
import yaml
import re
from typing import List, Dict, Any, Optional
from common.utils import SharedUtils


class Blocklist:
    """Common class for handling blacklists and whitelists with URL and sender patterns."""
    
    def __init__(self, file_path: Optional[str] = None, list_type: str = 'blacklist'):
        """
        Initialize blocklist/whitelist.
        
        Args:
            file_path: Path to YAML file containing the list
            list_type: Type of list ('blacklist' or 'whitelist')
        """
        self.file_path = file_path
        self.list_type = list_type
        self.entries = []
        self._load_from_file()
    
    def _load_from_file(self) -> None:
        """Load entries from the configured file."""
        if not self.file_path:
            return
        
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    entries = data.get(self.list_type, [])
                    if isinstance(entries, list):
                        self.entries = entries
                        logging.info(f'Loaded {len(entries)} {self.list_type} entries from {self.file_path}')
                    else:
                        logging.warning(f'Invalid {self.list_type} format in {self.file_path}')
                else:
                    logging.warning(f'Invalid {self.list_type} file format: {self.file_path}')
        except FileNotFoundError:
            logging.warning(f'{self.list_type.capitalize()} file not found: {self.file_path}')
        except yaml.YAMLError as e:
            logging.error(f'Error parsing {self.list_type} file {self.file_path}: {e}')
        except Exception as e:
            logging.error(f'Error loading {self.list_type} file {self.file_path}: {e}')
    
    def reload(self) -> None:
        """Reload entries from file."""
        self._load_from_file()
    
    def is_url_blacklisted(self, url: str) -> bool:
        """Check if URL is blacklisted."""
        if self.list_type != 'blacklist':
            return False
        
        for entry in self.entries:
            if isinstance(entry, dict) and 'url' in entry:
                if SharedUtils.test_url_against_patterns(url, [entry['url']], self.list_type):
                    return True
            elif isinstance(entry, str):
                if SharedUtils.test_url_against_patterns(url, [entry], self.list_type):
                    return True
        return False
    
    def is_url_whitelisted(self, url: str) -> bool:
        """Check if URL is whitelisted."""
        if self.list_type != 'whitelist':
            return False
        
        for entry in self.entries:
            if isinstance(entry, dict) and 'url' in entry:
                if SharedUtils.test_url_against_patterns(url, [entry['url']], self.list_type):
                    return True
            elif isinstance(entry, str):
                if SharedUtils.test_url_against_patterns(url, [entry], self.list_type):
                    return True
        return False
    
    def is_sender_blacklisted(self, sender: str) -> bool:
        """Check if sender is blacklisted."""
        if self.list_type != 'blacklist' or not sender:
            return False
        
        for entry in self.entries:
            if isinstance(entry, dict) and 'sender' in entry:
                pattern = entry['sender']
                result = re.match(pattern, sender)
                logging.debug(f"Testing sender blacklist: pattern={pattern!r}, sender={sender!r}, match={result}")
                if result:
                    return True
        return False
    
    def is_sender_whitelisted(self, sender: str) -> bool:
        """Check if sender is whitelisted."""
        if self.list_type != 'whitelist' or not sender:
            return False
        
        for entry in self.entries:
            if isinstance(entry, dict) and 'sender' in entry:
                pattern = entry['sender']
                result = re.match(pattern, sender)
                if result:
                    return True
        return False
    
    def get_url_entries(self) -> List[str]:
        """Get all URL patterns from the list."""
        url_entries = []
        for entry in self.entries:
            if isinstance(entry, dict) and 'url' in entry:
                url_entries.append(entry['url'])
            elif isinstance(entry, str):
                url_entries.append(entry)
        return url_entries
    
    def get_sender_entries(self) -> List[str]:
        """Get all sender patterns from the list."""
        sender_entries = []
        for entry in self.entries:
            if isinstance(entry, dict) and 'sender' in entry:
                sender_entries.append(entry['sender'])
        return sender_entries
    
    def add_url_entry(self, url: str) -> bool:
        """Add a URL entry to the list."""
        if not self.is_url_blacklisted(url) if self.list_type == 'blacklist' else not self.is_url_whitelisted(url):
            logging.info(f'Adding {url} to {self.list_type}')
            self.entries.append({'url': url})
            return True
        return False
    
    def add_sender_entry(self, sender: str) -> bool:
        """Add a sender entry to the list."""
        if not self.is_sender_blacklisted(sender) if self.list_type == 'blacklist' else not self.is_sender_whitelisted(sender):
            logging.info(f'Adding {sender} to {self.list_type}')
            self.entries.append({'sender': sender})
            return True
        return False
    
    def get_entries(self) -> List[Dict[str, Any]]:
        """Get all entries in the list."""
        return self.entries.copy()
    
    def __len__(self) -> int:
        """Return the number of entries."""
        return len(self.entries) 