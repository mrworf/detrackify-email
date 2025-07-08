"""Blacklist management for the guard server."""
import yaml
import logging
import os
import re

class Blacklist:
    """Loads and manages blacklist from a YAML file."""
    def __init__(self, blacklist_file: str):
        self.blacklist_file = blacklist_file
        self.entries = []
        
        if not self.blacklist_file or not os.path.isfile(self.blacklist_file):
            logging.warning(f'Blacklist file not found: {self.blacklist_file}')
            return
            
        try:
            with open(self.blacklist_file, 'r', encoding='utf-8') as f:
                blacklist_data = yaml.safe_load(f)
                if isinstance(blacklist_data, dict) and 'blacklist' in blacklist_data:
                    # Extract URL patterns from the blacklist
                    for entry in blacklist_data['blacklist']:
                        if isinstance(entry, dict) and 'url' in entry:
                            self.entries.append(entry['url'])
                        elif isinstance(entry, str):
                            self.entries.append(entry)
                    logging.info(f'Loaded {len(self.entries)} blacklist entries from {self.blacklist_file}')
                else:
                    logging.warning(f'Invalid blacklist file format: {self.blacklist_file}')
        except yaml.YAMLError as e:
            logging.error(f'Error parsing blacklist file {self.blacklist_file}: {e}')
        except Exception as e:
            logging.error(f'Error loading blacklist file {self.blacklist_file}: {e}')

    def is_url_blacklisted(self, url):
        """Check if a URL is blacklisted."""
        if not url:
            return False
        for entry in self.entries:
            try:
                pattern = entry.replace('\\\\', '\\')
                if re.match(pattern, url):
                    logging.debug(f'URL blacklisted: {url} matches {entry}')
                    return True
            except re.error:
                logging.warning(f'Invalid regex in blacklist: {entry}')
        return False 