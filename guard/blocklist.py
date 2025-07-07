"""Blocklist management for the guard server."""
import yaml
import logging
import os
import re

class Blocklist:
    """Loads and manages blocklist from a YAML file."""
    def __init__(self, blocklist_file: str):
        self.blocklist_file = blocklist_file
        self.blocklist = self._load_blocklist()

    def _load_blocklist(self):
        if not self.blocklist_file or not os.path.isfile(self.blocklist_file):
            logging.warning(f'Blocklist file not found: {self.blocklist_file}')
            return {'whitelist': [], 'blacklisted': []}
        try:
            with open(self.blocklist_file, 'r', encoding='utf-8') as f:
                blocklist_data = yaml.safe_load(f)
                if isinstance(blocklist_data, dict):
                    logging.info(f'Loaded blocklist from {self.blocklist_file}')
                    return blocklist_data
                else:
                    logging.warning(f'Invalid blocklist file format: {self.blocklist_file}')
                    return {'whitelist': [], 'blacklisted': []}
        except yaml.YAMLError as e:
            logging.error(f'Error parsing blocklist file {self.blocklist_file}: {e}')
            return {'whitelist': [], 'blacklisted': []}
        except Exception as e:
            logging.error(f'Error loading blocklist file {self.blocklist_file}: {e}')
            return {'whitelist': [], 'blacklisted': []}

    def is_url_blacklisted(self, url):
        """Check if a URL is blacklisted."""
        if not url:
            return False
        blacklist_entries = self.blocklist.get('blacklisted', [])
        for entry in blacklist_entries:
            if isinstance(entry, dict) and 'url' in entry:
                try:
                    pattern = entry['url'].replace('\\\\', '\\')
                    if re.match(pattern, url):
                        logging.debug(f'URL blacklisted: {url} matches {entry["url"]}')
                        return True
                except re.error:
                    logging.warning(f'Invalid regex in blacklist: {entry["url"]}')
            elif isinstance(entry, str):
                try:
                    pattern = entry.replace('\\\\', '\\')
                    if re.match(pattern, url):
                        logging.debug(f'URL blacklisted: {url} matches {entry}')
                        return True
                except re.error:
                    logging.warning(f'Invalid regex in blacklist: {entry}')
        return False 