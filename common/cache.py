"""
Cache system for detrackify with persistent storage.
"""

import logging
import yaml
import os
from typing import Optional, Dict, Any
from common.blocklist import Blocklist


class Cache:
    """Cache system for blacklist and whitelist entries with persistent storage."""
    
    def __init__(self, cache_file: Optional[str] = None):
        """
        Initialize cache system.
        
        Args:
            cache_file: Path to cache YAML file for persistent storage
        """
        self.cache_file = cache_file
        self.blacklist_cache = Blocklist(None, 'blacklist')  # In-memory only
        self.whitelist_cache = Blocklist(None, 'whitelist')  # In-memory only
        self._load_cache()
    
    def _load_cache(self) -> None:
        """Load cache from file if it exists."""
        if not self.cache_file:
            return
        
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f) or {}
                    
                    # Load blacklist cache
                    blacklist_entries = data.get('blacklist', [])
                    if isinstance(blacklist_entries, list):
                        self.blacklist_cache.entries = blacklist_entries
                        logging.info(f'Loaded {len(blacklist_entries)} blacklist cache entries from {self.cache_file}')
                    
                    # Load whitelist cache
                    whitelist_entries = data.get('whitelist', [])
                    if isinstance(whitelist_entries, list):
                        self.whitelist_cache.entries = whitelist_entries
                        logging.info(f'Loaded {len(whitelist_entries)} whitelist cache entries from {self.cache_file}')
                        
        except yaml.YAMLError as e:
            logging.error(f'Error parsing cache file {self.cache_file}: {e}')
        except Exception as e:
            logging.error(f'Error loading cache file {self.cache_file}: {e}')
    
    def save_cache(self) -> bool:
        """Save cache to file."""
        if not self.cache_file:
            return False
        
        try:
            cache_data = {
                'blacklist': self.blacklist_cache.get_entries(),
                'whitelist': self.whitelist_cache.get_entries()
            }
            
            # Create directory if it doesn't exist
            cache_dir = os.path.dirname(self.cache_file)
            if cache_dir and not os.path.exists(cache_dir):
                os.makedirs(cache_dir)
            
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                yaml.dump(cache_data, f, default_flow_style=False)
            
            logging.info(f'Saved {len(self.blacklist_cache)} blacklist and {len(self.whitelist_cache)} whitelist cache entries to {self.cache_file}')
            return True
            
        except Exception as e:
            logging.error(f'Error saving cache file {self.cache_file}: {e}')
            return False
    
    def add_blacklist_entry(self, url: str) -> bool:
        """Add a URL to the blacklist cache."""
        return self.blacklist_cache.add_url_entry(url)
    
    def add_whitelist_entry(self, url: str) -> bool:
        """Add a URL to the whitelist cache."""
        return self.whitelist_cache.add_url_entry(url)
    
    def is_url_blacklisted(self, url: str) -> bool:
        """Check if URL is in blacklist cache."""
        return self.blacklist_cache.is_url_blacklisted(url)
    
    def is_url_whitelisted(self, url: str) -> bool:
        """Check if URL is in whitelist cache."""
        return self.whitelist_cache.is_url_whitelisted(url)
    
    def get_blacklist_entries(self) -> list:
        """Get all blacklist cache entries."""
        return self.blacklist_cache.get_entries()
    
    def get_whitelist_entries(self) -> list:
        """Get all whitelist cache entries."""
        return self.whitelist_cache.get_entries()
    
    def clear_cache(self) -> None:
        """Clear all cache entries."""
        self.blacklist_cache.entries.clear()
        self.whitelist_cache.entries.clear()
        logging.info('Cache cleared')
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            'blacklist_entries': len(self.blacklist_cache),
            'whitelist_entries': len(self.whitelist_cache),
            'total_entries': len(self.blacklist_cache) + len(self.whitelist_cache)
        } 