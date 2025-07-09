"""Domain alias management for both detrackify_email and detrackify_guard."""

import yaml
import logging
import os
from typing import Dict, Any, Optional
from .utils import SharedUtils


class DomainAliases:
    """Loads and manages domain aliases from a YAML file."""
    
    def __init__(self, aliases_file: Optional[str] = None):
        """
        Initialize domain aliases.
        
        Args:
            aliases_file: Path to the YAML file containing domain aliases.
                         If None, no aliases will be loaded.
        """
        self.aliases_file = aliases_file
        self.aliases = self._load_aliases() if aliases_file else {}
    
    def set_aliases(self, aliases: Dict[str, Any]) -> None:
        """
        Set aliases directly without loading from file.
        
        Args:
            aliases: Dictionary of domain aliases
        """
        self.aliases = aliases
    
    def _load_aliases(self) -> Dict[str, Any]:
        """Load domain aliases from the configured file."""
        if not self.aliases_file or not os.path.isfile(self.aliases_file):
            logging.warning(f'Domain aliases file not found: {self.aliases_file}')
            return {}
        
        try:
            with open(self.aliases_file, 'r', encoding='utf-8') as f:
                aliases_data = yaml.safe_load(f)
                if isinstance(aliases_data, dict):
                    logging.info(f'Loaded {len(aliases_data)} domain aliases from {self.aliases_file}')
                    return aliases_data
                else:
                    logging.warning(f'Invalid domain aliases file format: {self.aliases_file}')
                    return {}
        except yaml.YAMLError as e:
            logging.error(f'Error parsing domain aliases file {self.aliases_file}: {e}')
            return {}
        except Exception as e:
            logging.error(f'Error loading domain aliases file {self.aliases_file}: {e}')
            return {}
    
    def are_aliases(self, domain1: str, domain2: str) -> bool:
        """
        Check if two domains are aliases of each other.
        
        Args:
            domain1: First domain to compare
            domain2: Second domain to compare
            
        Returns:
            True if domains are aliases, False otherwise
        """
        return SharedUtils.are_domains_aliases(domain1, domain2, self.aliases)
    
    def get_aliases(self) -> Dict[str, Any]:
        """
        Get the loaded aliases dictionary.
        
        Returns:
            Dictionary of domain aliases
        """
        return self.aliases.copy()
    
    def reload(self) -> bool:
        """
        Reload aliases from the file.
        
        Returns:
            True if reload was successful, False otherwise
        """
        if not self.aliases_file:
            return False
        
        new_aliases = self._load_aliases()
        if new_aliases is not None:
            self.aliases = new_aliases
            return True
        return False 