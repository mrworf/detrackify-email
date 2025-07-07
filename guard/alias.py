"""Domain alias management for the guard server."""
import yaml
import logging
import os
from guard.utils import GuardUtils

class DomainAliases:
    """Loads and manages domain aliases from a YAML file."""
    def __init__(self, aliases_file: str):
        self.aliases_file = aliases_file
        self.aliases = self._load_aliases()

    def _load_aliases(self):
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

    def are_aliases(self, domain1, domain2):
        """Check if two domains are aliases of each other."""
        if not domain1 or not domain2:
            return False
        
        domain1 = GuardUtils.normalize_domain(domain1)
        domain2 = GuardUtils.normalize_domain(domain2)
        
        if domain1 == domain2:
            return True
        
        if GuardUtils.is_subdomain(domain1, domain2) or GuardUtils.is_subdomain(domain2, domain1):
            return True
        
        for owner, alias_list in self.aliases.items():
            owner = GuardUtils.normalize_domain(owner)
            if isinstance(alias_list, str):
                alias_list = [alias_list]
            elif not isinstance(alias_list, list):
                continue
            
            alias_list = [GuardUtils.normalize_domain(alias) for alias in alias_list]
            alias_group = {owner} | set(alias_list)
            
            domain1_in_group = (domain1 == owner or domain1 in alias_list or 
                               any(GuardUtils.is_subdomain(domain1, d) for d in alias_group))
            domain2_in_group = (domain2 == owner or domain2 in alias_list or 
                               any(GuardUtils.is_subdomain(domain2, d) for d in alias_group))
            
            if domain1_in_group and domain2_in_group:
                logging.debug(f'Domain alias match: {domain1} and {domain2} in {owner} -> {alias_list}')
                return True
        
        return False 