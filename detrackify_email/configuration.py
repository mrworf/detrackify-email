"""
Configuration management for detrackify email processing.
"""

import os
import re
import logging
import yaml
from typing import Optional, Dict, Any, List
from common.utils import SharedUtils
from common.alias import DomainAliases
from common.blocklist import Blocklist
from common.cache import Cache


class Configuration:
    """Configuration management class with YAML loading and argparse override support."""
    
    # Configuration keys
    CFG_VERBOSE = 'options.verbose'
    CFG_STRIP_FILE = 'options.strip.file'
    CFG_STRIP_COOKIES = 'options.strip.cookies'
    CFG_STRIP_REDIRECT = 'options.strip.redirect'
    CFG_STRIP_ENABLE = 'options.strip.enable'
    CFG_STRIP_PARAM_PREFIX = 'options.strip.param_prefix'
    CFG_COPY = 'options.copy'
    CFG_GUARD_SERVER = 'options.guard.server'
    CFG_GUARD_SALT = 'options.guard.salt'
    CFG_GUARD_LINK = 'options.guard.link'
    CFG_GUARD_CAPTURE_TO = 'options.guard.capture_to'
    CFG_GUARD_WHITELIST_FILE = 'options.guard.whitelist_file'

    CFG_DOMAIN_ALIASES_FILE = 'domain_aliases_file'
    CFG_WHITELIST_FILE = 'whitelist_file'
    CFG_BLACKLIST_FILE = 'blacklist_file'
    CFG_CACHE_FILE = 'cache_file'
    
    def __init__(self):
        """Initialize configuration with defaults."""
        self.config = self._get_default_config()
        self.last_blacklist = 0
        self.last_rewrite = 0
        self.last_whitelist = 0
        # Always initialize domain_aliases, even if no file is provided
        from common.alias import DomainAliases
        self.domain_aliases = DomainAliases()
        # Initialize blocklists
        self.blacklist = None
        self.whitelist = None
        self.guard_whitelist = None
        # Initialize cache
        self.cache = None
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values."""
        return {
            'options': {
                'strip': {
                    'file': 'strip.yml',
                    'cookies': True,
                    'redirect': True,
                    'enable': False,
                    'param_prefix': []
                },
                'verbose': False,
                'copy': None,
                'guard': {
                    'server': None,
                    'salt': None,
                    'link': 'off',
                    'capture_to': False,
                    'whitelist_file': None
                }
            },
            'domain_aliases_file': 'domain_aliases.yml',
            'whitelist_file': None,
            'blacklist_file': None,
            'cache_file': None,
            'whitelist': [],
            'rewrite': []
        }
    
    def load_from_yaml(self, path: str) -> bool:
        """Load configuration from YAML file."""
        try:
            with open(path, 'r') as stream:
                settings = yaml.safe_load(stream) or {}
                self._merge_settings(settings)
        except FileNotFoundError:
            logging.exception(f"Configuration file not found: {path}")
            return False
        except yaml.YAMLError as exc:
            logging.exception(f"Error loading configuration file: {exc}")
            return False
        except Exception as e:
            logging.exception(f"Error loading configuration file: {e}")
            return False
        
        self._update_counters()
        logging.debug(f'Loaded configuration file: {path} with {self.last_blacklist} blacklisted URLs and {self.last_rewrite} rewrite rules')
        
        # Load additional files
        self.load_domain_aliases_from_file()
        self.load_whitelist_from_file()
        self.load_blacklist_from_file()
        self.load_cache_from_file()
        
        return True
    
    def load_from_args(self, args) -> None:
        """Load configuration from argparse object, overriding existing settings."""
        if args.verbose:
            self.set(Configuration.CFG_VERBOSE, True)
        
        if args.strip:
            self.set(Configuration.CFG_STRIP_ENABLE, True)
        
        if args.copy:
            if not os.path.exists(args.copy):
                raise ValueError(f'Copy folder does not exist: {args.copy}')
            self.set(Configuration.CFG_COPY, args.copy)
        
        if args.guardserver:
            self.set(Configuration.CFG_GUARD_SERVER, args.guardserver)
        if args.guardsalt:
            self.set(Configuration.CFG_GUARD_SALT, args.guardsalt)
        if args.guardlink is not None:
            self.set(Configuration.CFG_GUARD_LINK, args.guardlink)
        if args.guardcaptureto:
            self.set(Configuration.CFG_GUARD_CAPTURE_TO, True)
        
        # Only load additional files if the paths were actually set via command line arguments
        if args.domain_aliases_file:
            self.set(Configuration.CFG_DOMAIN_ALIASES_FILE, args.domain_aliases_file)
            self.load_domain_aliases_from_file()
        if args.whitelist_file:
            self.set(Configuration.CFG_WHITELIST_FILE, args.whitelist_file)
            self.load_whitelist_from_file()
        if args.blacklist_file:
            self.set(Configuration.CFG_BLACKLIST_FILE, args.blacklist_file)
            self.load_blacklist_from_file()
        if args.guard_whitelist_file:
            self.set(Configuration.CFG_GUARD_WHITELIST_FILE, args.guard_whitelist_file)
            self.load_guard_whitelist_from_file()
        if args.cache_file:
            self.set(Configuration.CFG_CACHE_FILE, args.cache_file)
            self.load_cache_from_file()
        
        # Handle strip parameter prefixes
        if args.strip_param_prefix:
            self.set(Configuration.CFG_STRIP_PARAM_PREFIX, args.strip_param_prefix)
    
    def _merge_settings(self, settings: Dict[str, Any]) -> None:
        """Merge settings into configuration."""
        opts = settings.get('options', {})
        for key, value in opts.items():
            if isinstance(value, dict) and isinstance(self.config['options'].get(key), dict):
                self.config['options'][key].update(value)
            else:
                self.config['options'][key] = value
        
        for key, value in settings.items():
            if key == 'options':
                continue
            if key in self.config and isinstance(self.config[key], list) and isinstance(value, list):
                self.config[key].extend(value)
            else:
                self.config[key] = value
        

    
    def _update_counters(self) -> None:
        """Update internal counters for tracking changes."""
        self.last_blacklist = len(self.config.get('blacklist', []))
        self.last_rewrite = len(self.config.get('rewrite', []))
        self.last_whitelist = len(self.config.get('whitelist', []))
    
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value."""
        parts = key.split('.')
        config = self.config
        
        if len(parts) == 1:
            config[parts[0]] = value
        else:
            for c in range(len(parts) - 1):
                if parts[c] in config:
                    config = config[parts[c]]
                    if c == len(parts) - 2:
                        config[parts[c + 1]] = value
                        break
        
        if key == Configuration.CFG_STRIP_ENABLE:
            self.load_learned(self.get(Configuration.CFG_STRIP_FILE))
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        parts = key.split('.')
        config = self.config
        for part in parts:
            if part in config:
                config = config[part]
            else:
                logging.warning(f'Key not found: {part} in {config}')
                return default
        return config
    
    def is_blacklisted(self, url: str) -> bool:
        """Check if the URL is blacklisted."""
        # First check the main blacklist
        if self.blacklist and self.blacklist.is_url_blacklisted(url):
            return True
        # Then check the cache
        if self.cache and self.cache.is_url_blacklisted(url):
            return True
        return False
    
    def is_whitelisted(self, url: str) -> bool:
        """Check if the URL is whitelisted."""
        # First check the main whitelist
        if self.whitelist and self.whitelist.is_url_whitelisted(url):
            return True
        # Then check the cache
        if self.cache and self.cache.is_url_whitelisted(url):
            return True
        return False
    
    def is_sender_blacklisted(self, sender: str) -> bool:
        """Check if a sender email is blacklisted."""
        if self.blacklist:
            return self.blacklist.is_sender_blacklisted(sender)
        return False
    
    def is_guard_link_whitelisted(self, url: str) -> Optional[str]:
        """Check if URL should bypass link guarding."""
        if self.guard_whitelist:
            # Check URL entries
            url_entries = self.guard_whitelist.get_url_entries()
            for entry in url_entries:
                if SharedUtils.test_url_against_patterns(url, [entry], 'guard link whitelist'):
                    return entry
        return None
    
    def is_guard_sender_whitelisted(self, sender: str) -> bool:
        """Check if sender should bypass guarding."""
        if self.guard_whitelist:
            return self.guard_whitelist.is_sender_whitelisted(sender)
        return False
    
    def are_domains_aliases(self, domain1: str, domain2: str) -> bool:
        """Check if two domains are aliases of each other."""
        if not self.domain_aliases:
            raise RuntimeError("DomainAliases instance not initialized. Call load_domain_aliases_from_file or ensure aliases are loaded from config.")
        return self.domain_aliases.are_aliases(domain1, domain2)
    
    def rewrite_url(self, url: str) -> str:
        """Rewrite the URL if needed."""
        for rule in self.config.get('rewrite', []):
            f = rule.get('from', None)
            t = rule.get('to', None)
            if f and t:
                try:
                    result = re.sub(rule.get('from'), rule.get('to'), url)
                    if result != url:
                        logging.info(f'Rewriting {url} to {result} ({rule})')
                        return result
                except Exception as e:
                    logging.error(f'Rewriting {url} from {f} to {t} failed: {e}')
            else:
                logging.error(f'Invalid rewrite rule: {rule}')
        return url
    
    def add_to_cache_blacklist(self, url: str) -> bool:
        """Add a URL to the cache blacklist."""
        if self.cache:
            return self.cache.add_blacklist_entry(url)
        return False
    
    def add_to_cache_whitelist(self, url: str) -> bool:
        """Add a URL to the cache whitelist."""
        if self.cache:
            return self.cache.add_whitelist_entry(url)
        return False
    
    def add_rewrite(self, from_url: str, to_url: str) -> bool:
        """Add a rewrite rule."""
        for rule in self.config['rewrite']:
            if rule.get('from') == from_url:
                if rule.get('to') == to_url:
                    logging.debug(f'Rule already exists: {from_url} -> {to_url}')
                    return False
                else:
                    logging.warning(f'Overwriting rewrite rule: {from_url} -> {to_url}')
                    rule['to'] = to_url
                    return True
        
        logging.info(f'Adding rewrite rule: {from_url} -> {to_url}')
        self.config['rewrite'].append({'from': from_url, 'to': to_url})
        return True
    
    def load_domain_aliases_from_file(self) -> None:
        """Load domain aliases from the configured file."""
        aliases_file = self.get(Configuration.CFG_DOMAIN_ALIASES_FILE)
        if not aliases_file:
            return
        
        # Use the common DomainAliases class
        self.domain_aliases = DomainAliases(aliases_file)
        

    

    
    def load_whitelist_from_file(self) -> None:
        """Load whitelist from the configured file."""
        whitelist_file = self.get(Configuration.CFG_WHITELIST_FILE)
        self.whitelist = Blocklist(whitelist_file, 'whitelist')
        self.config['whitelist'] = self.whitelist.get_entries()
    
    def load_blacklist_from_file(self) -> None:
        """Load blacklist from the configured file."""
        blacklist_file = self.get(Configuration.CFG_BLACKLIST_FILE)
        logging.debug(f"DEBUG: load_blacklist_from_file called with blacklist_file={blacklist_file!r}")
        self.blacklist = Blocklist(blacklist_file, 'blacklist')
        self.config['blacklist'] = self.blacklist.get_entries()
        logging.debug(f"DEBUG: After loading blacklist: blacklist={self.config['blacklist']}")
        logging.debug(f"DEBUG: config after blacklist load: {self.config}")
    
    def load_guard_whitelist_from_file(self) -> None:
        """Load guard whitelist from the configured file."""
        guard_whitelist_file = self.get(Configuration.CFG_GUARD_WHITELIST_FILE)
        if not guard_whitelist_file:
            return
        
        self.guard_whitelist = Blocklist(guard_whitelist_file, 'whitelist')
        self.config['options']['guard']['whitelist'] = self.guard_whitelist.get_entries()
        
        logging.info(f'Loaded {len(self.guard_whitelist)} guard whitelist entries from {guard_whitelist_file}')
    
    def load_cache_from_file(self) -> None:
        """Load cache from the configured file."""
        cache_file = self.get(Configuration.CFG_CACHE_FILE)
        if cache_file:
            self.cache = Cache(cache_file)
            logging.info(f'Cache loaded from {cache_file}')
    
    def save_cache(self) -> bool:
        """Save cache to file."""
        if self.cache:
            return self.cache.save_cache()
        return False
    
    def load_learned(self, path: str) -> bool:
        """Load learned rules from file."""
        try:
            with open(path, 'r') as stream:
                learned = yaml.safe_load(stream)
                self.config['whitelist'].extend(learned.get('whitelist', []))
                self.config['blacklist'].extend(learned.get('blacklist', []))
                self.config['rewrite'].extend(learned.get('rewrite', []))
                logging.debug(f'Loaded learned file: {path}')
        except FileNotFoundError:
            logging.warning(f"Learned file not found: {path}")
            return True
        except Exception as e:
            logging.exception(f"Error loading learned file: {e}")
            return False
        return True
    
    def save_learned(self, path: str) -> bool:
        """Save learned rules to file."""
        try:
            partial = {
                'whitelist': self.config.get('whitelist', [])[self.last_whitelist:],
                'blacklist': self.config.get('blacklist', [])[self.last_blacklist:],
                'rewrite': self.config.get('rewrite', [])[self.last_rewrite:]
            }
            with open(path, 'w') as stream:
                yaml.dump(partial, stream)
                logging.debug(f'Saved learned file: {path}')
        except Exception as e:
            logging.exception(f"Error saving learned file: {e}")
            return False
        return True
    
    def validate_guard_config(self) -> None:
        """Validate guard configuration."""
        mode = self.get(Configuration.CFG_GUARD_LINK, 'off')
        if mode != 'off':
            server = self.get(Configuration.CFG_GUARD_SERVER)
            salt = self.get(Configuration.CFG_GUARD_SALT)
            if not server:
                raise ValueError('Guard server must be specified when guardlink is enabled')
            if not re.match(r'^https?://', server):
                raise ValueError('Guard server must include http or https scheme')
            if server.startswith('http://'):
                logging.warning('Guard server is using HTTP, consider HTTPS')
            if not salt or len(salt) < 8:
                raise ValueError('Guardsalt must be at least 8 characters')
    
    def load(self, path: str) -> bool:
        """Alias for load_from_yaml for backward compatibility."""
        return self.load_from_yaml(path) 