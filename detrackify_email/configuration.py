"""
Configuration management for detrackify email processing.
"""

import os
import re
import logging
import yaml
from typing import Optional, Dict, Any, List
from .helpers import EmailHelpers


class Configuration:
    """Configuration management class with YAML loading and argparse override support."""
    
    # Configuration keys
    CFG_VERBOSE = 'options.verbose'
    CFG_STRIP_FILE = 'options.strip.file'
    CFG_STRIP_COOKIES = 'options.strip.cookies'
    CFG_STRIP_REDIRECT = 'options.strip.redirect'
    CFG_STRIP_ENABLE = 'options.strip.enable'
    CFG_COPY = 'options.copy'
    CFG_GUARD_SERVER = 'options.guard.server'
    CFG_GUARD_SALT = 'options.guard.salt'
    CFG_GUARD_LINK = 'options.guard.link'
    CFG_GUARD_CAPTURE_TO = 'options.guard.capture_to'
    CFG_GUARD_WHITELINK = 'options.guard.whitelist_links'
    CFG_GUARD_WHITELIST_SENDER = 'options.guard.whitelist_senders'
    CFG_GUARD_DOMAIN_ALIASES = 'options.guard.domain_aliases'
    CFG_DOMAIN_ALIASES_FILE = 'domain_aliases_file'
    CFG_BLOCKLIST_FILE = 'blocklist_file'
    
    def __init__(self):
        """Initialize configuration with defaults."""
        self.config = self._get_default_config()
        self.last_blacklist = 0
        self.last_rewrite = 0
        self.last_whitelist = 0
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values."""
        return {
            'options': {
                'strip': {
                    'file': 'strip.yml',
                    'cookies': True,
                    'redirect': True,
                    'enable': False
                },
                'verbose': False,
                'copy': None,
                'guard': {
                    'server': None,
                    'salt': None,
                    'link': 'off',
                    'capture_to': False,
                    'whitelist_links': [],
                    'whitelist_senders': [],
                    'domain_aliases': {}
                }
            },
            'domain_aliases_file': 'domain_aliases.yml',
            'blocklist_file': None,
            'blacklist': [],
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
        self.load_blocklist_from_file()
        
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
        
        if args.guardwhitelink:
            self.config['options']['guard']['whitelist_links'].extend(args.guardwhitelink)
        if args.guardwhitelistsender:
            self.config['options']['guard']['whitelist_senders'].extend(args.guardwhitelistsender)
        
        if args.guarddomainalias:
            for alias_spec in args.guarddomainalias:
                if ':' in alias_spec:
                    owner, aliases_str = alias_spec.split(':', 1)
                    owner = owner.strip()
                    aliases = [alias.strip() for alias in aliases_str.split(',')]
                    if owner and aliases:
                        self.config['options']['guard']['domain_aliases'][owner] = aliases
                        logging.info(f'Added domain alias: {owner} -> {aliases}')
                    else:
                        logging.warning(f'Invalid domain alias format: {alias_spec}')
                else:
                    logging.warning(f'Invalid domain alias format (missing colon): {alias_spec}')
        
        if args.domainaliasesfile:
            self.set(Configuration.CFG_DOMAIN_ALIASES_FILE, args.domainaliasesfile)
        if args.blocklistfile:
            self.set(Configuration.CFG_BLOCKLIST_FILE, args.blocklistfile)
        
        # Load additional files after setting paths
        self.load_domain_aliases_from_file()
        self.load_blocklist_from_file()
    
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
        blacklist_entries = self.config.get('blacklist', [])
        for entry in blacklist_entries:
            if isinstance(entry, dict) and 'url' in entry:
                if EmailHelpers.test_url_against_patterns(url, [entry['url']], 'blacklist'):
                    return True
            elif isinstance(entry, str):
                if EmailHelpers.test_url_against_patterns(url, [entry], 'blacklist'):
                    return True
        return False
    
    def is_whitelisted(self, url: str) -> bool:
        """Check if the URL is whitelisted."""
        whitelist_entries = self.config.get('whitelist', [])
        return bool(EmailHelpers.test_url_against_patterns(url, whitelist_entries, 'whitelist'))
    
    def is_sender_blacklisted(self, sender: str) -> bool:
        """Check if a sender email is blacklisted."""
        if not sender:
            return False
        blacklist_entries = self.config.get('blacklist', [])
        logging.debug(f"is_sender_blacklisted: sender={sender}, blacklist_entries={blacklist_entries}")
        for entry in blacklist_entries:
            if isinstance(entry, dict) and 'sender' in entry:
                pattern = entry['sender']
                result = re.match(pattern, sender)
                debug_line = f"DEBUG: Testing sender blacklist: pattern={pattern!r}, sender={sender!r}, match={result}\n"
                try:
                    with open('sender_blacklist_debug.log', 'a') as dbg:
                        dbg.write(debug_line)
                except Exception:
                    pass
                logging.debug(debug_line.strip())
                if result:
                    return True
        return False
    
    def is_guard_link_whitelisted(self, url: str) -> Optional[str]:
        """Check if link should bypass guarding."""
        return EmailHelpers.test_url_against_patterns(
            url,
            self.get(Configuration.CFG_GUARD_WHITELINK, []),
            'guard link whitelist'
        )
    
    def is_guard_sender_whitelisted(self, sender: str) -> bool:
        """Check if sender should bypass guarding."""
        return bool(
            EmailHelpers.test_url_against_patterns(
                sender,
                self.get(Configuration.CFG_GUARD_WHITELIST_SENDER, []),
                'guard sender whitelist'
            )
        )
    
    def are_domains_aliases(self, domain1: str, domain2: str) -> bool:
        """Check if two domains are aliases of each other."""
        if not domain1 or not domain2:
            return False
        
        domain1 = EmailHelpers.normalize_domain(domain1)
        domain2 = EmailHelpers.normalize_domain(domain2)
        
        # Direct match
        if domain1 == domain2:
            return True
        
        # Check subdomain relationship
        if EmailHelpers.is_subdomain(domain1, domain2) or EmailHelpers.is_subdomain(domain2, domain1):
            return True
        
        # Check configured aliases
        aliases = self.get(Configuration.CFG_GUARD_DOMAIN_ALIASES, {})
        for owner, alias_list in aliases.items():
            owner = EmailHelpers.normalize_domain(owner)
            if isinstance(alias_list, str):
                alias_list = [alias_list]
            elif not isinstance(alias_list, list):
                continue
            
            alias_list = [EmailHelpers.normalize_domain(alias) for alias in alias_list]
            alias_group = {owner} | set(alias_list)
            
            domain1_in_group = (domain1 == owner or domain1 in alias_list or 
                               any(EmailHelpers.is_subdomain(domain1, d) for d in alias_group))
            domain2_in_group = (domain2 == owner or domain2 in alias_list or 
                               any(EmailHelpers.is_subdomain(domain2, d) for d in alias_group))
            
            if domain1_in_group and domain2_in_group:
                logging.debug(f'Domain alias match: {domain1} and {domain2} in {owner} -> {alias_list}')
                return True
        
        return False
    
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
    
    def add_blacklist(self, url: str) -> bool:
        """Add a URL to the blacklist."""
        if not self.is_blacklisted(url):
            logging.info(f'Adding {url} to blacklist')
            self.config['blacklist'].append(url)
            return True
        return False
    
    def add_whitelist(self, url: str) -> bool:
        """Add a URL to the whitelist."""
        if not self.is_whitelisted(url):
            logging.info(f'Adding {url} to whitelist')
            self.config['whitelist'].append(url)
            return True
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
        
        try:
            with open(aliases_file, 'r', encoding='utf-8') as f:
                aliases_data = yaml.safe_load(f)
                if isinstance(aliases_data, dict):
                    existing_aliases = self.get(Configuration.CFG_GUARD_DOMAIN_ALIASES, {})
                    processed_aliases = {}
                    
                    for owner, alias_list in aliases_data.items():
                        if isinstance(alias_list, str):
                            processed_aliases[owner] = [alias_list]
                        elif isinstance(alias_list, list):
                            processed_aliases[owner] = alias_list
                        else:
                            logging.warning(f'Invalid alias format for {owner}: {alias_list}')
                            continue
                    
                    existing_aliases.update(processed_aliases)
                    self.config['options']['guard']['domain_aliases'] = existing_aliases
                    logging.info(f'Loaded {len(processed_aliases)} domain aliases from {aliases_file}')
                else:
                    logging.warning(f'Invalid domain aliases file format: {aliases_file}')
        except FileNotFoundError:
            logging.warning(f'Domain aliases file not found: {aliases_file}')
        except yaml.YAMLError as e:
            logging.error(f'Error parsing domain aliases file {aliases_file}: {e}')
        except Exception as e:
            logging.error(f'Error loading domain aliases file {aliases_file}: {e}')
    
    def load_blocklist_from_file(self) -> None:
        """Load blocklist from the configured file."""
        blocklist_file = self.get(Configuration.CFG_BLOCKLIST_FILE)
        logging.debug(f"DEBUG: load_blocklist_from_file called with blocklist_file={blocklist_file!r}")
        if not blocklist_file:
            return
        try:
            with open(blocklist_file, 'r', encoding='utf-8') as f:
                blocklist_data = yaml.safe_load(f)
                if isinstance(blocklist_data, dict):
                    self.config['whitelist'] = []
                    self.config['blacklist'] = []
                    whitelist_entries = blocklist_data.get('whitelist', [])
                    if isinstance(whitelist_entries, list):
                        self.config['whitelist'] = whitelist_entries
                        logging.info(f'Loaded {len(whitelist_entries)} whitelist entries from {blocklist_file}')
                    blacklist_entries = blocklist_data.get('blacklist', [])
                    if isinstance(blacklist_entries, list):
                        self.config['blacklist'] = blacklist_entries
                        logging.info(f'Loaded {len(blacklist_entries)} blacklist entries from {blocklist_file}')
                        logging.debug(f"DEBUG: After loading blocklist: blacklist={self.config['blacklist']}")
                else:
                    logging.warning(f'Invalid blocklist file format: {blocklist_file}')
            logging.debug(f"DEBUG: config after blocklist load: {self.config}")
        except FileNotFoundError:
            logging.warning(f'Blocklist file not found: {blocklist_file}')
        except yaml.YAMLError as e:
            logging.error(f'Error parsing blocklist file {blocklist_file}: {e}')
        except Exception as e:
            logging.error(f'Error loading blocklist file {blocklist_file}: {e}')
    
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