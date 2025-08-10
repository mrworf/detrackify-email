#!/usr/bin/env python3
"""Configuration management for Detrackify guard server."""

import argparse
import logging
import os
from dataclasses import dataclass, field
from typing import Optional, List

import yaml
from guard.utils import GuardUtils
from common.utils import SharedUtils
from common.config_loader import load_config_sections


@dataclass
class GuardConfig:
    """Configuration options for :class:`GuardServer`."""

    # Core configuration
    salt: str
    timeout: int = 5
    template_dir: str = "templates"
    resource_dir: str = "resources"
    privacy: bool = False
    
    # Network configuration
    listen_ip: str = "127.0.0.1"
    listen_port: int = 9090
    
    # URL resolution configuration
    resolve: Optional[str] = None  # 'head', 'get', or None
    cache_file: Optional[str] = None
    cache_days: int = 30
    cache_max: int = 4096
    
    # URL processing configuration
    strip_param_prefixes: List[str] = field(default_factory=list)
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    # Localization and security
    force_language: Optional[str] = None
    domain_aliases_file: str = "domain_aliases.yml"
    blacklist_file: str = "blacklist.yml"
    deny_on_warnings: List[str] = field(default_factory=list)
    
    # Development options (command line only)
    debug: bool = False

    @classmethod
    def from_yaml(cls, config_path: str) -> 'GuardConfig':
        """Load configuration from YAML using shared loader and strict validation."""
        try:
            common, _, guard_settings = load_config_sections(config_path)
            if not common and not guard_settings:
                # Mirror previous behavior: empty file is invalid for guard loader
                raise ValueError("Configuration file must contain a dictionary")

            salt = (common.get('salt') or '')
            domain_aliases_file = common.get('domain_aliases_file', 'domain_aliases.yml')
            blacklist_file = common.get('blacklist_file', 'blacklist.yml')
            strip_param_prefixes = common.get('strip_param_prefix', []) or []

            return cls(
                salt=salt,
                timeout=guard_settings.get('timeout', 5),
                template_dir=guard_settings.get('template_dir', 'templates'),
                resource_dir=guard_settings.get('resources_dir', 'resources'),
                privacy=guard_settings.get('privacy', False),
                listen_ip=guard_settings.get('listen_ip', '127.0.0.1'),
                listen_port=guard_settings.get('listen_port', 9090),
                resolve=guard_settings.get('resolve'),
                cache_file=guard_settings.get('resolve_cache_file'),
                cache_days=guard_settings.get('resolve_cache_days', 30),
                cache_max=guard_settings.get('resolve_cache_max', 4096),
                strip_param_prefixes=strip_param_prefixes,
                user_agent=guard_settings.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'),
                force_language=guard_settings.get('force_language'),
                domain_aliases_file=domain_aliases_file,
                blacklist_file=blacklist_file,
                deny_on_warnings=guard_settings.get('deny_on_warnings', []),
            )
        except FileNotFoundError:
            logging.error("Configuration file not found: %s", config_path)
            raise
        except Exception as e:
            logging.error("Error loading configuration file: %s", e)
            raise

    @classmethod
    def from_env(cls) -> 'GuardConfig':
        """Load configuration from environment variables."""
        def get_env_bool(key: str, default: bool = False) -> bool:
            """Get boolean value from environment variable."""
            value = os.getenv(key, '').lower()
            return value in ('true', '1', 'yes', 'on')

        def get_env_list(key: str, default: List[str] = None) -> List[str]:
            """Get list value from environment variable (comma-separated)."""
            if default is None:
                default = []
            value = os.getenv(key, '')
            if not value:
                return default
            return [item.strip() for item in value.split(',') if item.strip()]

        def get_env_int(key: str, default: int) -> int:
            """Get integer value from environment variable."""
            try:
                return int(os.getenv(key, default))
            except (ValueError, TypeError):
                return default

        # Extract configuration values from environment
        return cls(
            salt=os.getenv('GUARD_SALT', ''),
            timeout=get_env_int('TIMEOUT', 5),
            template_dir=os.getenv('TEMPLATE_DIR', 'templates'),
            resource_dir=os.getenv('RESOURCES_DIR', 'resources'),
            privacy=get_env_bool('PRIVACY', False),
            listen_ip=os.getenv('LISTEN_IP', '127.0.0.1'),
            listen_port=get_env_int('LISTEN_PORT', 9090),
            resolve=os.getenv('RESOLVE'),
            cache_file=os.getenv('RESOLVE_CACHE_FILE'),
            cache_days=get_env_int('RESOLVE_CACHE_DAYS', 30),
            cache_max=get_env_int('RESOLVE_CACHE_MAX', 4096),
            strip_param_prefixes=get_env_list('STRIP_PARAM_PREFIX'),
            user_agent=os.getenv('USER_AGENT', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'),
            force_language=os.getenv('FORCE_LANGUAGE'),
            domain_aliases_file=os.getenv('DOMAIN_ALIASES_FILE', 'domain_aliases.yml'),
            blacklist_file=os.getenv('BLACKLIST_FILE', 'blacklist.yml'),
            deny_on_warnings=get_env_list('DENY_ON_WARNINGS'),
        )

    @classmethod
    def from_args(cls, args: argparse.Namespace, config_path: Optional[str] = None) -> 'GuardConfig':
        """Create configuration from command line arguments and optional YAML file."""
        # Start with default configuration
        if config_path:
            try:
                config = cls.from_yaml(config_path)
                logging.info("Loaded configuration from: %s", config_path)
            except Exception as e:
                logging.error("Failed to load configuration file: %s", e)
                raise
        else:
            # Create with minimal defaults - salt will be required
            config = cls(salt='')

        # Override with command line arguments
        if args.salt is not None:
            config.salt = args.salt
        if args.listen_ip is not None:
            config.listen_ip = args.listen_ip
        if args.listen_port is not None:
            config.listen_port = args.listen_port
        if args.template_dir is not None:
            config.template_dir = args.template_dir
        if args.resources_dir is not None:
            config.resource_dir = args.resources_dir
        if args.timeout is not None:
            config.timeout = args.timeout
        if args.privacy:
            config.privacy = True
        if args.resolve is not None:
            config.resolve = args.resolve
        if args.resolve_cache_file is not None:
            config.cache_file = args.resolve_cache_file
        if args.resolve_cache_days is not None:
            config.cache_days = args.resolve_cache_days
        if args.resolve_cache_max is not None:
            config.cache_max = args.resolve_cache_max
        if args.strip_param_prefix is not None:
            config.strip_param_prefixes = args.strip_param_prefix
        if args.user_agent is not None:
            config.user_agent = args.user_agent
        if args.debug:
            config.debug = True
        if args.force_language is not None:
            config.force_language = args.force_language
        if args.domain_aliases_file is not None:
            config.domain_aliases_file = args.domain_aliases_file
        if args.blacklist_file is not None:
            config.blacklist_file = args.blacklist_file
        if args.deny_on_warnings is not None:
            config.deny_on_warnings = args.deny_on_warnings

        # Validate required fields
        if not config.salt:
            raise ValueError("Salt is required. Specify with --salt or in config file.")

        return config

    def validate(self) -> None:
        """Validate configuration values."""
        if not self.salt:
            raise ValueError("Guard salt is required")
        
        if self.timeout < 0:
            raise ValueError("Timeout must be non-negative")
        
        if self.listen_port < 1 or self.listen_port > 65535:
            raise ValueError("Listen port must be between 1 and 65535")
        
        if self.resolve and self.resolve not in ['head', 'get']:
            raise ValueError("Resolve must be 'head', 'get', or None")
        
        if self.cache_days < 0:
            raise ValueError("Cache days must be non-negative")
        
        if self.cache_max < 1:
            raise ValueError("Cache max must be positive")
        
        if self.force_language and not self.validate_language_code(self.force_language):
            raise ValueError("Invalid language code format")

    def validate_language_code(self, lang_code: str) -> bool:
        """Validate language code."""
        return SharedUtils.validate_language_code(lang_code)

    def to_dict(self) -> dict:
        """Convert configuration to dictionary for serialization."""
        return {
            'salt': self.salt,
            'timeout': self.timeout,
            'template_dir': self.template_dir,
            'resources_dir': self.resource_dir,
            'privacy': self.privacy,
            'listen_ip': self.listen_ip,
            'listen_port': self.listen_port,
            'resolve': self.resolve,
            'resolve_cache_file': self.cache_file,
            'resolve_cache_days': self.cache_days,
            'resolve_cache_max': self.cache_max,
            'strip_param_prefix': self.strip_param_prefixes,
            'user_agent': self.user_agent,
            'force_language': self.force_language,
            'domain_aliases_file': self.domain_aliases_file,
            'blacklist_file': self.blacklist_file,
            'deny_on_warnings': self.deny_on_warnings,
        } 