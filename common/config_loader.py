"""
Shared configuration loader and validator for YAML files.

Parses a YAML file and returns structured sections (common, email, guard)
with strict validation and warnings for misplaced/unknown keys.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Tuple
import yaml


ALLOWED_COMMON_KEYS = {
    'salt',
    'domain_aliases_file',
    'blacklist_file',
    'strip_param_prefix',
}

ALLOWED_EMAIL_TOP = {
    'verbose', 'strip', 'copy', 'guard', 'cache_file', 'rewrite',
}

ALLOWED_EMAIL_GUARD = {'server', 'link', 'capture_to', 'whitelist_file', 'phishy'}

ALLOWED_GUARD_TOP = {
    'listen_ip', 'listen_port', 'timeout', 'privacy',
    'resolve', 'resolve_cache_file', 'resolve_cache_days', 'resolve_cache_max',
    'user_agent', 'template_dir', 'resources_dir', 'force_language',
    'deny_on_warnings', 'auto_redirect',
}


def load_config_sections(path: str) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """Load and validate YAML config, returning (common, email, guard_server) sections.

    Warnings are logged and invalid/misplaced keys are ignored.
    """
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            config_data = yaml.safe_load(fh)
        if config_data is None:
            # Empty file treated as empty dict for lenient behavior
            config_data = {}
        if not isinstance(config_data, dict):
            raise ValueError("Configuration file must contain a dictionary")
    except FileNotFoundError:
        logging.error("Configuration file not found: %s", path)
        raise
    except yaml.YAMLError as e:
        logging.error("Invalid YAML in configuration file: %s", e)
        raise

    # Extract sections
    common = dict(config_data.get('common', {}) or {})
    email = dict(config_data.get('email', {}) or {})
    guard = dict(config_data.get('guard_server', {}) or {})

    # Warn for unknown top-level keys
    for top_key in config_data.keys():
        if top_key not in {'common', 'email', 'guard_server'}:
            logging.warning("Unknown top-level key '%s' ignored. Expected 'common', 'email', or 'guard_server'", top_key)

    # Common: unknown keys
    for key in list(common.keys()):
        if key not in ALLOWED_COMMON_KEYS:
            logging.warning("Unknown key in common: '%s' ignored", key)
            common.pop(key, None)

    # Email: unknown keys
    for key in list(email.keys()):
        if key not in ALLOWED_EMAIL_TOP:
            logging.warning("Unknown or disallowed key in email: '%s' ignored", key)
            email.pop(key, None)

    # Email guard subkeys
    if isinstance(email.get('guard'), dict):
        for key in list(email['guard'].keys()):
            if key not in ALLOWED_EMAIL_GUARD:
                logging.warning("Unknown key in email.guard: '%s' ignored", key)
                email['guard'].pop(key, None)

    # Guard: unknown keys
    for key in list(guard.keys()):
        if key not in ALLOWED_GUARD_TOP:
            logging.warning("Unknown or disallowed key in guard: '%s' ignored", key)
            guard.pop(key, None)

    # Misplacement checks
    def warn_if_present(dct: Dict[str, Any], path_name: str, key_name: str):
        if isinstance(dct, dict) and key_name in dct:
            logging.warning("Misplaced key '%s' found at '%s' - use 'common.%s' instead. Ignored.", key_name, path_name, key_name)

    for misplaced in ('salt', 'domain_aliases_file', 'blacklist_file', 'strip_param_prefix'):
        warn_if_present(config_data, '<root>', misplaced)
        warn_if_present(email, 'email', misplaced)
        warn_if_present(guard, 'guard', misplaced)

    # Special case: salt may appear under email.guard historically
    if isinstance(email.get('guard'), dict) and 'salt' in email['guard']:
        logging.warning("Misplaced key 'salt' found at 'email.guard' - use 'common.salt' instead. Ignored.")
        email['guard'].pop('salt', None)

    return common, email, guard


