#!/usr/bin/env python3
"""
Shared URL utilities for detrackify project.

This module provides common URL parameter stripping functionality
used by both detrackify_email.py and detrackify_guard.py.
"""

import urllib.parse
import logging


def strip_query_params(url, prefixes):
    """
    Remove query parameters starting with configured prefixes (case-insensitive).
    
    This function removes the first parameter that matches any of the configured
    prefixes and all subsequent parameters. This is useful for removing tracking
    parameters while preserving legitimate parameters that come before them.
    
    Args:
        url (str): The URL to process
        prefixes (list): List of parameter prefixes to strip (case-insensitive)
        
    Returns:
        str: The URL with matching parameters stripped
        
    Examples:
        >>> strip_query_params("https://example.com/?param1=value&utm_source=test&param2=value", ["utm_"])
        "https://example.com/?param1=value"
        
        >>> strip_query_params("https://example.com/?param1=value&UTM_SOURCE=test&param2=value", ["utm_"])
        "https://example.com/?param1=value"
        
        >>> strip_query_params("https://example.com/?fbclid=123&param1=value", ["fbclid"])
        "https://example.com/"
    """
    if not prefixes or not url:
        return url
        
    try:
        parts = urllib.parse.urlsplit(url)
    except Exception:  # pylint: disable=broad-except
        logging.debug(f"Failed to parse URL: {url}")
        return url
        
    if not parts.query:
        return url
        
    params = parts.query.split("&")
    keep = []
    
    # Convert prefixes to lowercase for case-insensitive matching
    lower_prefixes = [prefix.lower() for prefix in prefixes]
    
    for param in params:
        # Extract parameter name (before '=' if present)
        key = param.split("=")[0].lower()
        
        # Check if this parameter matches any prefix (case-insensitive)
        if any(key.startswith(prefix) for prefix in lower_prefixes):
            # Found a matching parameter - stop processing and discard this and all following params
            break
            
        keep.append(param)
    
    # Reconstruct the URL with remaining parameters
    new_query = "&".join(p for p in keep if p)
    parts = parts._replace(query=new_query)
    return urllib.parse.urlunsplit(parts)


def normalize_prefixes(prefixes):
    """
    Normalize parameter prefixes for consistent handling.
    
    Args:
        prefixes (list or str): Parameter prefixes to normalize
        
    Returns:
        list: Normalized list of prefixes
    """
    if isinstance(prefixes, str):
        prefixes = [prefixes]
    
    if not prefixes:
        return []
    
    return [prefix.strip() for prefix in prefixes if prefix and prefix.strip()]


def is_tracking_parameter(param_name, prefixes):
    """
    Check if a parameter name matches any tracking prefix (case-insensitive).
    
    Args:
        param_name (str): The parameter name to check
        prefixes (list): List of prefixes to check against
        
    Returns:
        bool: True if the parameter matches a tracking prefix
    """
    if not prefixes or not param_name:
        return False
        
    lower_param = param_name.lower()
    lower_prefixes = [prefix.lower() for prefix in prefixes]
    
    return any(lower_param.startswith(prefix) for prefix in lower_prefixes) 