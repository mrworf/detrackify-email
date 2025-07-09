"""Guard-specific utility functions."""

import logging
import os
import re
from typing import Optional, Tuple, Dict, Any
from common.utils import SharedUtils


class GuardUtils:
    """Static utility class containing guard-specific helper functions."""
    
    # Allowed file extensions for resources
    ALLOWED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.ico'}
    
    # ============================================================================
    # Guard-Specific Security Functions
    # ============================================================================
    
    @staticmethod
    def validate_path_security(path: str, base_dir: str) -> bool:
        """Validate path for security (prevent path traversal)."""
        try:
            normalized_path = os.path.normpath(path)
            if normalized_path.startswith('..') or normalized_path.startswith('/'):
                return False
            
            full_path = os.path.join(base_dir, normalized_path)
            real_path = os.path.realpath(full_path)
            base_real = os.path.realpath(base_dir)
            
            return real_path.startswith(base_real)
        except OSError:
            return False
    
    @staticmethod
    def validate_file_extension(filename: str, allowed_extensions: set = None) -> bool:
        """Validate file extension."""
        if allowed_extensions is None:
            allowed_extensions = GuardUtils.ALLOWED_EXTENSIONS
        
        ext = os.path.splitext(filename)[1].lower()
        return bool(ext and ext in allowed_extensions)
    
    @staticmethod
    def create_secure_filename(filename: str) -> str:
        """Create a secure filename by removing dangerous characters."""
        # Remove or replace dangerous characters
        dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Remove leading/trailing spaces and dots
        filename = filename.strip('. ')
        
        # Ensure filename is not empty
        if not filename:
            filename = 'unnamed'
        
        return filename
    
    # ============================================================================
    # Guard-Specific Utility Functions
    # ============================================================================
    
    # (format_time_elapsed removed - only used in tests) 