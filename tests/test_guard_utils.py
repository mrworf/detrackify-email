#!/usr/bin/env python3
"""Unit tests for guard-specific utilities (GuardUtils)."""

import os
import sys
import tempfile
import unittest

# Add the parent directory to the path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from guard.utils import GuardUtils

class TestGuardUtilsSpecific(unittest.TestCase):
    """Test guard-specific utility functions."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_validate_path_security(self):
        """Test path security validation."""
        # Test valid paths
        valid_paths = [
            'file.txt',
            'subdir/file.txt',
            'subdir/subsubdir/file.txt',
        ]
        for path in valid_paths:
            result = GuardUtils.validate_path_security(path, self.temp_dir)
            self.assertTrue(result)
        
        # Test invalid paths (path traversal attempts)
        invalid_paths = [
            '../file.txt',
            '../../file.txt',
            'subdir/../../file.txt',
            '/absolute/path',
        ]
        for path in invalid_paths:
            result = GuardUtils.validate_path_security(path, self.temp_dir)
            self.assertFalse(result)
    
    def test_validate_file_extension(self):
        """Test file extension validation."""
        # Test valid extensions
        valid_files = ['image.png', 'photo.jpg', 'icon.gif', 'logo.ico']
        for filename in valid_files:
            result = GuardUtils.validate_file_extension(filename)
            self.assertTrue(result)
        
        # Test invalid extensions
        invalid_files = ['script.exe', 'document.pdf', 'data.txt', 'file']
        for filename in invalid_files:
            result = GuardUtils.validate_file_extension(filename)
            self.assertFalse(result)
        
        # Test custom extensions
        custom_extensions = {'.pdf', '.txt'}
        result = GuardUtils.validate_file_extension('document.pdf', custom_extensions)
        self.assertTrue(result)
        result = GuardUtils.validate_file_extension('image.png', custom_extensions)
        self.assertFalse(result)
    
    def test_create_secure_filename(self):
        """Test secure filename creation."""
        test_cases = [
            ('file.txt', 'file.txt'),
            ('file with spaces.txt', 'file with spaces.txt'),
            ('file@#$%.txt', 'file@#$%.txt'),
            ('../../../file.txt', '_.._.._file.txt'),
            ('', 'unnamed'),
        ]
        for input_name, expected in test_cases:
            result = GuardUtils.create_secure_filename(input_name)
            self.assertEqual(result, expected)

if __name__ == '__main__':
    unittest.main() 