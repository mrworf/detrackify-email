"""
Email processing package for detrackify.

This package contains classes for processing and cleaning email content,
removing tracking pixels, and guarding links.
"""

from .detector import Detector
from .detrackify import Detrackify
from .configuration import Configuration
from .helpers import EmailHelpers

__all__ = ['Detector', 'Detrackify', 'Configuration', 'EmailHelpers'] 