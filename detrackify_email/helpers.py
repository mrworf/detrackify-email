"""
Static helper class containing email-specific utilities.
"""

import re
import base64
import hashlib
import json
import logging
from typing import Optional, Dict, Any, List, Tuple
from common.utils import SharedUtils


class EmailHelpers:
    """Static helper class containing email-specific utilities."""
    
    # ============================================================================
    # Image Processing Functions
    # ============================================================================
    
    @staticmethod
    def create_blank_tracker() -> str:
        """Create a 1x1 transparent PNG image as base64 data URL."""
        from PIL import Image
        from io import BytesIO
        
        # Create a 1x1 transparent image
        image = Image.new('RGBA', (1, 1), (255, 255, 255, 0))
        
        # Save the image to a BytesIO object
        buffered = BytesIO()
        image.save(buffered, format="PNG")
        
        # Encode the image in Base64
        base64_image = base64.b64encode(buffered.getvalue()).decode('utf-8')
        
        # Format it for use in an img tag
        return f"data:image/png;base64,{base64_image}" 