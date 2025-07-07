"""
Detector class for identifying tracking pixels and analyzing URLs.
"""

import re
import logging
import requests
from typing import Optional, Dict, Any, List
from PIL import Image
from io import BytesIO
from .helpers import EmailHelpers
from .configuration import Configuration


class Detector:
    """Detector class for identifying tracking pixels and analyzing URLs."""
    
    def __init__(self, config: Configuration):
        """Initialize detector with configuration."""
        self.config = config
    
    def strip_tracking_parameters(self, url: str) -> Optional[str]:
        """Strip tracking parameters from URL."""
        return EmailHelpers.strip_tracking_parameters(url)
    
    def detect_needed_rewrite(self, url: str, replace_1x1: bool = False) -> Optional[Dict[str, Any]]:
        """Check if the URL contains a query string and needs rewriting."""
        ret = {'url': url, 'reason': []}
        match = re.search(r'(https?:\/\/[^?]+)(\??.*)', url)
        if match:
            if match.group(2) and match.group(2) != '':
                logging.debug(f'Query string detected: {url} -> {match.group(1)} ({match.group(2)})')
                # Break up the query string into parts
                query = match.group(2)[1:]  # Skip the question mark
                parts = query.split('&')
                
                # Blank the last part, this stops us from doing a complete HTTP GET of the (potentially) tracking URL
                # This doesn't guarantee they won't track us anyway, but at least we try to avoid it.
                parts[-1] = ''
                
                # Reconstruct the URL without the query string
                result = f'{match.group(1)}?'
                while len(parts) > 0:
                    findings = self.interrogate_url(result[:-1])
                    if findings:
                        # Check if the image is 1x1
                        if findings['width'] <= 1 and findings['height'] <= 1:
                            ret['reason'].append('Tracker')
                        ret['url'] = findings['url']  # Allows us to use the final destination directly
                        ret['reason'].extend(findings['detected'])
                        return ret
                    result += f'{parts.pop(0)}&'
                ret = None
        else:
            logging.warning(f'URL does not confirm: {url}')
        return ret
    
    def interrogate_url(self, url: str) -> Dict[str, Any]:
        """Attempt to connect to the URL to see if it returns an image."""
        result = {
            'width': -1,
            'height': -1,
            'detected': [],
            'url': url
        }
        
        try:
            req = requests.get(
                url, 
                stream=True, 
                timeout=3, 
                allow_redirects=self.config.get(Configuration.CFG_STRIP_REDIRECT)
            )
            
            if req.status_code == 200:
                if req.cookies:
                    logging.debug(f'URL {url} returns cookies, so it is going to be a tracking device')
                    result['detected'].append('Cookies')
                
                if req.history:
                    logging.debug(f'Request was redirected, intermediate URLs:')
                    for r in req.history:
                        logging.debug(f'  - {r.url}')
                    logging.debug(f'Final URL: {req.url}')
                    result['detected'].append('Redirect')
                    result['url'] = req.url  # Update to the final one
                
                # So far so good, check mimetype
                if 'image' in req.headers['Content-Type']:
                    # Read image so we can determine dimensions
                    image = Image.open(BytesIO(req.content))
                    result['width'], result['height'] = image.size
                    logging.debug(f'URL {url} is an image: {result["width"]}x{result["height"]}')
                else:
                    logging.debug(f'URL {url} does not return an image')
                    result['detected'].append('No Image')
            elif req.status_code == 301 or req.status_code == 302:
                logging.debug(f'URL {url} is a redirect, not likely to be a legit image')
                result['detected'].append('Redirect')
            else:
                logging.debug(f'URL {url} returned status code {req.status_code}')
        except Exception as e:
            # This isn't superpretty, but we'll do some text matching
            error = str(e)
            if "Name or service not known" in error:
                # No need to retry, this is a dead end
                result['detected'].append('DNS error')
            elif "Max retries":
                # Also not a good indicator, so we'll treat it as a tracking image
                result['detected'].append('Connection Issues')
            # All else...
            logging.error(f'Error testing {url}: {e}')
            logging.exception(f"Exception: {e}")
        
        return result
    
    def is_tracking_image(self, img_tag) -> List[str]:
        """Detect if an image tag represents a tracking pixel."""
        try:
            style = img_tag.get('style', '')
            width = img_tag.get('width', EmailHelpers.extract_style_size(style, 'width'))
            height = img_tag.get('height', EmailHelpers.extract_style_size(style, 'height'))
            src = img_tag.get('src', '')
            alt = img_tag.get('alt', None)
            
            logging.debug(f"is_tracking_image - src: {src}, width: {width}, height: {height}, alt: {alt}")
            
            # Parse width and height
            width = EmailHelpers.parse_size_value(width)
            height = EmailHelpers.parse_size_value(height)
            
            logging.debug(f'Size: {width}x{height}, URL: {src} (Alt: {alt})')
            
            # Check for small size (1x1 pixels)
            size_check = (width <= 1 and height <= 1)
            logging.debug(f"is_tracking_image - size_check: {size_check} ({width}x{height})")
            
            # However, if there's no size specified, we can't be sure, so we need to take some executive decisions
            if width == -1 and height == -1:
                # see if there's a tracking URL in the src
                stripped_src = self.strip_tracking_parameters(src)
                if not stripped_src:
                    # Unlikely a tracking image, probably just a lazy developer not providing size
                    logging.debug('(No size specified, but no tracking URL detected, assuming not a tracking pixel)')
                    logging.debug(f"is_tracking_image - no size specified, no tracking URL detected, assuming not tracking")
                    size_check = False
            
            # Check if the image is hidden based on style attribute
            hidden_element = EmailHelpers.is_invisible_element(style)
            logging.debug(f"is_tracking_image - hidden_element: {hidden_element}")
            
            # This regex checks for typical tracking URL patterns, can be adjusted as needed
            tracking_url = re.search(r'track|pixel', src, re.IGNORECASE) is not None
            logging.debug(f"is_tracking_image - tracking_url: {tracking_url}")
            
        except Exception as e:
            logging.error(f'Error processing image tag: {img_tag}')
            logging.exception(f"Error: {e}")
            # Reraise the exception
            raise e
        
        logging.debug(f'Size check: {size_check}, Tracking URL: {tracking_url}, Hidden element: {hidden_element}')
        reason = []
        if size_check:
            reason.append(f'Size check {width}x{height}')
        if tracking_url:
            reason.append(f'Tracker URL')
        if hidden_element:
            reason.append('Hidden element')
        logging.debug(f"is_tracking_image - returning reasons: {reason}")
        return reason 