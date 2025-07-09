"""Blacklist management for the guard server."""
from common.blocklist import Blocklist


class Blacklist(Blocklist):
    """Blacklist wrapper for the guard server."""
    
    def __init__(self, blacklist_file: str):
        """Initialize blacklist for guard server."""
        super().__init__(blacklist_file, 'blacklist') 