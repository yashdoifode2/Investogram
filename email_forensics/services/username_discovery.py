"""
Username Discovery Engine - Generates username variations from emails
"""

import re
import logging

logger = logging.getLogger(__name__)

class UsernameDiscovery:
    """Generate username variations from email addresses"""
    
    def __init__(self, email):
        self.email = email
        self.username = self._extract_username()
        self.variations = []
        self._generate_variations()
    
    def _extract_username(self):
        """Extract username part from email"""
        if '@' in self.email:
            return self.email.split('@')[0]
        return self.email
    
    def _generate_variations(self):
        """Generate all possible username variations"""
        username = self.username
        variations = set()
        
        # Original username
        variations.add(username)
        
        # Lowercase
        variations.add(username.lower())
        
        # Uppercase
        variations.add(username.upper())
        
        # Title case
        variations.add(username.title())
        
        # Remove dots
        variations.add(username.replace('.', ''))
        
        # Replace dots with underscores
        variations.add(username.replace('.', '_'))
        
        # Replace dots with hyphens
        variations.add(username.replace('.', '-'))
        
        # Split by dots and combine
        parts = username.split('.')
        if len(parts) > 1:
            variations.add(''.join(parts))
            variations.add('_'.join(parts))
            variations.add('-'.join(parts))
            variations.add(''.join(p[:1] for p in parts))
        
        # Add common prefixes/suffixes
        common_suffixes = ['123', '2020', '2021', '2022', '2023', '2024', '1', '01']
        for suffix in common_suffixes:
            variations.add(f"{username}{suffix}")
            variations.add(f"{username}_{suffix}")
        
        # Shorten username
        if len(username) > 3:
            variations.add(username[:3])
            variations.add(username[:4])
            variations.add(username[:5])
        
        # First name + last initial
        if '.' in username:
            parts = username.split('.')
            if len(parts) >= 2:
                variations.add(f"{parts[0]}{parts[1][0]}")
                variations.add(f"{parts[0]}_{parts[1][0]}")
                variations.add(f"{parts[0]}.{parts[1][0]}")
                variations.add(f"{parts[1]}{parts[0][0]}")
                variations.add(f"{parts[1]}_{parts[0][0]}")
        
        # Common variations
        if len(username) > 4:
            variations.add(username[:-1])
            variations.add(username[:-2])
            variations.add(username[:len(username)//2])
            variations.add(username[len(username)//2:])
        
        # Reverse
        variations.add(username[::-1])
        
        # Add @ and domain variations (for social media)
        domain = self.email.split('@')[1] if '@' in self.email else 'gmail.com'
        variations.add(f"{username}@{domain}")
        
        self.variations = list(variations)
    
    def get_variations(self, limit=50):
        """Get username variations (limited)"""
        return self.variations[:limit]
    
    def search_social(self):
        """Search for username on social platforms (placeholder)"""
        # This would use social media APIs
        # For now, return the variations
        return {
            'variations': self.variations[:20],
            'total': len(self.variations),
            'platforms': ['GitHub', 'Twitter', 'Instagram', 'Reddit', 'LinkedIn']
        }