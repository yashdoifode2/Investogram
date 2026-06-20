"""
Social Profile Discovery - Uses free OSINT APIs to find profiles
"""

import requests
import logging
import re
from urllib.parse import quote_plus

logger = logging.getLogger(__name__)

class SocialDiscovery:
    """Discover social media profiles using free APIs"""
    
    def __init__(self, username, email=None):
        self.username = username
        self.email = email
        self.profiles = []
        self._search_profiles()
    
    def _search_profiles(self):
        """Search for profiles on various platforms"""
        
        # Platform configurations
        platforms = [
            {
                'name': 'GitHub',
                'url': f"https://github.com/{self.username}",
                'api': f"https://api.github.com/users/{self.username}",
                'icon': 'fab fa-github',
                'color': '#333'
            },
            {
                'name': 'Twitter',
                'url': f"https://twitter.com/{self.username}",
                'icon': 'fab fa-twitter',
                'color': '#1DA1F2'
            },
            {
                'name': 'Instagram',
                'url': f"https://instagram.com/{self.username}",
                'icon': 'fab fa-instagram',
                'color': '#E4405F'
            },
            {
                'name': 'Reddit',
                'url': f"https://reddit.com/user/{self.username}",
                'icon': 'fab fa-reddit',
                'color': '#FF4500'
            },
            {
                'name': 'LinkedIn',
                'url': f"https://linkedin.com/in/{self.username}",
                'icon': 'fab fa-linkedin',
                'color': '#0077B5'
            },
            {
                'name': 'YouTube',
                'url': f"https://youtube.com/@{self.username}",
                'icon': 'fab fa-youtube',
                'color': '#FF0000'
            },
            {
                'name': 'Medium',
                'url': f"https://medium.com/@{self.username}",
                'icon': 'fab fa-medium',
                'color': '#00AB6C'
            },
            {
                'name': 'Dev.to',
                'url': f"https://dev.to/{self.username}",
                'icon': 'fab fa-dev',
                'color': '#0A0A0A'
            },
            {
                'name': 'Stack Overflow',
                'url': f"https://stackoverflow.com/users/{self.username}",
                'icon': 'fab fa-stack-overflow',
                'color': '#F48024'
            },
            {
                'name': 'Pinterest',
                'url': f"https://pinterest.com/{self.username}",
                'icon': 'fab fa-pinterest',
                'color': '#E60023'
            }
        ]
        
        # Check each platform
        for platform in platforms:
            profile = self._check_profile(platform)
            if profile:
                self.profiles.append(profile)
        
        # If email is provided, also search with email
        if self.email:
            self._search_with_email()
    
    def _check_profile(self, platform):
        """Check if a profile exists on a platform"""
        try:
            # For GitHub, use API
            if platform.get('api'):
                response = requests.get(platform['api'], timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'platform': platform['name'],
                        'username': self.username,
                        'url': platform['url'],
                        'icon': platform['icon'],
                        'color': platform['color'],
                        'found': True,
                        'confidence': 'HIGH',
                        'bio': data.get('bio', ''),
                        'location': data.get('location', ''),
                        'followers': data.get('followers', 0),
                        'repos': data.get('public_repos', 0),
                        'company': data.get('company', ''),
                    }
            else:
                # For other platforms, check if page exists
                response = requests.head(platform['url'], timeout=10, allow_redirects=True)
                if response.status_code == 200:
                    return {
                        'platform': platform['name'],
                        'username': self.username,
                        'url': platform['url'],
                        'icon': platform['icon'],
                        'color': platform['color'],
                        'found': True,
                        'confidence': 'MEDIUM',
                    }
        except Exception as e:
            logger.warning(f"Profile check failed for {platform['name']}: {e}")
        
        return None
    
    def _search_with_email(self):
        """Search for profiles using email address"""
        # This would use services like Hunter.io, EmailHippo, etc.
        # For now, add some common patterns
        email_username = self.email.split('@')[0] if '@' in self.email else self.email
        if email_username != self.username:
            # Search with email username
            platforms = [
                {'name': 'GitHub', 'url': f"https://github.com/{email_username}"},
                {'name': 'Twitter', 'url': f"https://twitter.com/{email_username}"},
            ]
            for platform in platforms:
                try:
                    response = requests.head(platform['url'], timeout=10)
                    if response.status_code == 200:
                        self.profiles.append({
                            'platform': platform['name'],
                            'username': email_username,
                            'url': platform['url'],
                            'found': True,
                            'confidence': 'LOW',
                            'source': 'Email'
                        })
                except:
                    pass
    
    def get_profiles(self):
        """Get discovered profiles"""
        return self.profiles
    
    def get_summary(self):
        """Get summary of discoveries"""
        return {
            'total_profiles': len(self.profiles),
            'platforms': [p['platform'] for p in self.profiles],
            'profiles': self.profiles
        }