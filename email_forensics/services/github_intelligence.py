"""
GitHub Intelligence - Uses GitHub public API
"""

import requests
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class GitHubIntelligence:
    """Gather GitHub intelligence using public API"""
    
    def __init__(self, username=None, email=None, domain=None):
        self.username = username
        self.email = email
        self.domain = domain
        self.data = {}
        self._fetch_data()
    
    def _fetch_data(self):
        """Fetch GitHub data using various search methods"""
        
        # Search by username
        if self.username:
            self._search_by_username()
        
        # Search by email (if provided)
        if self.email:
            self._search_by_email()
        
        # Search by domain (if provided)
        if self.domain:
            self._search_by_domain()
    
    def _search_by_username(self):
        """Search GitHub by username"""
        try:
            response = requests.get(f"https://api.github.com/users/{self.username}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.data['user'] = {
                    'login': data.get('login'),
                    'name': data.get('name'),
                    'bio': data.get('bio'),
                    'location': data.get('location'),
                    'company': data.get('company'),
                    'blog': data.get('blog'),
                    'email': data.get('email'),
                    'public_repos': data.get('public_repos'),
                    'followers': data.get('followers'),
                    'following': data.get('following'),
                    'created_at': data.get('created_at'),
                    'updated_at': data.get('updated_at'),
                    'url': data.get('html_url'),
                    'avatar_url': data.get('avatar_url'),
                }
                
                # Get user's repositories
                repos_response = requests.get(
                    f"https://api.github.com/users/{self.username}/repos",
                    params={'sort': 'updated', 'per_page': 10},
                    timeout=10
                )
                if repos_response.status_code == 200:
                    self.data['repositories'] = repos_response.json()
                
                # Get user's organizations
                orgs_response = requests.get(
                    f"https://api.github.com/users/{self.username}/orgs",
                    timeout=10
                )
                if orgs_response.status_code == 200:
                    self.data['organizations'] = orgs_response.json()
                    
        except Exception as e:
            logger.warning(f"GitHub username search failed: {e}")
    
    def _search_by_email(self):
        """Search GitHub by email"""
        try:
            # GitHub API doesn't directly support email search
            # Use alternative: search commits by email
            response = requests.get(
                f"https://api.github.com/search/commits",
                params={'q': f'{self.email}', 'per_page': 5},
                headers={'Accept': 'application/vnd.github.cloak-preview'},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                self.data['email_commits'] = {
                    'total': data.get('total_count', 0),
                    'items': data.get('items', [])[:5]
                }
        except Exception as e:
            logger.warning(f"GitHub email search failed: {e}")
    
    def _search_by_domain(self):
        """Search GitHub by domain"""
        try:
            # Search code for domain
            response = requests.get(
                f"https://api.github.com/search/code",
                params={'q': f'{self.domain}', 'per_page': 5},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                self.data['domain_code'] = {
                    'total': data.get('total_count', 0),
                    'items': data.get('items', [])[:5]
                }
        except Exception as e:
            logger.warning(f"GitHub domain search failed: {e}")
    
    def get_summary(self):
        """Get summary of GitHub findings"""
        summary = {
            'user_found': bool(self.data.get('user')),
            'email_found': bool(self.data.get('email_commits', {}).get('total', 0) > 0),
            'domain_found': bool(self.data.get('domain_code', {}).get('total', 0) > 0),
            'profile_url': self.data.get('user', {}).get('url'),
            'repos_count': len(self.data.get('repositories', [])),
            'orgs_count': len(self.data.get('organizations', [])),
            'developer_footprint': 'HIGH' if self.data.get('user') else 'MEDIUM' if self.data.get('email_commits', {}).get('total', 0) > 0 else 'LOW'
        }
        return summary
    
    def get_data(self):
        """Get all GitHub data"""
        return self.data